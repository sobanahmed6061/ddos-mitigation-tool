"""
Hybrid Detector — Isolation Forest + LSTM + Random Forest Classifier
All three models working together with confidence scores.
"""

import os, json, logging, collections
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

import numpy as np
import joblib
import tensorflow as tf
import time
from scapy.all         import sniff, IP, TCP, UDP, ICMP
from feature_extractor import FeatureExtractor
from threat_intel      import enrich_ip, format_threat_summary
from threat_scorer     import compute_threat_score, format_score_display, clear_ip_history
from mitigation_engine import apply_mitigation, format_mitigation_display, release_mitigation, ip_mitigation_state
from token_bucket      import bucket_manager
from whitelist_manager  import (is_whitelisted, update_ip_history,
                                format_whitelist_display, get_whitelist_summary)
from pcap_engine        import pcap_engine, attack_timeline, AttackTimeline
from report_generator   import report_generator
from state_manager      import state
from api_server         import start_api_server
from siem_integration   import siem_router
# ── Config ────────────────────────────────────────────────────
INTERFACE            = os.getenv("INTERFACE", "enp0s8")
LOG_FILE             = "/app/logs/hybrid_alerts.log"
MODEL_DIR            = "/app/models"
WINDOW_SIZE          = 5
SEQUENCE_LEN         = 10
CLASSIFIER_THRESHOLD = 0.60
# ─────────────────────────────────────────────────────────────

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    filename = LOG_FILE,
    level    = logging.WARNING,
    format   = "%(asctime)s - %(message)s"
)

# ── Load Isolation Forest ─────────────────────────────────────
print("[*] Loading Isolation Forest...")
iso_model  = joblib.load(f"{MODEL_DIR}/isolation_forest.joblib")
iso_scaler = joblib.load(f"{MODEL_DIR}/scaler.joblib")

with open(f"{MODEL_DIR}/model_meta.json") as f:
    iso_meta = json.load(f)
ISO_FEATURES = iso_meta["features"]

# ── Load LSTM ─────────────────────────────────────────────────
print("[*] Loading LSTM model...")
lstm_model  = tf.keras.models.load_model(f"{MODEL_DIR}/lstm_model.keras")
lstm_scaler = joblib.load(f"{MODEL_DIR}/lstm_scaler.joblib")

with open(f"{MODEL_DIR}/lstm_meta.json") as f:
    lstm_meta = json.load(f)
LSTM_FEATURES = lstm_meta["features"]

# ── Load Random Forest Classifier ─────────────────────────────
print("[*] Loading attack classifier...")
clf_model   = joblib.load(f"{MODEL_DIR}/classifier_rf.joblib")
clf_scaler  = joblib.load(f"{MODEL_DIR}/classifier_scaler.joblib")
clf_encoder = joblib.load(f"{MODEL_DIR}/classifier_encoder.joblib")

with open(f"{MODEL_DIR}/classifier_meta.json") as f:
    clf_meta = json.load(f)
CLF_FEATURES = clf_meta["features"]
CLF_CLASSES  = clf_meta["classes"]

print(f"[*] Isolation Forest F1 : {iso_meta['f1_score']}")
print(f"[*] LSTM F1             : {lstm_meta['lstm_f1']}")
print(f"[*] Classifier accuracy : {clf_meta['accuracy']}")
print(f"[*] Classifier classes  : {CLF_CLASSES}")
print(f"[*] Sniffing on {INTERFACE} | Window={WINDOW_SIZE}s\n")
print("─" * 80)

# ── Sequence buffer for LSTM ──────────────────────────────────
sequence_buffer = collections.deque(maxlen=SEQUENCE_LEN)

# ── State ─────────────────────────────────────────────────────
extractor         = FeatureExtractor(window_size=WINDOW_SIZE)
window_num        = 0
iso_normal_streak = 0
COOLDOWN_STREAK   = 2

# ── Stats ─────────────────────────────────────────────────────
stats = {"total": 0, "normal": 0, "alert": 0, "monitor": 0}


# ─────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────

def get_attack_type(features):
    """Fallback rule-based attack type identification."""
    if features["syn_ratio"] >= 0.5 and features["pps"] > 10:
        return "SYN_FLOOD"
    elif features["icmp_ratio"] > 0.7:
        return "ICMP_FLOOD"
    elif features["udp_ratio"] > 0.7:
        return "UDP_FLOOD"
    elif features["pps"] > 80 and features["tcp_ratio"] > 0.7:
        return "HTTP_FLOOD"
    elif features["pps"] > 200:
        return "VOLUMETRIC"
    elif features["syn_ratio"] > 0.3 and features["pps"] > 5:
        return "SYN_FLOOD"
    else:
        return "UNKNOWN"


def has_attack_signature(features):
    """Returns True if features match any known attack pattern."""
    return (
        (features["syn_ratio"]  >= 0.5 and features["pps"] > 10)  or
        (features["udp_ratio"]  >  0.7 and features["pps"] > 30)  or
        (features["icmp_ratio"] >  0.7 and features["pps"] > 8)   or
        (features["pps"] > 80 and features["tcp_ratio"] > 0.7
         and features["syn_ratio"] < 0.5)                          or
        (features["pps"] > 200)
    )


def run_isolation_forest(features):
    """Returns (prediction, score). 1=normal, -1=anomaly."""
    x     = np.array([[features[f] for f in ISO_FEATURES]])
    x_sc  = iso_scaler.transform(x)
    pred  = iso_model.predict(x_sc)[0]
    score = iso_model.decision_function(x_sc)[0]
    return pred, score


def run_lstm(features):
    """
    Returns (prediction, confidence).
    prediction: 0=normal, 1=attack.
    Returns (None, None) while warming up.
    """
    vec        = np.array([features[f] for f in LSTM_FEATURES])
    vec_scaled = lstm_scaler.transform(vec.reshape(1, -1))[0]
    sequence_buffer.append(vec_scaled)

    if len(sequence_buffer) < SEQUENCE_LEN:
        return None, None

    seq  = np.array(list(sequence_buffer)).reshape(1, SEQUENCE_LEN, len(LSTM_FEATURES))
    prob = lstm_model.predict(seq, verbose=0)[0][0]
    pred = 1 if prob >= 0.5 else 0
    return pred, float(prob)


def run_classifier(features):
    """
    Returns (top_class, top_confidence, all_probabilities).
    Uses Random Forest to classify attack type with confidence scores.
    """
    x     = np.array([[features[f] for f in CLF_FEATURES]])
    x_sc  = clf_scaler.transform(x)
    probs = clf_model.predict_proba(x_sc)[0]

    confidence_dict = {
        cls: round(float(prob), 4)
        for cls, prob in zip(CLF_CLASSES, probs)
    }

    top_class = CLF_CLASSES[np.argmax(probs)]
    top_conf  = float(np.max(probs))

    return top_class, top_conf, confidence_dict


# ─────────────────────────────────────────────────────────────
# Main packet handler
# ─────────────────────────────────────────────────────────────
# Track top source IP per window
ip_counter = collections.Counter()

def handle_packet(pkt):
    global window_num, iso_normal_streak

    if IP not in pkt:
        return

    src_ip  = pkt[IP].src
    own_ips = {
        "192.168.56.2",  # Ubuntu itself
        "127.0.0.1",     # loopback
        "10.0.2.2",      # VirtualBox NAT gateway
        "10.0.2.15",     # VirtualBox NAT adapter
    }

    # Also ignore API server port traffic (dashboard polling)
    api_ports = {9999, 10000, 8888, 7777}
    is_api_traffic = (
        TCP in pkt and (
            pkt[TCP].dport in api_ports or
            pkt[TCP].sport in api_ports
        )
    )

    if src_ip not in own_ips and not is_api_traffic:
        ip_counter[src_ip] += 1

    # Track source IPs for threat intel
    if src_ip not in own_ips:
        ip_counter[src_ip] += 1

    # Add to PCAP buffer if capture is active
    pcap_engine.add_packet(pkt)

    extractor.add_packet(pkt)

    if not extractor.is_window_ready():
        return

    features   = extractor.extract()
    extractor.reset()
    window_num     += 1
    stats["total"] += 1

    # Update shared state metrics
    state.update_metrics(features, window_num)

    # Get top attacking IP this window then reset counter
    top_ip = ip_counter.most_common(1)[0][0] if ip_counter else "unknown"
    ip_counter.clear()

    # ── Run all three models ──────────────────────────────────
    iso_pred,  iso_score              = run_isolation_forest(features)
    lstm_pred, lstm_conf              = run_lstm(features)
    clf_label, clf_conf, clf_all_prob = run_classifier(features)

    iso_flagged = (iso_pred == -1)
    lstm_ready  = (lstm_pred is not None)
    lstm_str    = f"{lstm_conf:.3f}" if lstm_ready else "warming"

    # ── Noise floor filter ────────────────────────────────────
    # Expanded noise floor — catches background traffic
    # and dashboard API polling
    is_noise = (features["pps"] < 1.0) or \
               (features["pps"] < 3.0 and iso_score > -0.05) or \
               (features["pps"] < 5.0 and iso_score > -0.03 and
                features["syn_ratio"] < 0.3)
    # Classifier override: if RF says normal with high confidence
    # AND ISO signal is weak → trust the classifier
    # This fixes LSTM lingering false alerts during recovery
    clf_says_normal = (clf_label == "normal" and clf_conf >= 0.90)
    weak_iso        = (iso_score > -0.06)
    clf_override    = (clf_says_normal and weak_iso)

    # ── Cooldown streak counter ───────────────────────────────
    if (iso_pred == 1 or is_noise or clf_override) and not has_attack_signature(features):
        iso_normal_streak += 1
    else:
        iso_normal_streak  = 0
    in_cooldown = (iso_normal_streak >= COOLDOWN_STREAK)

    # ── LSTM suppression logic ────────────────────────────────
    if not lstm_ready:
        lstm_flagged = False
    elif in_cooldown:
        lstm_flagged = False
    elif (iso_pred == 1 or is_noise) and features["pps"] < 10 \
            and lstm_conf is not None and lstm_conf < 0.999:
        lstm_flagged = False
    else:
        lstm_flagged = (lstm_pred == 1)

    sig_flagged = has_attack_signature(features)

    # ── Determine attack type ─────────────────────────────────
    # Use classifier if confident, fall back to feature rules
    if clf_conf >= CLASSIFIER_THRESHOLD and clf_label != "normal":
        attack_type = clf_label.upper()
        type_source = f"RF({clf_conf:.0%})"
    elif clf_label == "normal" and clf_conf >= CLASSIFIER_THRESHOLD:
        attack_type = ""
        type_source = f"RF({clf_conf:.0%})"
    else:
        attack_type = get_attack_type(features)
        type_source = "rules"

    # ── Hybrid decision ───────────────────────────────────────
    if is_noise or clf_override:
        decision    = "NORMAL"
        attack_type = ""

    elif sig_flagged and (iso_flagged or lstm_flagged):
        decision = "ALERT"

    elif iso_flagged and lstm_flagged:
        decision = "ALERT"

    elif iso_flagged or lstm_flagged:
        decision = "MONITOR"

    else:
        decision    = "NORMAL"
        attack_type = ""

    # ── Stats ─────────────────────────────────────────────────
    if decision == "ALERT":
        stats["alert"]   += 1
        symbol = "🚨 ALERT  "
    elif decision == "MONITOR":
        stats["monitor"] += 1
        symbol = "👁  MONITOR"
    else:
        stats["normal"]  += 1
        symbol = "✅ NORMAL  "

    # ── Build display strings ─────────────────────────────────
    iso_label  = "ANOMALY" if iso_flagged  else "normal "
    lstm_label = "ATTACK " if lstm_flagged else ("normal " if lstm_ready else "warmup ")
    cool_str   = f" [cooldown={iso_normal_streak}]" if in_cooldown else ""
    clf_str    = f"{clf_label}({clf_conf:.0%})"
    type_str   = f" | {attack_type}[{type_source}]" if attack_type else ""

    print(f"[W{window_num:>3}] {symbol}{cool_str} | "
          f"ISO={iso_label}({iso_score:+.3f}) | "
          f"LSTM={lstm_label}(p={lstm_str}) | "
          f"CLF={clf_str} | "
          f"pps={features['pps']:>7}"
          f"{type_str}")

    # ── Logging ───────────────────────────────────────────────
    if decision == "ALERT":
        # ── Whitelist check FIRST ─────────────────────────────
        whitelisted, wl_tier, wl_reason = is_whitelisted(top_ip)
        if whitelisted:
            print(
                f"[W{window_num:>3}] "
                f"{format_whitelist_display(top_ip, wl_tier, wl_reason)}"
            )
            update_ip_history(top_ip, was_alert=False)
            return   # skip all mitigation for whitelisted IPs

        # Track as alert in IP history
        update_ip_history(top_ip, was_alert=True)

        # ── Start PCAP capture if not already running ─────────
        if not pcap_engine.capturing:
            pcap_engine.start_capture(attack_type, top_ip)

        # ── Threat intelligence enrichment ────────────────────
        intel     = enrich_ip(top_ip)
        intel_str = format_threat_summary(intel)

        # ── Composite threat score ────────────────────────────
        lstm_conf_val = lstm_conf if lstm_ready else None
        score_data    = compute_threat_score(
            ip          = top_ip,
            attack_type = attack_type,
            clf_conf    = clf_conf,
            iso_score   = iso_score,
            lstm_conf   = lstm_conf_val,
            pps         = features["pps"],
            intel       = intel
        )

        # ── Display ───────────────────────────────────────────
        # ── Apply graduated mitigation ────────────────────────
        mit_result  = apply_mitigation(
            ip          = top_ip,
            score       = score_data["total_score"],
            attack_type = attack_type
        )

        # ── Display ───────────────────────────────────────────
        print(f"          🌍 {top_ip} → {intel_str}")
        print(format_score_display(score_data))
        print(format_mitigation_display(mit_result, top_ip))

        # Push to shared state for API
        state.add_alert(
            ip          = top_ip,
            attack_type = attack_type,
            score_data  = score_data,
            intel       = intel,
            mit_result  = mit_result,
            features    = features,
        )

        # Ship to SIEM platforms
        with state.lock:
            latest_alert = list(state.recent_alerts)[0] \
                           if state.recent_alerts else None
        if latest_alert:
            siem_router.queue_alert(latest_alert)
        # ── Log to attack timeline ────────────────────────────
        attack_timeline.add_event("ALERT", top_ip, {
            "attack_type"  : attack_type,
            "pps"          : features["pps"],
            "threat_score" : score_data["total_score"],
            "clf_conf"     : clf_conf,
            "iso_score"    : iso_score,
            "level"        : mit_result["level"],
        })
        attack_timeline.add_event("MITIGATION", top_ip, {
            "level"  : mit_result["level"],
            "name"   : mit_result["name"],
            "action" : mit_result["action"],
        })
        # Show kernel-level enforcement stats
        if mit_result["level"] >= 2:
            from mitigation_engine import get_kernel_drop_stats
            kernel_stats  = get_kernel_drop_stats(top_ip)
            pkts_dropped  = kernel_stats["pkts"]
            bytes_dropped = kernel_stats["bytes"]

            # Push to state for API/dashboard
            state.update_kernel_drops(top_ip, pkts_dropped, bytes_dropped)

            # Format large numbers readably
            if pkts_dropped >= 1000000:
                pkts_str = f"{pkts_dropped/1000000:.1f}M"
            elif pkts_dropped >= 1000:
                pkts_str = f"{pkts_dropped/1000:.1f}K"
            else:
                pkts_str = str(pkts_dropped)

            print(
                f"          ⚙️  KERNEL ENFORCEMENT | "
                f"method=iptables_hashlimit | "
                f"packets_dropped={pkts_str} | "
                f"bytes_dropped={bytes_dropped} | "
                f"level=L{mit_result['level']} | "
                f"enforced_in=kernel_space"
            )


        # ── Log full alert ────────────────────────────────────
        logging.warning(
            f"HYBRID ALERT | type={attack_type} | "
            f"src_ip={top_ip} | "
            f"threat_score={score_data['total_score']} | "
            f"threat_level={score_data['threat_level']} | "
            f"ml_pts={score_data['breakdown']['ml_anomaly']} | "
            f"type_pts={score_data['breakdown']['attack_type']} | "
            f"pps_pts={score_data['breakdown']['packet_rate']} | "
            f"intel_pts={score_data['breakdown']['threat_intel']} | "
            f"duration_pts={score_data['breakdown']['duration']} | "
            f"abuse_score={intel.get('abuse_score',0)} | "
            f"country={intel.get('country','?')} | "
            f"clf_conf={clf_conf:.4f} | "
            f"iso_score={iso_score:.4f} | "
            f"pps={features['pps']}"
        )
    elif decision == "NORMAL" and attack_type == "":
        if top_ip != "unknown":
            update_ip_history(top_ip, was_alert=False)
            clear_ip_history(top_ip)
            release_mitigation(top_ip)
            state.resolve_attack(top_ip)
            state.add_normal_window()
            # ── Stop PCAP and save timeline ───────────────────
            if pcap_engine.capturing:
                attack_id  = pcap_engine.attack_id
                pcap_path  = pcap_engine.stop_capture()
                tl_path    = attack_timeline.save_timeline(attack_id)
                attack_timeline.print_summary()

                # Generate forensic PDF report
                try:
                    report_generator.generate(
                        timeline_path = tl_path,
                        pcap_path     = pcap_path,
                    )
                except Exception as e:
                    print(f"          ❌ PDF generation failed: {e}")
    elif decision == "MONITOR":
        logging.info(
            f"MONITOR | iso={iso_label} | lstm={lstm_label} | "
            f"clf={clf_str} | "
            f"pps={features['pps']} | syn={features['syn_ratio']:.2f}"
        )
    # Log normal windows to timeline
    if decision == "NORMAL" and top_ip != "unknown":
        attack_timeline.add_event("NORMAL", top_ip, {
            "pps": features["pps"],
        })
    # ── Stats banner every 20 windows ────────────────────────
    if window_num % 20 == 0:
        wl_summary = get_whitelist_summary()
        print("\n" + "─" * 80)
        print(f"  Stats → Total:{stats['total']} | "
              f"Normal:{stats['normal']} | "
              f"Monitor:{stats['monitor']} | "
              f"Alert:{stats['alert']}")
        print(f"  Whitelist → "
              f"Tier1:{wl_summary['tier1_ranges']} ranges | "
              f"Tier2:{wl_summary['tier2_entries']} IPs | "
              f"Tier3:{wl_summary['tier3_active']} temp")
        print("─" * 80 + "\n")

# ─────────────────────────────────────────────────────────────
# Start API server in background
start_api_server(host="0.0.0.0", port=9999)

start_api_server(host="0.0.0.0", port=8888)

# Start heartbeat thread — keeps dashboard alive during idle
import threading
def _heartbeat():
    while True:
        time.sleep(5)
        with state.lock:
            if state.live_metrics["last_updated"] is None:
                state.live_metrics["last_updated"] = \
                    time.strftime("%Y-%m-%d %H:%M:%S")

threading.Thread(target=_heartbeat, daemon=True).start()

print(f"[*] Starting hybrid detection — first {SEQUENCE_LEN} windows warm up LSTM\n")
# BPF filter — capture attack-relevant traffic only
# Ignores: API server ports, mDNS, DHCP, NTP
BPF_FILTER = (
    "not port 9999 and "
    "not port 10000 and "
    "not port 8888 and "
    "not port 7777 and "
    "not port 5353 and "
    "not port 67 and "
    "not port 68 and "
    "not port 123"
)

print(f"[*] BPF filter active — background traffic excluded\n")
sniff(iface=INTERFACE, prn=handle_packet, store=0, filter=BPF_FILTER)
