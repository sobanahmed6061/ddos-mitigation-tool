"""
ML-powered live detector using trained Isolation Forest.
Hybrid detection: ML score + feature-based rules.
"""

from scapy.all import sniff, IP
from feature_extractor import FeatureExtractor
import numpy as np
import joblib, json, logging, os

# ── Config ────────────────────────────────────────────────────
INTERFACE   = os.getenv("INTERFACE", "enp0s8")
LOG_FILE    = "/app/logs/ml_alerts.log"
MODEL_PATH  = "/app/models/isolation_forest.joblib"
SCALER_PATH = "/app/models/scaler.joblib"
META_PATH   = "/app/models/model_meta.json"
WINDOW_SIZE = 5
# ─────────────────────────────────────────────────────────────

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING,
    format="%(asctime)s - %(message)s"
)

# ── Load model ────────────────────────────────────────────────
print("[*] Loading ML model...")
model  = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

with open(META_PATH) as f:
    meta = json.load(f)

FEATURES = meta["features"]
print(f"[*] Model loaded | F1={meta['f1_score']} | Features={meta['n_features']}")
print(f"[*] Sniffing on {INTERFACE} | Window={WINDOW_SIZE}s\n")

# ── Live detection loop ───────────────────────────────────────
extractor  = FeatureExtractor(window_size=WINDOW_SIZE)
window_num = 0

def handle_packet(pkt):
    global window_num

    if IP not in pkt:
        return

    extractor.add_packet(pkt)

    if not extractor.is_window_ready():
        return

    features   = extractor.extract()
    extractor.reset()
    window_num += 1

    # ── Build feature vector ──────────────────────────────────
    x_vec    = np.array([[features[f] for f in FEATURES]])
    x_scaled = scaler.transform(x_vec)

    # ── ML prediction ─────────────────────────────────────────
    prediction = model.predict(x_scaled)[0]      # 1=normal, -1=anomaly
    score      = model.decision_function(x_scaled)[0]

    # ── Feature-based attack signature rules ──────────────────
    syn_flood  = (features["syn_ratio"]  > 0.5 and features["pps"] > 15)
    udp_flood  = (features["udp_ratio"]  > 0.7 and features["pps"] > 30)
    icmp_flood = (features["icmp_ratio"] > 0.7 and features["pps"] > 8)
    http_flood = (features["pps"] > 80 and features["tcp_ratio"] > 0.7
                  and features["syn_ratio"] < 0.5)
    high_pps   = (features["pps"] > 200)

    attack_signature = syn_flood or udp_flood or icmp_flood or http_flood or high_pps

    # ── Suppress weak anomalies with no attack signature ──────
    STRONG_THRESHOLD = -0.10
    weak_anomaly     = (prediction == -1 and score > STRONG_THRESHOLD)

    if weak_anomaly and not attack_signature:
        prediction = 1
        suppressed = True
    else:
        suppressed = False

    # ── Determine attack type label ───────────────────────────
    if prediction == -1:
        if features["icmp_ratio"] > 0.7:
            attack_type = "ICMP_FLOOD"
        elif features["udp_ratio"] > 0.7:
            attack_type = "UDP_FLOOD"
        elif features["syn_ratio"] > 0.5 and features["pps"] > 15:
            attack_type = "SYN_FLOOD"
        elif features["pps"] > 80 and features["tcp_ratio"] > 0.7:
            attack_type = "HTTP_FLOOD"
        else:
            attack_type = "UNKNOWN"
    else:
        attack_type = ""

    # ── Build display line ────────────────────────────────────
    status       = "NORMAL    " if prediction == 1 else "⚠️  ANOMALY"
    suppress_tag = " [suppressed]" if suppressed else ""
    type_tag     = f" | type={attack_type}" if attack_type else ""

    print(f"[Window {window_num:>4}] {status}{suppress_tag} | "
          f"score={score:+.4f} | "
          f"pps={features['pps']:>8} | "
          f"syn_ratio={features['syn_ratio']:.3f} | "
          f"unique_ips={features['unique_src_ips']}"
          f"{type_tag}")

    # ── Log confirmed anomalies ───────────────────────────────
    if prediction == -1:
        msg = (f"ML ANOMALY DETECTED | "
               f"type={attack_type} | "
               f"score={score:.4f} | "
               f"pps={features['pps']} | "
               f"syn_ratio={features['syn_ratio']} | "
               f"udp_ratio={features['udp_ratio']} | "
               f"icmp_ratio={features['icmp_ratio']} | "
               f"unique_dst_ports={features['unique_dst_ports']}")
        logging.warning(msg)
        print(f"          🚨 Alert logged → {LOG_FILE}")


sniff(iface=INTERFACE, prn=handle_packet, store=0)
