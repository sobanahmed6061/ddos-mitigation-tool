"""
Week 9 — Composite Threat Scorer
Combines ML signals + threat intel + attack behavior
into a single 0-100 threat score per IP.

Score breakdown:
  ML Anomaly Strength    : 0-25 pts
  Attack Type Severity   : 0-20 pts
  Packet Rate            : 0-20 pts
  AbuseIPDB Score        : 0-20 pts
  Attack Duration        : 0-15 pts
  ─────────────────────────────────
  Total                  : 0-100 pts
"""

import time
from collections import defaultdict

# ── Attack type severity weights ──────────────────────────────
ATTACK_SEVERITY = {
    "SYN_FLOOD"  : 20,
    "UDP_FLOOD"  : 18,
    "HTTP_FLOOD" : 16,
    "ICMP_FLOOD" : 14,
    "SLOWLORIS"  : 15,
    "VOLUMETRIC" : 20,
    "UNKNOWN"    : 10,
    ""           : 0,
}

# ── Threat level thresholds ───────────────────────────────────
THREAT_LEVELS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0,  "INFO"),
]

# ── Per-IP attack tracking ────────────────────────────────────
# Stores attack start time and window count per IP
ip_attack_history = defaultdict(lambda: {
    "first_seen"    : None,
    "last_seen"     : None,
    "alert_count"   : 0,
    "attack_types"  : set(),
    "max_pps"       : 0,
    "total_score"   : 0,
})


def get_threat_level(score):
    """Convert numeric score to level label."""
    for threshold, level in THREAT_LEVELS:
        if score >= threshold:
            return level
    return "INFO"


def score_ml_anomaly(iso_score, lstm_conf):
    """
    Score ML anomaly strength: 0-25 pts
    Stronger anomaly signal = higher score
    """
    pts = 0

    # Isolation Forest contribution (0-12 pts)
    # iso_score is negative for anomalies, more negative = stronger
    if iso_score < -0.12:
        pts += 12
    elif iso_score < -0.09:
        pts += 9
    elif iso_score < -0.06:
        pts += 6
    elif iso_score < -0.03:
        pts += 3

    # LSTM contribution (0-13 pts)
    if lstm_conf is not None:
        if lstm_conf >= 0.99:
            pts += 13
        elif lstm_conf >= 0.95:
            pts += 10
        elif lstm_conf >= 0.80:
            pts += 7
        elif lstm_conf >= 0.50:
            pts += 4

    return min(pts, 25)


def score_attack_type(attack_type, clf_conf):
    """
    Score attack type severity: 0-20 pts
    More dangerous attack types score higher.
    Confidence scales the score.
    """
    base = ATTACK_SEVERITY.get(attack_type, 10)

    # Scale by classifier confidence
    if clf_conf >= 0.90:
        return base
    elif clf_conf >= 0.70:
        return int(base * 0.85)
    elif clf_conf >= 0.50:
        return int(base * 0.65)
    else:
        return int(base * 0.40)


def score_packet_rate(pps):
    """
    Score packet rate: 0-20 pts
    Higher packet rates indicate more severe attacks.
    """
    if pps >= 500:
        return 20
    elif pps >= 200:
        return 16
    elif pps >= 100:
        return 12
    elif pps >= 50:
        return 8
    elif pps >= 20:
        return 5
    elif pps >= 10:
        return 3
    else:
        return 1


def score_abuse_intel(intel):
    """
    Score threat intelligence: 0-20 pts
    Based on AbuseIPDB abuse confidence score.
    Private IPs get 0 (lab environment).
    """
    if intel.get("is_private"):
        return 0

    abuse_score = intel.get("abuse_score", 0)

    if abuse_score >= 80:
        return 20
    elif abuse_score >= 60:
        return 16
    elif abuse_score >= 40:
        return 12
    elif abuse_score >= 20:
        return 8
    elif abuse_score > 0:
        return 4
    else:
        return 0


def score_attack_duration(ip):
    """
    Score attack duration: 0-15 pts
    Sustained attacks score higher than brief ones.
    """
    history = ip_attack_history[ip]

    if history["first_seen"] is None:
        return 0

    duration = time.time() - history["first_seen"]
    count    = history["alert_count"]

    if duration >= 120 or count >= 20:
        return 15
    elif duration >= 60 or count >= 10:
        return 12
    elif duration >= 30 or count >= 5:
        return 8
    elif duration >= 15 or count >= 3:
        return 4
    else:
        return 2


def update_ip_history(ip, attack_type, pps):
    """Update per-IP attack tracking data."""
    now     = time.time()
    history = ip_attack_history[ip]

    if history["first_seen"] is None:
        history["first_seen"] = now

    history["last_seen"]  = now
    history["alert_count"] += 1
    history["max_pps"]    = max(history["max_pps"], pps)

    if attack_type:
        history["attack_types"].add(attack_type)


def clear_ip_history(ip):
    """Reset tracking when attack ends."""
    if ip in ip_attack_history:
        del ip_attack_history[ip]


def compute_threat_score(
    ip,
    attack_type,
    clf_conf,
    iso_score,
    lstm_conf,
    pps,
    intel
):
    """
    Main function — compute composite threat score for an IP.
    Returns full scoring breakdown dict.
    """
    # Update attack history for this IP
    update_ip_history(ip, attack_type, pps)

    # Compute individual component scores
    ml_pts       = score_ml_anomaly(iso_score, lstm_conf)
    type_pts     = score_attack_type(attack_type, clf_conf)
    pps_pts      = score_packet_rate(pps)
    intel_pts    = score_abuse_intel(intel)
    duration_pts = score_attack_duration(ip)

    # Total score capped at 100
    total = min(ml_pts + type_pts + pps_pts + intel_pts + duration_pts, 100)

    level   = get_threat_level(total)
    history = ip_attack_history[ip]

    return {
        "ip"              : ip,
        "total_score"     : total,
        "threat_level"    : level,
        "breakdown"       : {
            "ml_anomaly"   : ml_pts,
            "attack_type"  : type_pts,
            "packet_rate"  : pps_pts,
            "threat_intel" : intel_pts,
            "duration"     : duration_pts,
        },
        "attack_type"     : attack_type,
        "clf_confidence"  : round(clf_conf, 3),
        "pps"             : pps,
        "alert_count"     : history["alert_count"],
        "attack_duration" : round(time.time() - history["first_seen"], 1)
                            if history["first_seen"] else 0,
        "max_pps"         : history["max_pps"],
    }


def format_score_display(score_data):
    """
    Format threat score into a readable display block.
    """
    total   = score_data["total_score"]
    level   = score_data["threat_level"]
    bd      = score_data["breakdown"]

    # Visual score bar
    filled  = int(total / 5)
    empty   = 20 - filled
    bar     = "█" * filled + "░" * empty

    lines = [
        f"          ┌─ THREAT SCORE: {total}/100 [{bar}] {level}",
        f"          │  ML Anomaly:{bd['ml_anomaly']:>3}/25  "
        f"Attack Type:{bd['attack_type']:>2}/20  "
        f"Pkt Rate:{bd['packet_rate']:>2}/20  "
        f"Intel:{bd['threat_intel']:>2}/20  "
        f"Duration:{bd['duration']:>2}/15",
        f"          │  Alerts:{score_data['alert_count']}  "
        f"Duration:{score_data['attack_duration']}s  "
        f"MaxPPS:{score_data['max_pps']}",
        f"          └─ IP:{score_data['ip']}  "
        f"Type:{score_data['attack_type']}  "
        f"CLF:{score_data['clf_confidence']:.0%}",
    ]
    return "\n".join(lines)
