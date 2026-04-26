from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time, json, statistics, os

# ── Configuration ──────────────────────────────────────────
INTERFACE      = "enp0s8"
COLLECTION_DURATION = 120   # seconds to collect (2 minutes)
OUTPUT_FILE    = "baseline.json"
# ───────────────────────────────────────────────────────────

# Per-second buckets
pps_samples     = []          # total packets per second
tcp_samples     = []
udp_samples     = []
icmp_samples    = []
syn_samples     = []
bytes_samples   = []

# Current-second counters
current = defaultdict(int)
second_start = time.time()
collection_start = time.time()

def analyze(pkt):
    global second_start, current

    now = time.time()

    # Rotate every second
    if now - second_start >= 1.0:
        pps_samples.append(current["packets"])
        tcp_samples.append(current["tcp"])
        udp_samples.append(current["udp"])
        icmp_samples.append(current["icmp"])
        syn_samples.append(current["syn"])
        bytes_samples.append(current["bytes"])

        # Reset counters
        for k in current:
            current[k] = 0
        second_start = now

    if IP not in pkt:
        return

    current["packets"] += 1
    current["bytes"]   += len(pkt)

    if TCP in pkt:
        current["tcp"] += 1
        if pkt[TCP].flags == "S":
            current["syn"] += 1
    elif UDP in pkt:
        current["udp"] += 1
    elif ICMP in pkt:
        current["icmp"] += 1


def safe_stats(data):
    """Return mean, std, max, 95th percentile for a list."""
    if len(data) < 2:
        return {"mean": 0, "std": 0, "max": 0, "p95": 0}
    sorted_data = sorted(data)
    p95_index   = int(len(sorted_data) * 0.95)
    return {
        "mean": round(statistics.mean(data), 2),
        "std":  round(statistics.stdev(data), 2),
        "max":  max(data),
        "p95":  sorted_data[p95_index]
    }


def save_baseline():
    baseline = {
        "collected_at":       time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds":   COLLECTION_DURATION,
        "packets_per_second": safe_stats(pps_samples),
        "bytes_per_second":   safe_stats(bytes_samples),
        "tcp_per_second":     safe_stats(tcp_samples),
        "udp_per_second":     safe_stats(udp_samples),
        "icmp_per_second":    safe_stats(icmp_samples),
        "syn_per_second":     safe_stats(syn_samples),
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(baseline, f, indent=4)

    print("\n\n✅ Baseline saved to", OUTPUT_FILE)
    print(json.dumps(baseline, indent=4))


print(f"[*] Collecting baseline on {INTERFACE} for {COLLECTION_DURATION}s...")
print("[*] Generate NORMAL traffic now (browse, ping, curl). No attacks!\n")

sniff(
    iface=INTERFACE,
    prn=analyze,
    store=0,
    timeout=COLLECTION_DURATION
)

save_baseline()
