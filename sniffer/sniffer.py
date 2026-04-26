#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
import logging
import json
import os

# ── Read config from environment variables (Docker) or use defaults ──
INTERFACE     = os.getenv("INTERFACE", "enp0s8")
BASELINE_FILE = os.getenv("BASELINE_FILE", "baseline.json")
LOG_FILE      = os.getenv("LOG_FILE", "ddos_alerts.log")

# ── Load baseline (if exists) ──
baseline = {}

if os.path.exists(BASELINE_FILE):
    with open(BASELINE_FILE) as f:
        baseline = json.load(f)
    print(f"[*] Baseline loaded from {BASELINE_FILE}")
else:
    print(f"[!] No baseline file found at {BASELINE_FILE}. Run baseline_collector.py first.")

# ── Dynamic threshold (mean + 5*std), with a safe minimum (you set 50) ──
# NOTE: Your baseline.json uses key "syn_per_second" (not "syn_per_second")
syn_mean = baseline.get("syn_per_second", {}).get("mean", 0)
syn_std  = baseline.get("syn_per_second", {}).get("std", 1)

SYN_THRESHOLD = max(50, int(syn_mean + 5 * syn_std))
print(f"[*] SYN_THRESHOLD={SYN_THRESHOLD} (mean={syn_mean:.2f}, std={syn_std:.2f})")

# ── Logging (writes alerts to file) ──
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING,
    format="%(asctime)s - %(message)s"
)

packet_counts = defaultdict(int)
syn_counts = defaultdict(int)
start_time = time.time()

def analyze_packet(pkt):
    if IP in pkt:
        src = pkt[IP].src
        packet_counts[src] += 1

        if TCP in pkt and pkt[TCP].flags == "S":
            syn_counts[src] += 1

            # Alert using baseline threshold
            if syn_counts[src] > SYN_THRESHOLD:
                msg = f"SYN FLOOD from {src} | count={syn_counts[src]} | threshold={SYN_THRESHOLD}"
                print(f"[ALERT] {msg}")
                logging.warning(msg)

if __name__ == "__main__":
    print(f"[*] Start sniffer on {INTERFACE} (Ctrl+C to stop)")
    print(f"[*] Baseline file: {BASELINE_FILE}")
    print(f"[*] Log file: {LOG_FILE}")
    sniff(iface=INTERFACE, prn=analyze_packet, store=0)
