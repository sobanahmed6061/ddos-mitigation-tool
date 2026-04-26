from scapy.all import sniff, IP
from feature_extractor import FeatureExtractor
import csv, os, sys, time

# ── Config ────────────────────────────────────────────────────
INTERFACE    = os.getenv("INTERFACE", "enp0s8")
DURATION     = int(os.getenv("DURATION", "600"))    # 10 minutes default
LABEL        = sys.argv[1] if len(sys.argv) > 1 else "normal"
OUTPUT_FILE  = f"/app/logs/training_{LABEL}.csv"
WINDOW_SIZE  = 5  # seconds per feature window
# ─────────────────────────────────────────────────────────────

extractor   = FeatureExtractor(window_size=WINDOW_SIZE)
all_rows    = []
start_time  = time.time()

FEATURE_COLUMNS = [
    "pps","bps","avg_pkt_size","total_packets","total_bytes",
    "tcp_ratio","udp_ratio","icmp_ratio",
    "syn_ratio","synack_ratio","rst_ratio",
    "syn_count","ack_count","rst_count","fin_count",
    "unique_src_ips","top_ip_ratio",
    "unique_dst_ports","unique_src_ports",
    "iat_mean","iat_std","window_duration","label"
]

def handle_packet(pkt):
    if IP not in pkt:
        return

    extractor.add_packet(pkt)

    if extractor.is_window_ready():
        features         = extractor.extract()
        features["label"] = LABEL          # force correct label
        all_rows.append(features)

        elapsed = int(time.time() - start_time)
        print(f"  [Window {len(all_rows):>4}] "
              f"pps={features['pps']:>8} | "
              f"syn_ratio={features['syn_ratio']:.3f} | "
              f"unique_ips={features['unique_src_ips']:>3} | "
              f"label={LABEL}  "
              f"[{elapsed}s/{DURATION}s]")

        extractor.reset()

print(f"\n[*] Collecting '{LABEL}' training data on {INTERFACE}")
print(f"[*] Duration: {DURATION}s | Window: {WINDOW_SIZE}s")
print(f"[*] Output:   {OUTPUT_FILE}\n")

if LABEL == "attack":
    print("⚠️  START YOUR ATTACK FROM KALI NOW!\n")
else:
    print("ℹ️  Generate normal traffic (curl loops, browsing).\n")

sniff(
    iface=INTERFACE,
    prn=handle_packet,
    store=0,
    timeout=DURATION
)

# Save to CSV
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=FEATURE_COLUMNS)
    writer.writeheader()
    writer.writerows(all_rows)

print(f"\n✅ Saved {len(all_rows)} windows to {OUTPUT_FILE}")
