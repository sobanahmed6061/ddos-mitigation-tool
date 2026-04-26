from scapy.all import IP, TCP, UDP, ICMP
from collections import defaultdict
import numpy as np
import time

class FeatureExtractor:
    """
    Extracts 20+ statistical features from a window of packets.
    Each window = 5 seconds of traffic.
    Output = one feature vector fed into the ML model.
    """

    def __init__(self, window_size=5):
        self.window_size   = window_size
        self.reset()

    def reset(self):
        """Clear all counters for a new window."""
        self.packets        = []
        self.window_start   = time.time()

    def add_packet(self, pkt):
        """Add one packet to the current window."""
        if IP not in pkt:
            return
        self.packets.append(pkt)

    def is_window_ready(self):
        """Returns True when window_size seconds have passed."""
        return (time.time() - self.window_start) >= self.window_size

    def extract(self):
        """
        Extract all features from the current window.
        Returns a dict of feature_name → value.
        """
        pkts = self.packets
        n    = len(pkts)

        if n == 0:
            return self._empty_features()

        # ── Volume features ───────────────────────────────────
        duration        = max(time.time() - self.window_start, 0.001)
        total_bytes     = sum(len(p) for p in pkts)
        pps             = n / duration
        bps             = total_bytes / duration
        avg_pkt_size    = total_bytes / n

        # ── Protocol counts ───────────────────────────────────
        tcp_count  = sum(1 for p in pkts if TCP  in p)
        udp_count  = sum(1 for p in pkts if UDP  in p)
        icmp_count = sum(1 for p in pkts if ICMP in p)

        tcp_ratio  = tcp_count  / n
        udp_ratio  = udp_count  / n
        icmp_ratio = icmp_count / n

        # ── TCP flag counts ───────────────────────────────────
        syn_count    = sum(1 for p in pkts if TCP in p and p[TCP].flags & 0x02)
        ack_count    = sum(1 for p in pkts if TCP in p and p[TCP].flags & 0x10)
        synack_count = sum(1 for p in pkts if TCP in p and p[TCP].flags & 0x12)
        rst_count    = sum(1 for p in pkts if TCP in p and p[TCP].flags & 0x04)
        fin_count    = sum(1 for p in pkts if TCP in p and p[TCP].flags & 0x01)

        syn_ratio    = syn_count    / max(tcp_count, 1)
        synack_ratio = synack_count / max(tcp_count, 1)
        rst_ratio    = rst_count    / max(tcp_count, 1)

        # ── Source IP diversity ───────────────────────────────
        src_ips         = [p[IP].src for p in pkts]
        unique_src_ips  = len(set(src_ips))

        # Top IP concentration: what fraction came from the top IP?
        ip_counts       = defaultdict(int)
        for ip in src_ips:
            ip_counts[ip] += 1
        top_ip_count    = max(ip_counts.values())
        top_ip_ratio    = top_ip_count / n

        # ── Port diversity ────────────────────────────────────
        dst_ports = [
            p[TCP].dport if TCP in p else (p[UDP].dport if UDP in p else 0)
            for p in pkts
        ]
        unique_dst_ports = len(set(dst_ports))

        src_ports = [
            p[TCP].sport if TCP in p else (p[UDP].sport if UDP in p else 0)
            for p in pkts
        ]
        unique_src_ports = len(set(src_ports))

        # ── Packet inter-arrival times ─────────────────────────
        timestamps = [float(p.time) for p in pkts]
        timestamps.sort()
        if len(timestamps) > 1:
            iats        = np.diff(timestamps)
            iat_mean    = float(np.mean(iats))
            iat_std     = float(np.std(iats))
        else:
            iat_mean    = 0.0
            iat_std     = 0.0

        return {
            # Volume
            "pps":              round(pps, 2),
            "bps":              round(bps, 2),
            "avg_pkt_size":     round(avg_pkt_size, 2),
            "total_packets":    n,
            "total_bytes":      total_bytes,

            # Protocol ratios
            "tcp_ratio":        round(tcp_ratio,  4),
            "udp_ratio":        round(udp_ratio,  4),
            "icmp_ratio":       round(icmp_ratio, 4),

            # TCP flag ratios
            "syn_ratio":        round(syn_ratio,    4),
            "synack_ratio":     round(synack_ratio, 4),
            "rst_ratio":        round(rst_ratio,    4),
            "syn_count":        syn_count,
            "ack_count":        ack_count,
            "rst_count":        rst_count,
            "fin_count":        fin_count,

            # IP diversity
            "unique_src_ips":   unique_src_ips,
            "top_ip_ratio":     round(top_ip_ratio, 4),

            # Port diversity
            "unique_dst_ports": unique_dst_ports,
            "unique_src_ports": unique_src_ports,

            # Timing
            "iat_mean":         round(iat_mean, 6),
            "iat_std":          round(iat_std,  6),

            # Metadata
            "window_duration":  round(duration, 2),
            "label":            "normal"   # changed to "attack" during simulation
        }

    def _empty_features(self):
        """Return zero-valued features when window has no packets."""
        keys = [
            "pps","bps","avg_pkt_size","total_packets","total_bytes",
            "tcp_ratio","udp_ratio","icmp_ratio",
            "syn_ratio","synack_ratio","rst_ratio",
            "syn_count","ack_count","rst_count","fin_count",
            "unique_src_ips","top_ip_ratio",
            "unique_dst_ports","unique_src_ports",
            "iat_mean","iat_std","window_duration"
        ]
        result = {k: 0 for k in keys}
        result["label"] = "normal"
        return result
