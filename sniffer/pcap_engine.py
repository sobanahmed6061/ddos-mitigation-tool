"""
Phase 5 Week 13 — PCAP Capture Engine
Automatically captures packets during attacks and
reconstructs attack timelines for forensic analysis.
"""

import os
import time
import threading
import json
from collections import defaultdict
from scapy.all import wrpcap, PacketList

# ── Config ────────────────────────────────────────────────────
PCAP_DIR     = "/app/logs/pcap"
TIMELINE_DIR = "/app/logs/timelines"
MAX_PACKETS  = 100000   # max packets per capture
MAX_FILESIZE = 50       # MB max per pcap file
# ─────────────────────────────────────────────────────────────

os.makedirs(PCAP_DIR,     exist_ok=True)
os.makedirs(TIMELINE_DIR, exist_ok=True)


class PCAPEngine:
    """
    Captures packets during attack windows and saves
    them to compressed PCAP files for Wireshark analysis.
    """

    def __init__(self):
        self.capturing      = False
        self.current_attack = None
        self.packet_buffer  = []
        self.lock           = threading.Lock()
        self.capture_start  = None
        self.attack_id      = None

    def start_capture(self, attack_type, src_ip):
        """Start capturing packets for a new attack."""
        with self.lock:
            if self.capturing:
                return   # already capturing

            self.capturing     = True
            self.capture_start = time.time()
            self.attack_id     = time.strftime("%Y%m%d_%H%M%S")
            self.packet_buffer = []
            self.current_attack = {
                "attack_id"  : self.attack_id,
                "attack_type": attack_type,
                "src_ip"     : src_ip,
                "start_time" : time.strftime("%Y-%m-%d %H:%M:%S"),
                "start_ts"   : self.capture_start,
            }
            print(f"          📸 PCAP capture started → "
                  f"{PCAP_DIR}/attack_{self.attack_id}.pcap")

    def add_packet(self, pkt):
        """Add packet to capture buffer during active capture."""
        if not self.capturing:
            return

        with self.lock:
            if len(self.packet_buffer) < MAX_PACKETS:
                self.packet_buffer.append(pkt)

    def stop_capture(self, attack_stats=None):
        """
        Stop capture and save PCAP file.
        Returns path to saved file.
        """
        with self.lock:
            if not self.capturing:
                return None

            self.capturing = False
            packets        = self.packet_buffer.copy()
            attack_id      = self.attack_id
            attack_info    = self.current_attack.copy()
            self.packet_buffer = []

        if not packets:
            print("          📸 PCAP: No packets captured")
            return None

        # Save PCAP file
        pcap_path = f"{PCAP_DIR}/attack_{attack_id}.pcap"
        try:
            wrpcap(pcap_path, packets)
            size_kb = os.path.getsize(pcap_path) / 1024

            print(f"          💾 PCAP saved → {pcap_path} "
                  f"({len(packets)} pkts, {size_kb:.1f}KB)")

            # Save capture metadata
            meta = {
                **attack_info,
                "end_time"     : time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration_s"   : round(time.time() - attack_info["start_ts"], 1),
                "packet_count" : len(packets),
                "file_size_kb" : round(size_kb, 1),
                "pcap_path"    : pcap_path,
            }
            if attack_stats:
                meta.update(attack_stats)

            meta_path = f"{PCAP_DIR}/attack_{attack_id}_meta.json"
            with open(meta_path, "w") as f:
                json.dump(meta, f, indent=4)

            return pcap_path

        except Exception as e:
            print(f"          ❌ PCAP save failed: {e}")
            return None


class AttackTimeline:
    """
    Reconstructs attack timeline from window-by-window data.
    Tracks how attack evolved over time per IP.
    """

    def __init__(self):
        self.events     = []
        self.ip_stats   = defaultdict(lambda: {
            "first_seen"    : None,
            "last_seen"     : None,
            "peak_pps"      : 0,
            "total_alerts"  : 0,
            "attack_types"  : set(),
            "max_score"     : 0,
            "mitigation_levels": [],
        })
        self.start_time = time.time()

    def add_event(self, event_type, ip, data):
        """
        Add an event to the timeline.
        event_type: ALERT / NORMAL / MITIGATION / WHITELIST
        """
        event = {
            "timestamp"  : time.strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed_s"  : round(time.time() - self.start_time, 1),
            "event_type" : event_type,
            "ip"         : ip,
            **data
        }
        self.events.append(event)

        # Update per-IP stats
        stats = self.ip_stats[ip]
        now   = time.time()

        if stats["first_seen"] is None:
            stats["first_seen"] = now
        stats["last_seen"] = now

        if event_type == "ALERT":
            stats["total_alerts"] += 1
            stats["peak_pps"]      = max(
                stats["peak_pps"],
                data.get("pps", 0)
            )
            if data.get("attack_type"):
                stats["attack_types"].add(data["attack_type"])
            stats["max_score"] = max(
                stats["max_score"],
                data.get("threat_score", 0)
            )

        if event_type == "MITIGATION":
            level = data.get("level", 0)
            if level not in stats["mitigation_levels"]:
                stats["mitigation_levels"].append(level)

    def get_attack_summary(self, ip):
        """Generate summary for a specific attacking IP."""
        stats    = self.ip_stats.get(ip, {})
        duration = 0

        if stats.get("first_seen") and stats.get("last_seen"):
            duration = round(stats["last_seen"] - stats["first_seen"], 1)

        return {
            "ip"                : ip,
            "duration_seconds"  : duration,
            "total_alerts"      : stats.get("total_alerts", 0),
            "peak_pps"          : stats.get("peak_pps", 0),
            "attack_types"      : list(stats.get("attack_types", set())),
            "max_threat_score"  : stats.get("max_score", 0),
            "mitigation_levels" : sorted(stats.get("mitigation_levels", [])),
        }

    def save_timeline(self, attack_id):
        """Save complete timeline to JSON file."""
        # Convert sets to lists for JSON serialization
        ip_stats_serializable = {}
        for ip, stats in self.ip_stats.items():
            ip_stats_serializable[ip] = {
                **stats,
                "attack_types"      : list(stats["attack_types"]),
                "mitigation_levels" : list(stats["mitigation_levels"]),
            }

        timeline_data = {
            "attack_id"    : attack_id,
            "generated_at" : time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_events" : len(self.events),
            "ip_summaries" : {
                ip: self.get_attack_summary(ip)
                for ip in self.ip_stats
            },
            "events"       : self.events,
            "ip_stats"     : ip_stats_serializable,
        }

        path = f"{TIMELINE_DIR}/timeline_{attack_id}.json"
        with open(path, "w") as f:
            json.dump(timeline_data, f, indent=4)

        print(f"          📊 Timeline saved → {path} "
              f"({len(self.events)} events)")
        return path

    def print_summary(self):
        """Print attack summary to terminal."""
        if not self.ip_stats:
            return

        print("\n" + "═" * 80)
        print("  ATTACK TIMELINE SUMMARY")
        print("═" * 80)

        for ip, stats in self.ip_stats.items():
            summary = self.get_attack_summary(ip)
            if summary["total_alerts"] == 0:
                continue

            duration = summary["duration_seconds"]
            print(f"\n  IP: {ip}")
            print(f"  ├─ Duration      : {duration}s")
            print(f"  ├─ Total Alerts  : {summary['total_alerts']}")
            print(f"  ├─ Peak PPS      : {summary['peak_pps']}")
            print(f"  ├─ Attack Types  : {', '.join(summary['attack_types'])}")
            print(f"  ├─ Max Score     : {summary['max_threat_score']}/100")
            print(f"  └─ Mitig Levels  : "
                  f"{['L'+str(l) for l in summary['mitigation_levels']]}")

        print("\n" + "═" * 80 + "\n")


# ── Global instances ──────────────────────────────────────────
pcap_engine    = PCAPEngine()
attack_timeline = AttackTimeline()
