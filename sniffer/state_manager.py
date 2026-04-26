"""
Shared state manager — thread-safe data store
shared between hybrid_detector.py and api_server.py
"""

import threading
import time
import json
import os
from collections import deque

class StateManager:
    """
    Thread-safe shared state between detector and API.
    Stores recent alerts, attack history, and live metrics.
    """

    def __init__(self):
        self.lock               = threading.Lock()

        # Live metrics (updated every window)
        self.live_metrics       = {
            "pps"               : 0,
            "bps"               : 0,
            "syn_ratio"         : 0,
            "udp_ratio"         : 0,
            "icmp_ratio"        : 0,
            "tcp_ratio"         : 0,
            "unique_ips"        : 0,
            "window_num"        : 0,
            "last_updated"      : None,
        }

        # Recent alerts (last 100)
        self.recent_alerts      = deque(maxlen=100)

        # Active attacks per IP
        self.active_attacks     = {}
        # Kernel drop counters per IP
        self.kernel_drops       = {}

        # Attack history (last 50 incidents)
        self.attack_history     = deque(maxlen=50)

        # System stats
        self.system_stats       = {
            "total_windows"     : 0,
            "total_alerts"      : 0,
            "total_normal"      : 0,
            "total_blocked_ips" : 0,
            "uptime_start"      : time.time(),
        }

        # WebSocket clients
        self.ws_clients         = set()
        self.ws_lock            = threading.Lock()

        # Recent events for WebSocket streaming
        self.event_queue        = deque(maxlen=1000)

    def update_metrics(self, features, window_num):
        """Update live traffic metrics."""
        with self.lock:
            self.live_metrics.update({
                "pps"          : features.get("pps", 0),
                "bps"          : features.get("bps", 0),
                "syn_ratio"    : features.get("syn_ratio", 0),
                "udp_ratio"    : features.get("udp_ratio", 0),
                "icmp_ratio"   : features.get("icmp_ratio", 0),
                "tcp_ratio"    : features.get("tcp_ratio", 0),
                "unique_ips"   : features.get("unique_src_ips", 0),
                "window_num"   : window_num,
                "last_updated" : time.strftime("%Y-%m-%d %H:%M:%S"),
            })
            self.system_stats["total_windows"] += 1

    def add_alert(self, ip, attack_type, score_data,
                  intel, mit_result, features):
        """Add new alert to state."""
        with self.lock:
            alert = {
                "id"            : f"alert_{int(time.time()*1000)}",
                "timestamp"     : time.strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip"        : ip,
                "attack_type"   : attack_type,
                "threat_score"  : score_data.get("total_score", 0),
                "threat_level"  : score_data.get("threat_level", "?"),
                "pps"           : features.get("pps", 0),
                "country"       : intel.get("country", "?"),
                "isp"           : intel.get("isp", "?"),
                "abuse_score"   : intel.get("abuse_score", 0),
                "mitigation"    : {
                    "level"     : mit_result.get("level", 0),
                    "name"      : mit_result.get("name", "?"),
                    "action"    : mit_result.get("action", "?"),
                },
                "breakdown"     : score_data.get("breakdown", {}),
                "acknowledged"  : False,
            }
            self.recent_alerts.appendleft(alert)
            self.system_stats["total_alerts"] += 1


            # Update active attacks
            self.active_attacks[ip] = {
                "ip"              : ip,
                "attack_type"     : attack_type,
                "started_at"      : self.active_attacks.get(
                    ip, {}
                ).get("started_at", time.strftime("%Y-%m-%d %H:%M:%S")),
                "last_seen"       : time.strftime("%Y-%m-%d %H:%M:%S"),
                "threat_score"    : score_data.get("total_score", 0),
                "mitigation_level": mit_result.get("level", 0),
                "breakdown"       : score_data.get("breakdown", {}),
            }
            # Add to event queue for WebSocket
            self.event_queue.append({
                "type"          : "ALERT",
                "timestamp"     : time.strftime("%Y-%m-%d %H:%M:%S"),
                "data"          : alert,
            })

    def resolve_attack(self, ip):
        """Mark attack as resolved when traffic returns to normal."""
        with self.lock:
            if ip in self.active_attacks:
                attack = self.active_attacks.pop(ip)
                attack["resolved_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                self.attack_history.appendleft(attack)

                self.event_queue.append({
                    "type"      : "RESOLVED",
                    "timestamp" : time.strftime("%Y-%m-%d %H:%M:%S"),
                    "data"      : {"ip": ip, "attack": attack},
                })

    def acknowledge_alert(self, alert_id):
        """Mark alert as acknowledged."""
        with self.lock:
            for alert in self.recent_alerts:
                if alert["id"] == alert_id:
                    alert["acknowledged"] = True
                    return True
        return False

    def get_live_status(self):
        """Get current system status."""
        with self.lock:
            uptime = time.time() - self.system_stats["uptime_start"]
            return {
                "status"            : "running",
                "uptime_seconds"    : round(uptime, 0),
                "active_attacks"    : len(self.active_attacks),
                "total_alerts"      : self.system_stats["total_alerts"],
                "total_windows"     : self.system_stats["total_windows"],
                "live_metrics"      : self.live_metrics.copy(),
                "active_attack_ips" : list(self.active_attacks.keys()),
            }

    def get_recent_alerts(self, limit=20, unack_only=False):
        """Get recent alerts."""
        with self.lock:
            alerts = list(self.recent_alerts)
            if unack_only:
                alerts = [a for a in alerts if not a["acknowledged"]]
            return alerts[:limit]

    def get_attack_history(self, limit=10):
        """Get resolved attack history."""
        with self.lock:
            return list(self.attack_history)[:limit]

    def add_normal_window(self):
        """Track normal window count."""
        with self.lock:
            self.system_stats["total_normal"] += 1

    def update_kernel_drops(self, ip, pkts, bytes_dropped):
        """Update kernel drop counters for an IP."""
        with self.lock:
            self.kernel_drops[ip] = {
                "pkts"  : pkts,
                "bytes" : bytes_dropped,
                "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            # Also update active attack entry
            if ip in self.active_attacks:
                self.active_attacks[ip]["kernel_drops_pkts"]  = pkts
                self.active_attacks[ip]["kernel_drops_bytes"] = bytes_dropped

    def get_kernel_drops(self, ip):
        """Get kernel drop stats for an IP."""
        with self.lock:
            return self.kernel_drops.get(ip, {"pkts": 0, "bytes": 0})

# ── Global instance ───────────────────────────────────────────
state = StateManager()
