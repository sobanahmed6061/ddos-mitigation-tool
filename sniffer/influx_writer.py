"""
InfluxDB Time-Series Writer
Stores traffic metrics and alerts for Grafana visualization.
"""

import time
import os
from influxdb_client          import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

# ── Config ────────────────────────────────────────────────────
INFLUX_URL    = os.getenv("INFLUX_URL",    "http://localhost:8086")
INFLUX_TOKEN  = os.getenv("INFLUX_TOKEN",  "")
INFLUX_ORG    = os.getenv("INFLUX_ORG",   "ddos-lab")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "traffic")
# ─────────────────────────────────────────────────────────────

class InfluxWriter:
    def __init__(self):
        self.enabled = False
        self.client  = None
        self.write_api = None
        self._connect()

    def _connect(self):
        """Connect to InfluxDB — get token from env or setup."""
        try:
            # Get token from InfluxDB setup
            token = INFLUX_TOKEN or self._get_token()
            if not token:
                print("[InfluxDB] No token found — metrics disabled")
                return

            self.client    = InfluxDBClient(
                url   = INFLUX_URL,
                token = token,
                org   = INFLUX_ORG
            )
            self.write_api = self.client.write_api(
                write_options=SYNCHRONOUS
            )
            # Test connection
            self.client.ping()
            self.enabled = True
            print(f"[InfluxDB] Connected → {INFLUX_URL}")

        except Exception as e:
            print(f"[InfluxDB] Connection failed: {e}")
            self.enabled = False

    def _get_token(self):
        """Try to read InfluxDB token from config file."""
        token_paths = [
            "/app/influx_token.txt",
            "/home/ubuntu/ddos-tool/influx_token.txt",
        ]
        for path in token_paths:
            try:
                with open(path) as f:
                    return f.read().strip()
            except:
                continue
        return ""

    def write_metrics(self, features, window_num):
        """Write per-window traffic metrics to InfluxDB."""
        if not self.enabled:
            return
        try:
            point = (
                Point("traffic_metrics")
                .tag("host", "ubuntu-victim")
                .field("pps",           features.get("pps", 0))
                .field("bps",           features.get("bps", 0))
                .field("syn_ratio",     features.get("syn_ratio", 0))
                .field("udp_ratio",     features.get("udp_ratio", 0))
                .field("icmp_ratio",    features.get("icmp_ratio", 0))
                .field("tcp_ratio",     features.get("tcp_ratio", 0))
                .field("unique_src_ips",features.get("unique_src_ips", 0))
                .field("avg_pkt_size",  features.get("avg_pkt_size", 0))
                .field("window_num",    window_num)
                .time(time.time_ns(), WritePrecision.NS)
            )
            self.write_api.write(
                bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point
            )
        except Exception as e:
            print(f"❌ [INFLUX ERROR]: {e}")   # silent fail — never slow down detector

    def write_alert(self, ip, attack_type, score,
                    threat_level, pps, mit_level):
        """Write alert event to InfluxDB."""
        if not self.enabled:
            return
        try:
            point = (
                Point("ddos_alerts")
                .tag("host",         "ubuntu-victim")
                .tag("src_ip",       ip)
                .tag("attack_type",  attack_type)
                .tag("threat_level", threat_level)
                .tag("mit_level",    f"L{mit_level}")
                .field("threat_score",     score)
                .field("pps",              pps)
                .field("mitigation_level", mit_level)
                .time(time.time_ns(), WritePrecision.NS)
            )
            self.write_api.write(
                bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point
            )
        except Exception as e:
            print(f"❌ [INFLUX ERROR]: {e}")

    def write_mitigation(self, ip, level, pkts_dropped):
        """Write mitigation action to InfluxDB."""
        if not self.enabled:
            return
        try:
            point = (
                Point("mitigation_actions")
                .tag("host",    "ubuntu-victim")
                .tag("src_ip",  ip)
                .tag("level",   f"L{level}")
                .field("mitigation_level", level)
                .field("pkts_dropped",     pkts_dropped)
                .time(time.time_ns(), WritePrecision.NS)
            )
            self.write_api.write(
                bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point
            )
        except Exception as e:
            print(f"❌ [INFLUX ERROR]: {e}")


# ── Global instance ───────────────────────────────────────────
influx = InfluxWriter()
