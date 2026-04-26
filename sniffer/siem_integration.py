"""
Phase 6 Week 17 — SIEM Integration Module
Supports: Splunk HEC, ELK/Elasticsearch, Syslog CEF, Kafka
"""

import json
import time
import socket
import logging
import threading
import os
import requests
from collections import deque

# ── Config from environment ───────────────────────────────────
SPLUNK_HEC_URL    = os.getenv("SPLUNK_HEC_URL",   "")
SPLUNK_HEC_TOKEN  = os.getenv("SPLUNK_HEC_TOKEN", "")
ELASTIC_URL       = os.getenv("ELASTIC_URL",      "")
ELASTIC_INDEX     = os.getenv("ELASTIC_INDEX",    "ddos-alerts")
SYSLOG_HOST       = os.getenv("SYSLOG_HOST",      "")
SYSLOG_PORT       = int(os.getenv("SYSLOG_PORT",  "514"))
KAFKA_BROKER      = os.getenv("KAFKA_BROKER",     "")
KAFKA_TOPIC       = os.getenv("KAFKA_TOPIC",      "ddos-alerts")
# ─────────────────────────────────────────────────────────────

siem_logger = logging.getLogger("siem")
siem_logger.setLevel(logging.INFO)

# ── Event queue for async shipping ───────────────────────────
event_queue  = deque(maxlen=10000)
queue_lock   = threading.Lock()


# ─────────────────────────────────────────────────────────────
# CEF Format (Common Event Format)
# ─────────────────────────────────────────────────────────────

def format_cef(alert):
    """
    Format alert in CEF format for maximum SIEM compatibility.
    CEF is supported by: Splunk, QRadar, ArcSight, Sentinel
    """
    severity_map = {
        "CRITICAL": 10,
        "HIGH"    : 8,
        "MEDIUM"  : 5,
        "LOW"     : 3,
        "INFO"    : 1,
    }

    severity   = severity_map.get(alert.get("threat_level", "LOW"), 3)
    attack_type = alert.get("attack_type", "UNKNOWN")
    src_ip      = alert.get("src_ip", "0.0.0.0")
    score       = alert.get("threat_score", 0)
    country     = alert.get("country", "Unknown")
    mit_level   = alert.get("mitigation", {}).get("level", 0)
    mit_name    = alert.get("mitigation", {}).get("name", "MONITOR")

    # CEF header
    cef_header = (
        f"CEF:0|DDoS-Tool|MitigationEngine|2.0|"
        f"{attack_type}|DDoS {attack_type} Detected|{severity}|"
    )

    # CEF extension fields
    cef_ext = (
        f"src={src_ip} "
        f"dst=192.168.56.2 "
        f"dpt=80 "
        f"proto=TCP "
        f"act={mit_name} "
        f"cs1={attack_type} "
        f"cs1Label=AttackType "
        f"cs2={country} "
        f"cs2Label=Country "
        f"cn1={score} "
        f"cn1Label=ThreatScore "
        f"cn2={mit_level} "
        f"cn2Label=MitigationLevel "
        f"msg=DDoS attack detected and mitigated"
    )

    return cef_header + cef_ext


# ─────────────────────────────────────────────────────────────
# Splunk HEC Integration
# ─────────────────────────────────────────────────────────────
class SplunkHEC:
    def __init__(self, url, token):
        self.url     = url
        self.token   = token
        self.enabled = bool(url and token)
        if self.enabled:
            print(f"[SIEM] Splunk HEC enabled → {url}")
        # Silent when disabled


    def send(self, alert):
        """Send alert to Splunk via HEC."""
        if not self.enabled:
            return False

        payload = {
            "time"       : time.time(),
            "host"       : "ddos-mitigation-tool",
            "source"     : "ddos_detector",
            "sourcetype" : "ddos:alert",
            "index"      : "security",
            "event"      : alert,
        }

        try:
            response = requests.post(
                f"{self.url}/services/collector/event",
                headers = {
                    "Authorization": f"Splunk {self.token}",
                    "Content-Type" : "application/json",
                },
                json    = payload,
                timeout = 3,
                verify  = False,
            )
            if response.status_code == 200:
                siem_logger.info(f"Splunk HEC: sent alert {alert.get('id')}")
                return True
            else:
                siem_logger.warning(
                    f"Splunk HEC error: {response.status_code}"
                )
                return False
        except Exception as e:
            siem_logger.error(f"Splunk HEC failed: {e}")
            return False

    def test_connection(self):
        """Test Splunk HEC connectivity."""
        if not self.enabled:
            return False, "Not configured"
        try:
            r = requests.get(
                f"{self.url}/services/collector/health",
                headers = {"Authorization": f"Splunk {self.token}"},
                timeout = 3,
                verify  = False,
            )
            return r.status_code == 200, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)


# ─────────────────────────────────────────────────────────────
# Elasticsearch/ELK Integration
# ─────────────────────────────────────────────────────────────
class ElasticSIEM:
    def __init__(self, url, index):
        self.url     = url
        self.index   = index
        self.enabled = bool(url)
        if self.enabled:
            print(f"[SIEM] Elasticsearch enabled → {url}/{index}")
        # Silent when disabled


    def send(self, alert):
        """Index alert document into Elasticsearch."""
        if not self.enabled:
            return False

        doc = {
            "@timestamp"   : time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                           time.gmtime()),
            "event.kind"   : "alert",
            "event.type"   : "indicator",
            "event.category": "network",
            "source.ip"    : alert.get("src_ip"),
            "source.geo.country_iso_code": alert.get("country", "?"),
            "threat.tactic.name": alert.get("attack_type"),
            "ddos.threat_score": alert.get("threat_score"),
            "ddos.threat_level": alert.get("threat_level"),
            "ddos.pps"     : alert.get("pps"),
            "ddos.mitigation_level": alert.get(
                "mitigation", {}
            ).get("level", 0),
            "ddos.mitigation_name" : alert.get(
                "mitigation", {}
            ).get("name", "?"),
            "message"      : (
                f"DDoS {alert.get('attack_type')} from "
                f"{alert.get('src_ip')} "
                f"score={alert.get('threat_score')}"
            ),
        }

        try:
            response = requests.post(
                f"{self.url}/{self.index}/_doc",
                json    = doc,
                headers = {"Content-Type": "application/json"},
                timeout = 3,
            )
            if response.status_code in (200, 201):
                siem_logger.info(
                    f"Elastic: indexed {alert.get('id')}"
                )
                return True
            else:
                siem_logger.warning(
                    f"Elastic error: {response.status_code} "
                    f"{response.text[:100]}"
                )
                return False
        except Exception as e:
            siem_logger.error(f"Elastic failed: {e}")
            return False

    def test_connection(self):
        """Test Elasticsearch connectivity."""
        if not self.enabled:
            return False, "Not configured"
        try:
            r = requests.get(f"{self.url}/_cluster/health", timeout=3)
            data = r.json()
            return True, f"status={data.get('status','?')}"
        except Exception as e:
            return False, str(e)

    def create_index_template(self):
        """Create optimized index template for DDoS alerts."""
        if not self.enabled:
            return

        template = {
            "index_patterns": [f"{self.index}*"],
            "template": {
                "mappings": {
                    "properties": {
                        "@timestamp"        : {"type": "date"},
                        "source.ip"         : {"type": "ip"},
                        "ddos.threat_score" : {"type": "integer"},
                        "ddos.pps"          : {"type": "float"},
                        "ddos.mitigation_level": {"type": "integer"},
                        "threat.tactic.name": {"type": "keyword"},
                        "ddos.threat_level" : {"type": "keyword"},
                        "source.geo.country_iso_code": {"type": "keyword"},
                    }
                }
            }
        }

        try:
            requests.put(
                f"{self.url}/_index_template/ddos-template",
                json    = template,
                headers = {"Content-Type": "application/json"},
                timeout = 3,
            )
            print(f"[SIEM] Elastic index template created")
        except Exception as e:
            siem_logger.error(f"Template creation failed: {e}")


# ─────────────────────────────────────────────────────────────
# Syslog CEF Integration
# ─────────────────────────────────────────────────────────────
class SyslogCEF:
    def __init__(self, host, port=514):
        self.host    = host
        self.port    = port
        self.enabled = bool(host)
        self.sock    = None

        if self.enabled:
            print(f"[SIEM] Syslog CEF enabled → {host}:{port}")
            self._connect()
        # Silent when disabled


    def _connect(self):
        """Create UDP syslog socket."""
        try:
            self.sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )
        except Exception as e:
            siem_logger.error(f"Syslog socket error: {e}")

    def send(self, alert):
        """Send CEF-formatted alert via syslog."""
        if not self.enabled or not self.sock:
            return False

        cef_msg = format_cef(alert)

        # Syslog priority: facility=10 (security), severity=3 (error)
        priority   = (10 * 8) + 3
        syslog_msg = f"<{priority}>{cef_msg}"

        try:
            self.sock.sendto(
                syslog_msg.encode(),
                (self.host, self.port)
            )
            return True
        except Exception as e:
            siem_logger.error(f"Syslog send failed: {e}")
            return False


# ─────────────────────────────────────────────────────────────
# SIEM Router — sends to all configured platforms
# ─────────────────────────────────────────────────────────────

class SIEMRouter:
    """
    Routes alerts to all configured SIEM platforms simultaneously.
    Runs asynchronously so it never slows down the detector.
    """

    def __init__(self):
        self.splunk  = SplunkHEC(SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN)
        self.elastic = ElasticSIEM(ELASTIC_URL, ELASTIC_INDEX)
        self.syslog  = SyslogCEF(SYSLOG_HOST, SYSLOG_PORT)

        # Start background shipping thread
        self.running = True
        self.thread  = threading.Thread(
            target = self._ship_loop,
            daemon = True,
            name   = "siem-shipper"
        )
        self.thread.start()
        if any([self.splunk.enabled, self.elastic.enabled, self.syslog.enabled]):
            print("[SIEM] Event router started")

    def queue_alert(self, alert):
        """Add alert to async shipping queue."""
        with queue_lock:
            event_queue.append(alert)

    def _ship_loop(self):
        """Background loop that ships queued events."""
        while self.running:
            if event_queue:
                with queue_lock:
                    alert = event_queue.popleft() \
                            if event_queue else None

                if alert:
                    self._ship_to_all(alert)

            time.sleep(0.1)

    def _ship_to_all(self, alert):
        """Send alert to all enabled SIEM platforms."""
        if self.splunk.enabled:
            self.splunk.send(alert)

        if self.elastic.enabled:
            self.elastic.send(alert)

        if self.syslog.enabled:
            self.syslog.send(alert)

    def test_all_connections(self):
        """Test connectivity to all configured SIEMs."""
        results = {}

        ok, msg = self.splunk.test_connection()
        results["splunk"] = {
            "enabled": self.splunk.enabled,
            "connected": ok,
            "message": msg
        }

        ok, msg = self.elastic.test_connection()
        results["elasticsearch"] = {
            "enabled": self.elastic.enabled,
            "connected": ok,
            "message": msg
        }

        results["syslog"] = {
            "enabled": self.syslog.enabled,
            "host"   : SYSLOG_HOST,
            "port"   : SYSLOG_PORT,
        }

        return results

    def get_cef_sample(self, alert):
        """Return sample CEF formatted event for testing."""
        return format_cef(alert)


# ── Global instance ───────────────────────────────────────────
siem_router = SIEMRouter()
