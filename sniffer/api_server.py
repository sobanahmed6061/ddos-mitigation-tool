"""
Phase 6 Week 16 — FastAPI REST API + WebSocket Server
Exposes DDoS tool data to SIEM platforms and dashboards.

Endpoints:
  GET  /api/v1/health              System health check
  GET  /api/v1/status              Live attack status
  GET  /api/v1/alerts              Recent alerts
  GET  /api/v1/alerts/live         Active attacks
  GET  /api/v1/alerts/{id}         Specific alert
  POST /api/v1/alerts/acknowledge  Acknowledge alert
  GET  /api/v1/metrics             Live traffic metrics
  GET  /api/v1/history             Attack history
  GET  /api/v1/whitelist           Whitelist entries
  POST /api/v1/whitelist           Add to whitelist
  POST /api/v1/mitigate            Manual mitigation
  GET  /api/v1/ioc/export          Export IOCs
  GET  /api/v1/forensics           List forensic files
  WS   /ws/events                  Real-time event stream
"""

import asyncio
import json
import os
import time
import threading
import uvicorn

from fastapi            import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses  import FileResponse, JSONResponse
from pydantic           import BaseModel
from typing             import Optional, List
from state_manager      import state

# ── App setup ─────────────────────────────────────────────────
app = FastAPI(
    title       = "DDoS Mitigation Tool API",
    description = "Real-time DDoS detection and mitigation API",
    version     = "2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── WebSocket connection manager ──────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active = []
        self.lock   = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self.lock:
            self.active.append(ws)
        print(f"[API] WebSocket connected | total={len(self.active)}")

    async def disconnect(self, ws: WebSocket):
        async with self.lock:
            if ws in self.active:
                self.active.remove(ws)
        print(f"[API] WebSocket disconnected | total={len(self.active)}")

    async def broadcast(self, message: dict):
        async with self.lock:
            dead = []
            for ws in self.active:
                try:
                    await ws.send_json(message)
                except:
                    dead.append(ws)
            for ws in dead:
                self.active.remove(ws)


manager = ConnectionManager()


# ── Request/Response models ───────────────────────────────────
class AcknowledgeRequest(BaseModel):
    alert_id: str

class WhitelistAddRequest(BaseModel):
    ip          : str
    tier        : int = 3
    duration_h  : int = 24
    reason      : str = "api_request"

class MitigateRequest(BaseModel):
    ip          : str
    level       : int
    reason      : str = "manual"


# ─────────────────────────────────────────────────────────────
# REST Endpoints
# ─────────────────────────────────────────────────────────────

@app.get("/api/v1/health")
async def health():
    """System health check — used by monitoring tools."""
    return {
        "status"    : "pass",
        "version"   : "2.0.0",
        "timestamp" : time.strftime("%Y-%m-%d %H:%M:%S"),
        "service"   : "ddos-mitigation-tool",
    }


@app.get("/api/v1/status")
async def get_status():
    """Live system status — active attacks and metrics."""
    return state.get_live_status()


@app.get("/api/v1/alerts")
async def get_alerts(
    limit       : int  = 20,
    unack_only  : bool = False
):
    """Get recent alerts with optional filtering."""
    alerts = state.get_recent_alerts(
        limit       = limit,
        unack_only  = unack_only
    )
    return {
        "count"  : len(alerts),
        "alerts" : alerts,
    }


@app.get("/api/v1/alerts/live")
async def get_live_alerts():
    """Get currently active attacks."""
    with state.lock:
        active = dict(state.active_attacks)
    return {
        "count"   : len(active),
        "attacks" : active,
    }


@app.get("/api/v1/alerts/{alert_id}")
async def get_alert(alert_id: str):
    """Get specific alert by ID."""
    with state.lock:
        for alert in state.recent_alerts:
            if alert["id"] == alert_id:
                return alert
    raise HTTPException(status_code=404, detail="Alert not found")


@app.post("/api/v1/alerts/acknowledge")
async def acknowledge_alert(req: AcknowledgeRequest):
    """Mark alert as acknowledged — for SIEM workflow."""
    success = state.acknowledge_alert(req.alert_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "acknowledged", "alert_id": req.alert_id}


@app.get("/api/v1/metrics")
async def get_metrics():
    """Real-time traffic metrics for SIEM dashboards."""
    with state.lock:
        metrics      = state.live_metrics.copy()
        stats        = state.system_stats.copy()
        kernel_drops = dict(state.kernel_drops)

    uptime = time.time() - stats["uptime_start"]

    # Total drops across all IPs
    total_pkts  = sum(v.get("pkts",  0) for v in kernel_drops.values())
    total_bytes = sum(v.get("bytes", 0) for v in kernel_drops.values())

    return {
        "live_traffic"   : {
            **metrics,
            "total_dropped_pkts"  : total_pkts,
            "total_dropped_bytes" : total_bytes,
        },
        "kernel_drops"   : kernel_drops,
        "system"         : {
            "uptime_s"     : round(uptime, 0),
            "total_windows": stats["total_windows"],
            "total_alerts" : stats["total_alerts"],
            "total_normal" : stats["total_normal"],
        }
    }

@app.get("/api/v1/history")
async def get_history(limit: int = 10):
    """Historical attack list for trend analysis."""
    history = state.get_attack_history(limit=limit)
    return {
        "count"   : len(history),
        "history" : history,
    }


@app.get("/api/v1/whitelist")
async def get_whitelist():
    """Get current whitelist entries."""
    from whitelist_manager import load_whitelist, TIER1_STATIC
    wl = load_whitelist()
    return {
        "tier1_count"  : len(TIER1_STATIC),
        "tier1_ranges" : list(TIER1_STATIC)[:10],  # sample
        "tier2"        : wl.get("tier2", {}),
        "tier3"        : wl.get("tier3", {}),
    }


@app.post("/api/v1/whitelist")
async def add_to_whitelist(req: WhitelistAddRequest):
    """Add IP to whitelist via API."""
    from whitelist_manager import add_tier2, add_tier3
    if req.tier == 2:
        add_tier2(req.ip, reason=req.reason)
    elif req.tier == 3:
        add_tier3(req.ip, req.duration_h, reason=req.reason)
    else:
        raise HTTPException(
            status_code=400,
            detail="tier must be 2 or 3"
        )
    return {
        "status"  : "added",
        "ip"      : req.ip,
        "tier"    : req.tier,
        "reason"  : req.reason,
    }


@app.post("/api/v1/mitigate")
async def manual_mitigate(req: MitigateRequest):
    """Trigger manual mitigation for an IP."""
    from mitigation_engine import apply_mitigation
    result = apply_mitigation(
        ip          = req.ip,
        score       = req.level * 20,   # map level to score
        attack_type = "MANUAL"
    )
    return {
        "status"    : "applied",
        "ip"        : req.ip,
        "level"     : result["level"],
        "name"      : result["name"],
        "reason"    : req.reason,
    }


@app.get("/api/v1/ioc/export")
async def export_iocs():
    """
    Export IOCs in STIX-like format for threat intel sharing.
    """
    with state.lock:
        alerts = list(state.recent_alerts)

    iocs = []
    seen = set()

    for alert in alerts:
        ip = alert.get("src_ip", "")
        if ip and ip not in seen:
            seen.add(ip)
            iocs.append({
                "type"         : "ipv4-addr",
                "value"        : ip,
                "attack_type"  : alert.get("attack_type", "?"),
                "threat_score" : alert.get("threat_score", 0),
                "country"      : alert.get("country", "?"),
                "first_seen"   : alert.get("timestamp", "?"),
                "confidence"   : "high" if alert["threat_score"] > 60
                                 else "medium",
            })

    return {
        "format"     : "STIX-like",
        "generated"  : time.strftime("%Y-%m-%d %H:%M:%S"),
        "ioc_count"  : len(iocs),
        "indicators" : iocs,
    }


@app.get("/api/v1/forensics")
async def list_forensics():
    """List available forensic files."""
    pcap_dir    = "/app/logs/pcap"
    report_dir  = "/app/logs/reports"
    timeline_dir= "/app/logs/timelines"

    def list_files(directory):
        if not os.path.exists(directory):
            return []
        files = []
        for f in os.listdir(directory):
            path = os.path.join(directory, f)
            files.append({
                "filename" : f,
                "size_kb"  : round(os.path.getsize(path)/1024, 1),
                "created"  : time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.localtime(os.path.getctime(path))
                ),
            })
        return sorted(files, key=lambda x: x["created"], reverse=True)

    return {
        "pcap_files"    : list_files(pcap_dir),
        "pdf_reports"   : list_files(report_dir),
        "timelines"     : list_files(timeline_dir),
    }
@app.get("/api/v1/siem/status")
async def get_siem_status():
    """Check connectivity to configured SIEM platforms."""
    from siem_integration import siem_router
    return {
        "siem_connections" : siem_router.test_all_connections(),
        "timestamp"        : time.strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.get("/api/v1/siem/cef/sample")
async def get_cef_sample():
    """Get a sample CEF formatted event."""
    from siem_integration import format_cef
    sample_alert = {
        "id"           : "alert_sample",
        "src_ip"       : "192.168.56.1",
        "attack_type"  : "SYN_FLOOD",
        "threat_score" : 55,
        "threat_level" : "MEDIUM",
        "country"      : "CN",
        "pps"          : 145.3,
        "mitigation"   : {"level": 2, "name": "THROTTLE"},
    }
    return {
        "cef_format" : format_cef(sample_alert),
        "description": "CEF format for Splunk/QRadar/ArcSight/Sentinel"
    }

# ─────────────────────────────────────────────────────────────
# WebSocket Endpoint
# ─────────────────────────────────────────────────────────────

@app.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    """
    Real-time event stream for SIEM integration.
    Pushes alerts, metrics and status updates as they happen.
    """
    await manager.connect(ws)

    try:
        # Send welcome message with current status
        await ws.send_json({
            "type"      : "CONNECTED",
            "timestamp" : time.strftime("%Y-%m-%d %H:%M:%S"),
            "message"   : "DDoS Mitigation Tool WebSocket connected",
            "status"    : state.get_live_status(),
        })

        # Send any queued events
        with state.lock:
            queued = list(state.event_queue)[-10:]  # last 10 events

        for event in queued:
            await ws.send_json(event)

        # Keep connection alive and forward new events
        last_sent = len(state.event_queue)

        while True:
            await asyncio.sleep(1)

            # Check for new events
            current_len = len(state.event_queue)
            if current_len > last_sent:
                with state.lock:
                    new_events = list(state.event_queue)[last_sent:]
                for event in new_events:
                    await ws.send_json(event)
                last_sent = current_len

            # Send heartbeat every 10 seconds
            if int(time.time()) % 10 == 0:
                await ws.send_json({
                    "type"      : "HEARTBEAT",
                    "timestamp" : time.strftime("%Y-%m-%d %H:%M:%S"),
                    "metrics"   : state.live_metrics.copy(),
                })

    except WebSocketDisconnect:
        await manager.disconnect(ws)


# ─────────────────────────────────────────────────────────────
# Server startup
# ─────────────────────────────────────────────────────────────
def find_free_port(start=9999):
    """Find first available port starting from start."""
    import socket
    for port in range(start, start + 20):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("0.0.0.0", port))
            s.close()
            return port
        except OSError:
            continue
    return start + 20


def start_api_server(host="0.0.0.0", port=9999):
    """Start API server in a background thread."""
    port   = find_free_port(port)

    config = uvicorn.Config(
        app,
        host        = host,
        port        = port,
        log_level   = "warning",
        access_log  = False,
    )

    server = uvicorn.Server(config)

    thread = threading.Thread(
        target  = server.run,
        daemon  = True,
        name    = "api-server"
    )
    thread.start()
    print(f"[*] API server started → http://{host}:{port}")
    print(f"[*] API docs          → http://localhost:{port}/docs")
    print(f"[*] WebSocket         → ws://localhost:{port}/ws/events")
    return thread


