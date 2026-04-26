# DDoS Mitigation Tool v2.0

## Overview
A comprehensive network security platform combining real-time traffic
analysis, machine learning anomaly detection, automated mitigation,
and SIEM integration to protect infrastructure from DDoS attacks.

## Architecture
Packet Capture (Scapy) → Feature Extraction (20+ features)
→ Isolation Forest + LSTM Hybrid Detection
→ Random Forest Attack Classification
→ Threat Intelligence (AbuseIPDB + GeoIP)
→ Composite Threat Scoring (0-100)
→ Graduated Mitigation Ladder (L1-L5 iptables)
→ PCAP Capture + Forensic PDF Reports
→ FastAPI REST API + WebSocket Streaming
→ SIEM Integration (Splunk/ELK/Syslog/CEF)
→ React Live Dashboard

## Quick Start

### Start all containers
```bash
cd /home/ubuntu/ddos-tool
sudo docker compose up -d
```

### Run hybrid detector
```bash
sudo docker exec -it ddos_sniffer python3 /app/hybrid_detector.py
```

### Open dashboard
```bash
cd /home/ubuntu/ddos-tool/dashboard
python3 -m http.server 7777
# Open: http://192.168.56.2:7777/index.html
```

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/health | System health check |
| GET | /api/v1/status | Live attack status |
| GET | /api/v1/alerts | Recent alerts |
| GET | /api/v1/alerts/live | Active attacks |
| POST | /api/v1/alerts/acknowledge | Acknowledge alert |
| GET | /api/v1/metrics | Live traffic metrics |
| GET | /api/v1/history | Attack history |
| GET | /api/v1/whitelist | Whitelist entries |
| POST | /api/v1/whitelist | Add to whitelist |
| POST | /api/v1/mitigate | Manual mitigation |
| GET | /api/v1/ioc/export | Export IOCs |
| GET | /api/v1/forensics | List forensic files |
| GET | /api/v1/siem/status | SIEM connectivity |
| GET | /api/v1/siem/cef/sample | Sample CEF event |
| WS | /ws/events | Real-time stream |

## ML Models

| Model | Purpose | Performance |
|-------|---------|-------------|
| Isolation Forest | Anomaly detection | F1: 0.9485 |
| LSTM Neural Network | Sequence analysis | F1: 0.9804 |
| Random Forest | Attack classification | Accuracy: 100% |

## Attack Types Detected
- SYN Flood
- UDP Flood
- ICMP Flood
- HTTP Flood
- Slowloris
- Volumetric attacks

## Mitigation Levels
| Level | Trigger | Action |
|-------|---------|--------|
| L1 MONITOR | Score 0-39 | Log only |
| L2 THROTTLE | Score 40-54 | Rate limit 50pps |
| L3 RESTRICT | Score 55-69 | Rate limit 10pps |
| L4 BLOCK | Score 70-84 | iptables DROP |
| L5 NULLROUTE | Score 85-100 | Permanent ban |

## Project Structure
ddos-tool/
├── sniffer/
│   ├── hybrid_detector.py      Main detector
│   ├── feature_extractor.py    20+ traffic features
│   ├── ml_detector.py          Isolation Forest
│   ├── train_model.py          IF trainer
│   ├── train_lstm.py           LSTM trainer
│   ├── train_classifier.py     RF trainer
│   ├── threat_intel.py         AbuseIPDB + GeoIP
│   ├── threat_scorer.py        0-100 scoring
│   ├── mitigation_engine.py    iptables automation
│   ├── token_bucket.py         Rate limit metrics
│   ├── whitelist_manager.py    3-tier whitelist
│   ├── pcap_engine.py          PCAP capture
│   ├── report_generator.py     PDF reports
│   ├── state_manager.py        Shared state
│   ├── api_server.py           FastAPI REST API
│   └── siem_integration.py     SIEM connectors
├── dashboard/
│   └── index.html              React dashboard
├── logs/
│   ├── hybrid_alerts.log
│   ├── mitigation.log
│   ├── pcap/
│   ├── reports/
│   └── timelines/
└── docker-compose.yml
