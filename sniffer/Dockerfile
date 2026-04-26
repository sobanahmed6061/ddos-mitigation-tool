FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    net-tools \
    iputils-ping \
    tcpdump \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# ── Copy requirements FIRST (separate layer) ──────────────────
# Docker caches this layer — only re-downloads if requirements.txt changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Code is mounted via volume — no need to copy ──────────────
# The docker-compose volume mount ./sniffer:/app handles live code

CMD ["python3", "hybrid_detector.py"]
