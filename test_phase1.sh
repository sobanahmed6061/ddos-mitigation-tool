#!/bin/bash
# ─────────────────────────────────────────────────────────────
# Phase 1 Test Suite — DDoS Mitigation Tool (Fixed Version)
# ─────────────────────────────────────────────────────────────

# Use absolute path — avoids ~ expanding to /root when using sudo
PROJECT_DIR="/home/ubuntu/ddos-tool"
LOGS_DIR="$PROJECT_DIR/logs"
RESULTS_FILE="$LOGS_DIR/phase1_test_results.txt"
ALERT_LOG="$LOGS_DIR/ddos_alerts.log"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.yml"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
PASS=0
FAIL=0

# ── Ensure logs directory exists ──────────────────────────────
mkdir -p "$LOGS_DIR"

# ── Helper functions ──────────────────────────────────────────
pass() {
    echo "  [PASS] $1" | tee -a "$RESULTS_FILE"
    ((PASS++))
}

fail() {
    echo "  [FAIL] $1" | tee -a "$RESULTS_FILE"
    ((FAIL++))
}

# ── Clear old results file ────────────────────────────────────
> "$RESULTS_FILE"

echo "================================================" | tee -a "$RESULTS_FILE"
echo " Phase 1 Test Suite — DDoS Mitigation Tool"     | tee -a "$RESULTS_FILE"
echo " Run at: $TIMESTAMP"                             | tee -a "$RESULTS_FILE"
echo "================================================" | tee -a "$RESULTS_FILE"

# ─────────────────────────────────────────────────────────────
# TEST 1 — Docker containers are running
# ─────────────────────────────────────────────────────────────
echo "" | tee -a "$RESULTS_FILE"
echo "TEST 1: Container Status" | tee -a "$RESULTS_FILE"

check_container() {
    local name=$1
    local status
    status=$(docker compose -f "$COMPOSE_FILE" ps "$name" 2>/dev/null | grep "$name")
    if echo "$status" | grep -q "Up\|running"; then
        pass "$name is running"
    else
        fail "$name is NOT running"
    fi
}

check_container "sniffer"
check_container "influxdb"
check_container "redis"

# ─────────────────────────────────────────────────────────────
# TEST 2 — Service health checks
# ─────────────────────────────────────────────────────────────
echo "" | tee -a "$RESULTS_FILE"
echo "TEST 2: Service Health Checks" | tee -a "$RESULTS_FILE"

# InfluxDB health (fixed — single clean check)
INFLUX_STATUS=$(curl -s http://localhost:8086/health)
if echo "$INFLUX_STATUS" | grep -q '"status":"pass"'; then
    pass "InfluxDB health check passed"
else
    fail "InfluxDB not healthy — response: $INFLUX_STATUS"
fi

# Redis ping
REDIS_RESPONSE=$(docker exec ddos_redis redis-cli ping 2>/dev/null)
if [ "$REDIS_RESPONSE" = "PONG" ]; then
    pass "Redis responded with PONG"
else
    fail "Redis did not respond (got: $REDIS_RESPONSE)"
fi

# Baseline file inside sniffer container
if docker exec ddos_sniffer test -f /app/baseline.json 2>/dev/null; then
    pass "baseline.json exists inside sniffer container"
else
    fail "baseline.json missing inside sniffer container"
fi

# Sniffer log file exists on host
if [ -f "$ALERT_LOG" ]; then
    pass "Alert log file exists at $ALERT_LOG"
else
    fail "Alert log file not found at $ALERT_LOG"
fi

# ─────────────────────────────────────────────────────────────
# TEST 3 — SYN Flood Detection (traffic from Kali)
# ─────────────────────────────────────────────────────────────
echo "" | tee -a "$RESULTS_FILE"
echo "TEST 3: SYN Flood Detection" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Clear old alerts so we only count new ones
> "$ALERT_LOG"
docker compose -f "$COMPOSE_FILE" restart sniffer > /dev/null 2>&1
sleep 3

echo "  ┌─────────────────────────────────────────────────┐"
echo "  │  ACTION REQUIRED — Go to your KALI machine now  │"
echo "  │                                                   │"
echo "  │  Run this command on Kali:                        │"
echo "  │                                                   │"
echo "  │  sudo hping3 -S --flood -p 80 192.168.56.2       │"
echo "  │                                                   │"
echo "  │  Waiting 30 seconds for attack traffic...         │"
echo "  └─────────────────────────────────────────────────┘"
echo ""

# Countdown so you know how long you have
for i in 30 25 20 15 10 5; do
    sleep 5
    echo "  [*] $i seconds remaining..."
done

echo ""
echo "  [*] Time is up. Checking for detected alerts..."
echo ""

# Check alert log file
ALERT_COUNT=$(grep -c "SYN FLOOD" "$ALERT_LOG" 2>/dev/null || echo "0")
if [ "$ALERT_COUNT" -ge 1 ] 2>/dev/null; then
    pass "SYN FLOOD detected and logged ($ALERT_COUNT alert entries in log file)"
else
    fail "No SYN FLOOD alerts found in log file (did Kali attack run?)"
fi

# Check Docker logs
DOCKER_ALERT_COUNT=$(docker compose -f "$COMPOSE_FILE" logs sniffer 2>/dev/null | grep -c "SYN FLOOD" || echo "0")
if [ "$DOCKER_ALERT_COUNT" -ge 1 ] 2>/dev/null; then
    pass "SYN FLOOD appeared in Docker container logs ($DOCKER_ALERT_COUNT entries)"
else
    fail "SYN FLOOD not found in Docker logs"
fi

# Show sample alerts as evidence
echo "" | tee -a "$RESULTS_FILE"
echo "  Sample alerts captured:" | tee -a "$RESULTS_FILE"
grep "SYN FLOOD" "$ALERT_LOG" 2>/dev/null | head -5 | \
    while read line; do echo "    $line" | tee -a "$RESULTS_FILE"; done

# ─────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────────────────────
echo "" | tee -a "$RESULTS_FILE"
echo "================================================" | tee -a "$RESULTS_FILE"
echo " RESULTS: $PASS passed | $FAIL failed"           | tee -a "$RESULTS_FILE"
echo "================================================" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

if [ "$FAIL" -eq 0 ]; then
    echo " ✅ ALL TESTS PASSED — Phase 1 Complete!" | tee -a "$RESULTS_FILE"
else
    echo " ⚠️  $FAIL TEST(S) FAILED — Review above output." | tee -a "$RESULTS_FILE"
fi

echo "" | tee -a "$RESULTS_FILE"
echo " Results saved to: $RESULTS_FILE"
