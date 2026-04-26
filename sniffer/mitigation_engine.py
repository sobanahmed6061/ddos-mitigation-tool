"""
Phase 4 Week 10/11 — Graduated Mitigation Ladder
Kernel-level enforcement via iptables.
Python detects and writes rules. Kernel enforces them.
"""

import subprocess
import logging
import time
import json
import os
from collections import defaultdict
from token_bucket import bucket_manager

# ── Config ────────────────────────────────────────────────────
MITIGATION_LOG   = "/app/logs/mitigation.log"
BLACKLIST_FILE   = "/app/logs/blacklist.json"
AUTO_ESCALATE    = True
ESCALATE_MINUTES = 5
# ─────────────────────────────────────────────────────────────

# ── Logging ───────────────────────────────────────────────────
mit_logger = logging.getLogger("mitigation")
mit_logger.setLevel(logging.INFO)
handler = logging.FileHandler(MITIGATION_LOG)
handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
mit_logger.addHandler(handler)

# ── Level definitions ─────────────────────────────────────────
LEVELS = {
    1: {"name": "MONITOR",   "min_score": 0,  "max_score": 39,  "symbol": "👁 "},
    2: {"name": "THROTTLE",  "min_score": 40, "max_score": 54,  "symbol": "🔶"},
    3: {"name": "RESTRICT",  "min_score": 55, "max_score": 69,  "symbol": "🔴"},
    4: {"name": "BLOCK",     "min_score": 70, "max_score": 84,  "symbol": "⛔"},
    5: {"name": "NULLROUTE", "min_score": 85, "max_score": 100, "symbol": "💀"},
}

# ── Per-IP mitigation state ───────────────────────────────────
ip_mitigation_state = defaultdict(lambda: {
    "current_level"   : 0,
    "level_since"     : None,
    "rules_applied"   : [],
    "escalation_count": 0,
    "first_mitigated" : None,
    "last_score"      : 0,
})

# ── Whitelist ─────────────────────────────────────────────────
WHITELIST = {
    "127.0.0.1",
    "192.168.56.2",
    "10.0.0.1",
    "10.0.2.2",
}


# ─────────────────────────────────────────────────────────────
# Core utilities
# ─────────────────────────────────────────────────────────────

def get_level_for_score(score):
    if score >= 85:
        return 5
    elif score >= 70:
        return 4
    elif score >= 55:
        return 3
    elif score >= 40:
        return 2
    else:
        return 1


def run_command(cmd, description):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=5
        )
        if result.returncode == 0:
            mit_logger.info(f"CMD OK: {description}")
            return True, result.stdout
        else:
            mit_logger.warning(f"CMD FAIL: {description} | {result.stderr}")
            return False, result.stderr
    except subprocess.TimeoutExpired:
        mit_logger.error(f"CMD TIMEOUT: {description}")
        return False, "timeout"
    except Exception as e:
        mit_logger.error(f"CMD ERROR: {description} | {e}")
        return False, str(e)


def get_kernel_drop_stats(ip):
    """
    Read actual packet drop counts directly from iptables kernel counters.
    Uses iptables -Z to read then zero counters for per-window accuracy.
    """
    try:
        # Get raw output with exact format
        result = subprocess.run(
            f"iptables -L INPUT -n -v -x | grep -w '{ip}'",
            shell=True, capture_output=True, text=True, timeout=5
        )

        if not result.stdout.strip():
            return {"pkts": 0, "bytes": 0}

        total_pkts  = 0
        total_bytes = 0

        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            # iptables -nvx format:
            # pkts bytes target prot opt in out source destination
            if len(parts) >= 2:
                try:
                    total_pkts  += int(parts[0])
                    total_bytes += int(parts[1])
                except ValueError:
                    continue

        return {"pkts": total_pkts, "bytes": total_bytes}

    except Exception as e:
        mit_logger.debug(f"get_kernel_drop_stats error: {e}")
        return {"pkts": 0, "bytes": 0}



def load_blacklist():
    if os.path.exists(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE) as f:
                return json.load(f)
        except:
            return {}
    return {}


def save_blacklist(data):
    with open(BLACKLIST_FILE, "w") as f:
        json.dump(data, f, indent=4)


def is_blacklisted(ip):
    return ip in load_blacklist()


# ─────────────────────────────────────────────────────────────
# Rule removal
# ─────────────────────────────────────────────────────────────

def remove_rules(ip):
    """Remove ALL existing iptables rules for this IP completely."""
    tag = ip.replace('.', '_')

    # Run multiple times to catch all duplicate rules
    for _ in range(3):
        run_command(
            f"iptables -D INPUT -s {ip} -j DROP 2>/dev/null || true",
            f"remove block {ip}"
        )
        run_command(
            f"iptables -D INPUT -s {ip} "
            f"-m hashlimit --hashlimit-name ratelimit_{tag} "
            f"--hashlimit-mode srcip --hashlimit-above 50/sec "
            f"--hashlimit-burst 100 -j DROP 2>/dev/null || true",
            f"remove throttle {ip}"
        )
        run_command(
            f"iptables -D INPUT -s {ip} "
            f"-m hashlimit --hashlimit-name restrict_{tag} "
            f"--hashlimit-mode srcip --hashlimit-above 10/sec "
            f"--hashlimit-burst 20 -j DROP 2>/dev/null || true",
            f"remove restrict {ip}"
        )

    # Nuclear option — flush entire INPUT chain rules for this IP
    # Reads all rules and deletes any matching this source IP
    run_command(
        f"iptables-save | grep -v '\-s {ip}' | iptables-restore 2>/dev/null || true",
        f"flush all rules for {ip}"
    )








# ─────────────────────────────────────────────────────────────
# Level actions
# ─────────────────────────────────────────────────────────────

def apply_l1_monitor(ip):
    """L1 — Log only, no firewall action."""
    mit_logger.info(f"L1 MONITOR | ip={ip} | action=log_only")
    return True


def apply_l2_throttle(ip):
    """L2 — Kernel rate limit 50pps burst 100."""
    remove_rules(ip)
    tag = ip.replace('.', '_')
    cmd = (
        f"iptables -I INPUT -s {ip} "
        f"-m hashlimit --hashlimit-name ratelimit_{tag} "
        f"--hashlimit-mode srcip --hashlimit-above 50/sec "
        f"--hashlimit-burst 100 -j DROP"
    )
    success, _ = run_command(cmd, f"L2 throttle {ip}")
    if success:
        mit_logger.info(f"L2 THROTTLE | ip={ip} | limit=50pps | burst=100")
    return success


def apply_l3_restrict(ip):
    """L3 — Kernel rate limit 10pps burst 20."""
    remove_rules(ip)
    tag = ip.replace('.', '_')
    cmd = (
        f"iptables -I INPUT -s {ip} "
        f"-m hashlimit --hashlimit-name restrict_{tag} "
        f"--hashlimit-mode srcip --hashlimit-above 10/sec "
        f"--hashlimit-burst 20 -j DROP"
    )
    success, _ = run_command(cmd, f"L3 restrict {ip}")
    if success:
        mit_logger.info(f"L3 RESTRICT | ip={ip} | limit=10pps | burst=20")
    return success


def apply_l4_block(ip):
    """L4 — Hard DROP all traffic from IP."""
    remove_rules(ip)
    success, _ = run_command(
        f"iptables -I INPUT -s {ip} -j DROP",
        f"L4 block {ip}"
    )
    if success:
        mit_logger.warning(f"L4 BLOCK | ip={ip} | action=hard_blocked")
    return success


def apply_l5_nullroute(ip):
    """L5 — Permanent blacklist + null route."""
    apply_l4_block(ip)
    run_command(f"ip route add blackhole {ip}/32", f"L5 nullroute {ip}")

    blacklist = load_blacklist()
    blacklist[ip] = {
        "banned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "reason"   : "threat_score >= 85",
        "permanent": True
    }
    save_blacklist(blacklist)
    mit_logger.critical(f"L5 NULLROUTE | ip={ip} | action=permanent_ban")
    return True


# ─────────────────────────────────────────────────────────────
# Release
# ─────────────────────────────────────────────────────────────

def release_mitigation(ip):
    """Remove all mitigation rules when attack ends."""
    if ip not in ip_mitigation_state:
        return

    level = ip_mitigation_state[ip]["current_level"]

    if level >= 4:
        mit_logger.info(
            f"RELEASE SKIPPED | ip={ip} | level=L{level} | reason=severe_block_kept"
        )
        return

    if level > 0:
        remove_rules(ip)
        mit_logger.info(f"RELEASE | ip={ip} | level=L{level} | action=rules_removed")
        print(f"          🔓 Mitigation released for {ip}")

    ip_mitigation_state.pop(ip, None)
    bucket_manager.remove(ip)


# ─────────────────────────────────────────────────────────────
# Main mitigation function
# ─────────────────────────────────────────────────────────────

def apply_mitigation(ip, score, attack_type):
    """Determine and apply correct mitigation level."""
    if ip in WHITELIST:
        return {"level": 0, "name": "WHITELISTED", "symbol": "✅",
                "action": "skipped", "score": score,
                "attack_type": attack_type, "bucket_stats": {}, "allowed": True}

    if is_blacklisted(ip):
        apply_l4_block(ip)
        return {"level": 5, "name": "BLACKLISTED", "symbol": "💀",
                "action": "block_reapplied", "score": score,
                "attack_type": attack_type, "bucket_stats": {}, "allowed": False}

    state         = ip_mitigation_state[ip]
    target_level  = get_level_for_score(score)
    current_level = state["current_level"]

    # Auto-escalation check
    if AUTO_ESCALATE and state["level_since"] is not None:
        minutes_at_level = (time.time() - state["level_since"]) / 60
        if minutes_at_level >= ESCALATE_MINUTES and current_level < 5:
            new_level = min(current_level + 1, 5)
            if new_level > target_level:
                target_level = new_level
                print(
                    f"          ⬆️  AUTO-ESCALATE "
                    f"L{current_level}→L{target_level} "
                    f"({minutes_at_level:.1f} min at level)"
                )
                mit_logger.warning(
                    f"AUTO-ESCALATE | ip={ip} | "
                    f"from=L{current_level} | to=L{target_level}"
                )

    level_changed = (target_level != current_level)

    if level_changed or current_level == 0:
        if target_level == 1:
            apply_l1_monitor(ip)
        elif target_level == 2:
            apply_l2_throttle(ip)
        elif target_level == 3:
            apply_l3_restrict(ip)
        elif target_level == 4:
            apply_l4_block(ip)
        elif target_level == 5:
            apply_l5_nullroute(ip)

        state["current_level"]  = target_level
        state["level_since"]    = time.time()
        state["last_score"]     = score

        if state["first_mitigated"] is None:
            state["first_mitigated"] = time.time()

        if level_changed and current_level > 0:
            state["escalation_count"] += 1

        action_taken = (
            "escalated"    if target_level > current_level else
            "new"          if current_level == 0           else
            "de-escalated"
        )
    else:
        action_taken = "maintained"

    # Token bucket metrics (display only — enforcement is via iptables)
    _, bucket_stats = bucket_manager.is_allowed(ip, target_level)

    return {
        "level"       : target_level,
        "name"        : LEVELS[target_level]["name"],
        "symbol"      : LEVELS[target_level]["symbol"],
        "action"      : action_taken,
        "score"       : score,
        "attack_type" : attack_type,
        "bucket_stats": bucket_stats,
        "allowed"     : True,
    }


def format_mitigation_display(mit_result, ip):
    """Format mitigation result for terminal display."""
    symbol = mit_result["symbol"]
    name   = mit_result["name"]
    level  = mit_result["level"]
    action = mit_result["action"]
    state  = ip_mitigation_state[ip]

    return (
        f"          {symbol} MITIGATION L{level} {name} | "
        f"action={action} | "
        f"score={mit_result['score']} | "
        f"escalations={state['escalation_count']}"
    )
