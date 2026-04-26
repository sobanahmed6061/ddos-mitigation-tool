"""
Phase 4 Week 12 — Advanced Whitelist Management
Three-tier whitelist system:
  Tier 1: Static permanent   — CDN ranges, cloud providers
  Tier 2: Dynamic learned    — IPs with clean history
  Tier 3: Temporary admin    — manual overrides with expiry
"""

import json
import os
import time
import ipaddress
from collections import defaultdict

# ── Paths ─────────────────────────────────────────────────────
WHITELIST_FILE = "/app/logs/whitelist.json"
HISTORY_FILE   = "/app/logs/ip_history.json"

# ── Tier 1 — Static permanent whitelist ───────────────────────
# These IPs and ranges are NEVER blocked under any circumstance
TIER1_STATIC = {
    # Local network — Ubuntu only, NOT Kali
    "127.0.0.1",
    "192.168.56.2",   # Ubuntu victim machine only
    "10.0.0.1",
    "10.0.2.2",

    # Cloudflare IP ranges
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",

    # Google
    "8.8.8.8",
    "8.8.4.4",
    "35.190.0.0/17",

    # AWS CloudFront
    "13.32.0.0/15",
    "13.35.0.0/16",

    # Local VirtualBox ranges
    # Local VirtualBox ranges
    # NOTE: Only whitelist Ubuntu itself, NOT the entire subnet
    # This allows testing attacks from 192.168.56.1 (Kali)
    # "192.168.56.0/24",   ← removed for lab testing
}

# ── IP History Tracking ───────────────────────────────────────
ip_history = defaultdict(lambda: {
    "first_seen"     : None,
    "last_seen"      : None,
    "request_count"  : 0,
    "alert_count"    : 0,
    "clean_days"     : 0,
    "whitelisted_at" : None,
    "tier"           : None,
})


def load_whitelist():
    """Load dynamic whitelist entries from file."""
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE) as f:
                return json.load(f)
        except:
            return {"tier2": {}, "tier3": {}}
    return {"tier2": {}, "tier3": {}}


def save_whitelist(data):
    """Save whitelist to file."""
    with open(WHITELIST_FILE, "w") as f:
        json.dump(data, f, indent=4)


def is_in_tier1(ip):
    """
    Check if IP matches any Tier 1 static entry.
    Handles both exact IPs and CIDR ranges.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        for entry in TIER1_STATIC:
            try:
                if "/" in entry:
                    if ip_obj in ipaddress.ip_network(entry, strict=False):
                        return True
                else:
                    if ip == entry:
                        return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False


def is_in_tier2(ip):
    """Check if IP is in dynamic learned whitelist."""
    wl = load_whitelist()
    return ip in wl.get("tier2", {})


def is_in_tier3(ip):
    """
    Check if IP is in temporary admin whitelist.
    Automatically removes expired entries.
    """
    wl      = load_whitelist()
    tier3   = wl.get("tier3", {})

    if ip not in tier3:
        return False

    entry   = tier3[ip]
    expires = entry.get("expires_at", 0)

    # Check if expired
    if expires and time.time() > expires:
        del tier3[ip]
        wl["tier3"] = tier3
        save_whitelist(wl)
        print(f"[*] Whitelist: Tier 3 entry expired for {ip}")
        return False

    return True


def is_whitelisted(ip):
    """
    Main check — returns (whitelisted, tier, reason).
    Checks all three tiers in order.
    """
    if is_in_tier1(ip):
        return True, 1, "static_permanent"

    if is_in_tier2(ip):
        wl     = load_whitelist()
        reason = wl["tier2"].get(ip, {}).get("reason", "learned")
        return True, 2, reason

    if is_in_tier3(ip):
        wl     = load_whitelist()
        reason = wl["tier3"].get(ip, {}).get("reason", "admin_override")
        return True, 3, reason

    return False, 0, ""


def add_tier2(ip, reason="clean_history_30d"):
    """Add IP to Tier 2 dynamic learned whitelist."""
    wl = load_whitelist()
    wl.setdefault("tier2", {})[ip] = {
        "added_at"   : time.strftime("%Y-%m-%d %H:%M:%S"),
        "reason"     : reason,
        "permanent"  : True,
    }
    save_whitelist(wl)
    print(f"[*] Whitelist: {ip} added to Tier 2 ({reason})")


def add_tier3(ip, duration_hours=24, reason="admin_override"):
    """
    Add IP to Tier 3 temporary whitelist.
    Automatically expires after duration_hours.
    """
    wl          = load_whitelist()
    expires_at  = time.time() + (duration_hours * 3600)

    wl.setdefault("tier3", {})[ip] = {
        "added_at"   : time.strftime("%Y-%m-%d %H:%M:%S"),
        "expires_at" : expires_at,
        "expires_str": time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(expires_at)
        ),
        "duration_h" : duration_hours,
        "reason"     : reason,
    }
    save_whitelist(wl)
    print(
        f"[*] Whitelist: {ip} added to Tier 3 | "
        f"expires in {duration_hours}h | reason={reason}"
    )


def remove_from_whitelist(ip):
    """Remove IP from Tier 2 or Tier 3 whitelist."""
    wl      = load_whitelist()
    removed = False

    if ip in wl.get("tier2", {}):
        del wl["tier2"][ip]
        removed = True
        print(f"[*] Whitelist: {ip} removed from Tier 2")

    if ip in wl.get("tier3", {}):
        del wl["tier3"][ip]
        removed = True
        print(f"[*] Whitelist: {ip} removed from Tier 3")

    if removed:
        save_whitelist(wl)
    else:
        print(f"[*] Whitelist: {ip} not found in Tier 2 or Tier 3")

    return removed


def update_ip_history(ip, was_alert=False):
    """
    Track IP behavior over time.
    IPs with 30+ clean days get auto-promoted to Tier 2.
    """
    now     = time.time()
    history = ip_history[ip]

    if history["first_seen"] is None:
        history["first_seen"] = now
    history["last_seen"]    = now
    history["request_count"] += 1

    if was_alert:
        history["alert_count"] += 1
        history["clean_days"]   = 0   # reset clean streak
    else:
        # Track clean days
        if history["first_seen"]:
            days_known = (now - history["first_seen"]) / 86400
            if history["alert_count"] == 0:
                history["clean_days"] = days_known

                # Auto-promote to Tier 2 after 30 clean days
                if days_known >= 30 and not is_in_tier2(ip):
                    add_tier2(ip, reason=f"auto_promoted_{days_known:.0f}d_clean")


def get_whitelist_summary():
    """Return summary of all whitelist entries."""
    wl    = load_whitelist()
    tier2 = wl.get("tier2", {})
    tier3 = wl.get("tier3", {})

    # Clean expired tier3 entries
    now           = time.time()
    tier3_active  = {
        ip: data for ip, data in tier3.items()
        if not data.get("expires_at") or data["expires_at"] > now
    }

    return {
        "tier1_ranges" : len(TIER1_STATIC),
        "tier2_entries": len(tier2),
        "tier3_active" : len(tier3_active),
        "tier3_expired": len(tier3) - len(tier3_active),
        "tier2_ips"    : list(tier2.keys()),
        "tier3_ips"    : list(tier3_active.keys()),
    }


def format_whitelist_display(ip, tier, reason):
    """Format whitelist status for terminal display."""
    tier_names = {
        1: "STATIC PERMANENT",
        2: "DYNAMIC LEARNED",
        3: "TEMP ADMIN OVERRIDE"
    }
    return (
        f"          🛡️  WHITELISTED [Tier {tier} — "
        f"{tier_names.get(tier, 'UNKNOWN')}] | "
        f"reason={reason} | action=skipped"
    )
