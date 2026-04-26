"""
Week 8 — Threat Intelligence Module
Enriches attacking IPs with AbuseIPDB + GeoIP data.
Results cached in Redis to avoid repeated API calls.
"""

import requests, json, os, socket
import redis

# ── Config ────────────────────────────────────────────────────
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_KEY", "")
REDIS_HOST     = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT     = int(os.getenv("REDIS_PORT", "6379"))
CACHE_TTL      = 3600   # cache results for 1 hour
# ─────────────────────────────────────────────────────────────

# ── Redis connection ──────────────────────────────────────────
try:
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=0,
        decode_responses=True,
        socket_connect_timeout=2
    )
    redis_client.ping()
    REDIS_AVAILABLE = True
    print("[*] Threat Intel: Redis cache connected")
except Exception as e:
    REDIS_AVAILABLE = False
    print(f"[!] Threat Intel: Redis unavailable ({e}) — caching disabled")


def _get_cache(ip):
    """Retrieve cached threat data for an IP."""
    if not REDIS_AVAILABLE:
        return None
    try:
        data = redis_client.get(f"threat:{ip}")
        return json.loads(data) if data else None
    except:
        return None


def _set_cache(ip, data):
    """Cache threat data for an IP."""
    if not REDIS_AVAILABLE:
        return
    try:
        redis_client.setex(
            f"threat:{ip}",
            CACHE_TTL,
            json.dumps(data)
        )
    except:
        pass


def is_private_ip(ip):
    """Returns True for RFC1918 private/loopback addresses."""
    private_prefixes = (
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168.", "127.", "169.254."
    )
    return any(ip.startswith(p) for p in private_prefixes)


def lookup_abuseipdb(ip):
    """
    Query AbuseIPDB for IP reputation data.
    Returns dict with abuse score and metadata.
    """
    if not ABUSEIPDB_KEY:
        return {
            "abuse_score"   : 0,
            "total_reports" : 0,
            "country"       : "Unknown",
            "isp"           : "Unknown",
            "domain"        : "Unknown",
            "is_whitelisted": False,
            "source"        : "no_api_key"
        }

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers = {
                "Key"    : ABUSEIPDB_KEY,
                "Accept" : "application/json"
            },
            params  = {
                "ipAddress"    : ip,
                "maxAgeInDays" : 90,
                "verbose"      : True
            },
            timeout = 3
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_score"   : data.get("abuseConfidenceScore", 0),
                "total_reports" : data.get("totalReports", 0),
                "country"       : data.get("countryCode", "Unknown"),
                "isp"           : data.get("isp", "Unknown"),
                "domain"        : data.get("domain", "Unknown"),
                "is_whitelisted": data.get("isWhitelisted", False),
                "source"        : "abuseipdb"
            }
        else:
            return {"abuse_score": 0, "source": f"api_error_{response.status_code}"}

    except requests.exceptions.Timeout:
        return {"abuse_score": 0, "source": "timeout"}
    except Exception as e:
        return {"abuse_score": 0, "source": f"error_{str(e)[:30]}"}


def calculate_threat_level(abuse_score, is_private):
    """
    Calculate overall threat level from available signals.
    Returns: CRITICAL / HIGH / MEDIUM / LOW / INFO
    """
    if is_private:
        if abuse_score == 0:
            return "LAB"       # private IP with no abuse = lab environment
        return "MEDIUM"        # private IP but has abuse history = suspicious

    if abuse_score >= 80:
        return "CRITICAL"
    elif abuse_score >= 50:
        return "HIGH"
    elif abuse_score >= 20:
        return "MEDIUM"
    elif abuse_score > 0:
        return "LOW"
    else:
        return "INFO"


def enrich_ip(ip):
    """
    Main function — enrich an IP with all available threat intelligence.
    Returns a dict with full threat context.
    Uses Redis cache to avoid repeated API calls.
    """
    # Check cache first
    cached = _get_cache(ip)
    if cached:
        cached["from_cache"] = True
        return cached

    private = is_private_ip(ip)

    # For private IPs skip external API calls
    if private:
        result = {
            "ip"            : ip,
            "is_private"    : True,
            "abuse_score"   : 0,
            "total_reports" : 0,
            "country"       : "Private",
            "isp"           : "Private Network",
            "domain"        : "local",
            "is_whitelisted": False,
            "threat_level"  : "LAB",
            "source"        : "private_range",
            "from_cache"    : False
        }
    else:
        # Query AbuseIPDB
        abuse_data = lookup_abuseipdb(ip)
        threat_lvl = calculate_threat_level(
            abuse_data.get("abuse_score", 0),
            private
        )

        result = {
            "ip"            : ip,
            "is_private"    : False,
            "threat_level"  : threat_lvl,
            "from_cache"    : False,
            **abuse_data
        }

    # Cache result
    _set_cache(ip, result)
    return result


def format_threat_summary(intel):
    """Format threat intel into a readable single-line summary."""
    level   = intel.get("threat_level",  "?")
    country = intel.get("country",       "?")
    isp     = intel.get("isp",           "?")[:30]
    score   = intel.get("abuse_score",   0)
    reports = intel.get("total_reports", 0)
    cached  = " [cached]" if intel.get("from_cache") else ""

    return (f"Threat:{level} | Country:{country} | "
            f"AbuseScore:{score}/100 | Reports:{reports} | "
            f"ISP:{isp}{cached}")
