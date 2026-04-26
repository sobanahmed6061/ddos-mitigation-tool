"""
Week 11 — Token Bucket Rate Limiter

ARCHITECTURE NOTE:
─────────────────────────────────────────────────────────────
This token bucket is used for METRICS ONLY — not enforcement.

Actual packet dropping is done by iptables in kernel space
which processes millions of packets/sec without Python overhead.

This module simulates what iptables is doing to give us:
  - Visual bucket fill level in the terminal
  - Drop rate estimation
  - Rate limit effectiveness metrics

Real enforcement chain:
  Attack traffic → iptables hashlimit rule (kernel) → DROP
  Python role    → detect → score → write iptables rule → done
─────────────────────────────────────────────────────────────
"""

import time
import threading
from collections import defaultdict


class TokenBucket:
    """
    Single token bucket for one IP address.
    Thread-safe implementation.
    """

    def __init__(self, rate, capacity, burst_multiplier=3):
        """
        rate             : tokens added per second (normal pps limit)
        capacity         : max tokens in bucket (burst allowance)
        burst_multiplier : how many times rate to allow as burst
        """
        self.rate      = rate
        self.capacity  = capacity or (rate * burst_multiplier)
        self.tokens    = self.capacity   # start full
        self.last_time = time.time()
        self.lock      = threading.Lock()

        # Stats
        self.total_allowed  = 0
        self.total_dropped  = 0
        self.created_at     = time.time()

    def consume(self, tokens=1):
        """
        Try to consume tokens from bucket.
        Returns True if allowed, False if rate limited.
        """
        with self.lock:
            now = time.time()

            # Refill tokens based on time elapsed
            elapsed       = now - self.last_time
            self.tokens   = min(
                self.capacity,
                self.tokens + (elapsed * self.rate)
            )
            self.last_time = now

            if self.tokens >= tokens:
                self.tokens      -= tokens
                self.total_allowed += 1
                return True
            else:
                self.total_dropped += 1
                return False

    @property
    def fill_level(self):
        """Returns bucket fill percentage 0-100."""
        return round((self.tokens / self.capacity) * 100, 1)

    @property
    def drop_rate(self):
        """Returns percentage of packets being dropped."""
        total = self.total_allowed + self.total_dropped
        if total == 0:
            return 0.0
        return round((self.total_dropped / total) * 100, 1)

    def stats(self):
        return {
            "rate"         : self.rate,
            "capacity"     : self.capacity,
            "tokens_left"  : round(self.tokens, 2),
            "fill_level"   : self.fill_level,
            "total_allowed": self.total_allowed,
            "total_dropped": self.total_dropped,
            "drop_rate"    : self.drop_rate,
            "age_seconds"  : round(time.time() - self.created_at, 1)
        }


class TokenBucketManager:
    """
    Manages token buckets for multiple IPs.
    Automatically creates and cleans up buckets.
    """

    # Rate limits per mitigation level
    LEVEL_RATES = {
        1: {"rate": 1000, "capacity": 5000},  # L1 MONITOR  — no real limit
        2: {"rate": 50,   "capacity": 200},   # L2 THROTTLE — 50pps, burst 200
        3: {"rate": 10,   "capacity": 50},    # L3 RESTRICT — 10pps, burst 50
        4: {"rate": 1,    "capacity": 5},     # L4 BLOCK    — near zero
        5: {"rate": 0,    "capacity": 0},     # L5 NULLROUTE — complete block
    }

    def __init__(self):
        self.buckets      = {}
        self.lock         = threading.Lock()
        self.ip_levels    = {}

    def get_or_create(self, ip, level=2):
        """Get existing bucket or create new one for IP."""
        with self.lock:
            if ip not in self.buckets or self.ip_levels.get(ip) != level:
                config = self.LEVEL_RATES.get(level, self.LEVEL_RATES[2])
                self.buckets[ip]   = TokenBucket(
                    rate     = config["rate"],
                    capacity = config["capacity"]
                )
                self.ip_levels[ip] = level
            return self.buckets[ip]

    def is_allowed(self, ip, level=2):
        """
        Check if packet from IP is allowed under current rate limit.
        Returns (allowed, bucket_stats).
        """
        if level == 5:
            return False, {"drop_rate": 100}

        if level == 1:
            return True, {"drop_rate": 0}

        bucket = self.get_or_create(ip, level)
        allowed = bucket.consume()
        return allowed, bucket.stats()

    def get_stats(self, ip):
        """Get stats for a specific IP."""
        if ip in self.buckets:
            return self.buckets[ip].stats()
        return None

    def remove(self, ip):
        """Remove bucket when IP is released."""
        with self.lock:
            self.buckets.pop(ip, None)
            self.ip_levels.pop(ip, None)

    def get_all_stats(self):
        """Get stats for all active buckets."""
        with self.lock:
            return {
                ip: bucket.stats()
                for ip, bucket in self.buckets.items()
            }

    def cleanup_idle(self, max_age_seconds=300):
        """Remove buckets idle for more than max_age_seconds."""
        with self.lock:
            now     = time.time()
            to_remove = [
                ip for ip, bucket in self.buckets.items()
                if (now - bucket.created_at) > max_age_seconds
                and bucket.total_allowed == 0
            ]
            for ip in to_remove:
                del self.buckets[ip]
                self.ip_levels.pop(ip, None)
            return len(to_remove)


# ── Global bucket manager instance ────────────────────────────
bucket_manager = TokenBucketManager()


def format_bucket_display(ip, stats):
    """Format token bucket stats for display."""
    if not stats:
        return ""

    bar_filled = int(stats["fill_level"] / 5)
    bar_empty  = 20 - bar_filled
    bar        = "█" * bar_filled + "░" * bar_empty

    return (
        f"          🪣 BUCKET [{bar}] {stats['fill_level']}% full | "
        f"rate={stats['rate']}pps | "
        f"dropped={stats['total_dropped']} | "
        f"drop_rate={stats['drop_rate']}%"
    )
