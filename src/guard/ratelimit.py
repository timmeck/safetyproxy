"""Rate limiting for SafetyProxy."""
from datetime import datetime, timedelta, timezone

from src.db.database import Database
from src.utils.logger import get_logger

log = get_logger("ratelimit")


class RateLimiter:
    """Token bucket / sliding window rate limiter backed by request log in DB."""

    def __init__(self, db: Database):
        self.db = db
        # In-memory counters for fast path (reset on restart)
        self._counters: dict[int, dict[str, list[datetime]]] = {}

    async def check_rate_limit(self, app_id: int, policy: dict) -> dict:
        """Check if the app has exceeded its rate limits.

        Returns:
            dict with keys:
                allowed (bool): Whether the request is within limits
                reason (str | None): Reason if blocked
                limits (dict): Current limit status
        """
        rpm_limit = policy.get("rate_limit_rpm", 60)
        rph_limit = policy.get("rate_limit_rph", 1000)
        rpd_limit = policy.get("rate_limit_rpd", 10000)

        now = datetime.now(timezone.utc)

        # Initialize counters for this app if needed
        if app_id not in self._counters:
            self._counters[app_id] = {"timestamps": []}

        timestamps = self._counters[app_id]["timestamps"]

        # Clean old entries (older than 24h)
        cutoff_day = now - timedelta(days=1)
        self._counters[app_id]["timestamps"] = [
            ts for ts in timestamps if ts > cutoff_day
        ]
        timestamps = self._counters[app_id]["timestamps"]

        # Count requests in windows
        minute_ago = now - timedelta(minutes=1)
        hour_ago = now - timedelta(hours=1)

        rpm_count = sum(1 for ts in timestamps if ts > minute_ago)
        rph_count = sum(1 for ts in timestamps if ts > hour_ago)
        rpd_count = len(timestamps)

        limits = {
            "rpm": {"count": rpm_count, "limit": rpm_limit},
            "rph": {"count": rph_count, "limit": rph_limit},
            "rpd": {"count": rpd_count, "limit": rpd_limit},
        }

        # Check limits
        if rpm_count >= rpm_limit:
            return {
                "allowed": False,
                "reason": f"Rate limit exceeded: {rpm_count}/{rpm_limit} requests per minute",
                "limits": limits,
            }

        if rph_count >= rph_limit:
            return {
                "allowed": False,
                "reason": f"Rate limit exceeded: {rph_count}/{rph_limit} requests per hour",
                "limits": limits,
            }

        if rpd_count >= rpd_limit:
            return {
                "allowed": False,
                "reason": f"Rate limit exceeded: {rpd_count}/{rpd_limit} requests per day",
                "limits": limits,
            }

        return {"allowed": True, "reason": None, "limits": limits}

    def record_request(self, app_id: int):
        """Record a request timestamp for rate limiting."""
        now = datetime.now(timezone.utc)
        if app_id not in self._counters:
            self._counters[app_id] = {"timestamps": []}
        self._counters[app_id]["timestamps"].append(now)

    def reset(self, app_id: int | None = None):
        """Reset rate limit counters."""
        if app_id:
            self._counters.pop(app_id, None)
        else:
            self._counters.clear()
