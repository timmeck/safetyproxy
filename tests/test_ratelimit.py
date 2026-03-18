"""Tests for rate limiting."""

import pytest

from src.db.database import Database
from src.guard.ratelimit import RateLimiter


@pytest.fixture
async def db(tmp_db_path):
    d = Database(db_path=tmp_db_path)
    await d.initialize()
    return d


@pytest.fixture
def limiter(db):
    return RateLimiter(db)


@pytest.mark.asyncio
async def test_allows_within_limits(limiter):
    """Requests within limits are allowed."""
    policy = {"rate_limit_rpm": 60, "rate_limit_rph": 1000, "rate_limit_rpd": 10000}
    result = await limiter.check_rate_limit(1, policy)
    assert result["allowed"] is True
    assert result["reason"] is None


@pytest.mark.asyncio
async def test_blocks_when_rpm_exceeded(limiter):
    """Blocks when per-minute limit exceeded."""
    policy = {"rate_limit_rpm": 3, "rate_limit_rph": 1000, "rate_limit_rpd": 10000}

    for _ in range(3):
        limiter.record_request(1)

    result = await limiter.check_rate_limit(1, policy)
    assert result["allowed"] is False
    assert "per minute" in result["reason"]


@pytest.mark.asyncio
async def test_blocks_when_rph_exceeded(limiter):
    """Blocks when per-hour limit exceeded."""
    policy = {"rate_limit_rpm": 1000, "rate_limit_rph": 5, "rate_limit_rpd": 10000}

    for _ in range(5):
        limiter.record_request(2)

    result = await limiter.check_rate_limit(2, policy)
    assert result["allowed"] is False
    assert "per hour" in result["reason"]


@pytest.mark.asyncio
async def test_blocks_when_rpd_exceeded(limiter):
    """Blocks when per-day limit exceeded."""
    policy = {"rate_limit_rpm": 1000, "rate_limit_rph": 1000, "rate_limit_rpd": 3}

    for _ in range(3):
        limiter.record_request(3)

    result = await limiter.check_rate_limit(3, policy)
    assert result["allowed"] is False
    assert "per day" in result["reason"]


@pytest.mark.asyncio
async def test_separate_app_counters(limiter):
    """Different apps have separate counters."""
    policy = {"rate_limit_rpm": 2, "rate_limit_rph": 1000, "rate_limit_rpd": 10000}

    limiter.record_request(10)
    limiter.record_request(10)

    # App 10 should be blocked
    result = await limiter.check_rate_limit(10, policy)
    assert result["allowed"] is False

    # App 20 should still be allowed
    result = await limiter.check_rate_limit(20, policy)
    assert result["allowed"] is True


@pytest.mark.asyncio
async def test_reset_counters(limiter):
    """Can reset counters."""
    policy = {"rate_limit_rpm": 2, "rate_limit_rph": 1000, "rate_limit_rpd": 10000}

    limiter.record_request(1)
    limiter.record_request(1)
    result = await limiter.check_rate_limit(1, policy)
    assert result["allowed"] is False

    limiter.reset(1)
    result = await limiter.check_rate_limit(1, policy)
    assert result["allowed"] is True


@pytest.mark.asyncio
async def test_limits_info_returned(limiter):
    """Rate limit response includes current counts."""
    policy = {"rate_limit_rpm": 60, "rate_limit_rph": 1000, "rate_limit_rpd": 10000}
    limiter.record_request(1)
    result = await limiter.check_rate_limit(1, policy)
    assert result["limits"]["rpm"]["count"] == 1
    assert result["limits"]["rpm"]["limit"] == 60
