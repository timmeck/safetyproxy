"""Tests for database layer."""

import pytest

from src.db.database import Database


@pytest.fixture
async def db(tmp_db_path):
    d = Database(db_path=tmp_db_path)
    await d.initialize()
    return d


@pytest.mark.asyncio
async def test_initialize_creates_tables(db):
    """Database init creates tables and default policy."""
    policies = await db.get_policies()
    assert len(policies) >= 1
    assert policies[0]["name"] == "default"


@pytest.mark.asyncio
async def test_create_and_get_policy(db):
    """Can create and retrieve a policy."""
    pid = await db.create_policy("strict", injection_threshold=40, pii_mode="block")
    assert pid is not None
    policy = await db.get_policy(pid)
    assert policy["name"] == "strict"
    assert policy["injection_threshold"] == 40
    assert policy["pii_mode"] == "block"


@pytest.mark.asyncio
async def test_get_policy_by_name(db):
    """Can retrieve policy by name."""
    policy = await db.get_policy_by_name("default")
    assert policy is not None
    assert policy["name"] == "default"


@pytest.mark.asyncio
async def test_register_and_get_app(db):
    """Can register an app and retrieve it."""
    app = await db.register_app("test-app")
    assert app["name"] == "test-app"
    assert app["api_key"].startswith("sp_")

    fetched = await db.get_app_by_key(app["api_key"])
    assert fetched is not None
    assert fetched["name"] == "test-app"


@pytest.mark.asyncio
async def test_list_apps(db):
    """Can list all apps."""
    await db.register_app("app1")
    await db.register_app("app2")
    apps = await db.get_apps()
    assert len(apps) >= 2


@pytest.mark.asyncio
async def test_delete_app(db):
    """Can delete an app."""
    app = await db.register_app("to-delete")
    await db.delete_app(app["id"])
    fetched = await db.get_app(app["id"])
    assert fetched is None


@pytest.mark.asyncio
async def test_log_request(db):
    """Can log a request."""
    app = await db.register_app("req-app")
    req_id = await db.log_request(app["id"], "gpt-4", "openai", status="allowed", injection_score=15)
    assert req_id > 0
    reqs = await db.get_requests(limit=10, app_id=app["id"])
    assert len(reqs) == 1
    assert reqs[0]["injection_score"] == 15


@pytest.mark.asyncio
async def test_log_violation(db):
    """Can log a violation."""
    app = await db.register_app("viol-app")
    vid = await db.log_violation(None, app["id"], "injection", "high", "test injection detected")
    assert vid > 0
    viols = await db.get_violations(limit=10, app_id=app["id"])
    assert len(viols) == 1
    assert viols[0]["violation_type"] == "injection"


@pytest.mark.asyncio
async def test_activity_log(db):
    """Can log and retrieve activity."""
    await db.log_activity("test_event", "Something happened", data={"key": "value"})
    activity = await db.get_activity(limit=10)
    assert len(activity) >= 1
    assert activity[0]["event_type"] == "test_event"


@pytest.mark.asyncio
async def test_stats(db):
    """Stats return expected keys."""
    stats = await db.get_stats()
    assert "requests_today" in stats
    assert "blocked_today" in stats
    assert "active_apps" in stats


@pytest.mark.asyncio
async def test_request_count_since(db):
    """Can count requests since a timestamp."""
    app = await db.register_app("count-app")
    await db.log_request(app["id"], "gpt-4", "openai")
    await db.log_request(app["id"], "gpt-4", "openai")
    count = await db.get_request_count_since(app["id"], "2000-01-01T00:00:00")
    assert count == 2
