"""SQLite database layer for SafetyProxy."""

import json
import secrets
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite

from src.config import DB_PATH
from src.utils.logger import get_logger

log = get_logger("db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    api_key TEXT NOT NULL,
    policy_id INTEGER,
    status TEXT DEFAULT 'active',
    created_at TEXT NOT NULL,
    FOREIGN KEY (policy_id) REFERENCES policies(id)
);

CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    injection_threshold INTEGER DEFAULT 70,
    pii_mode TEXT DEFAULT 'redact',
    content_categories TEXT DEFAULT '["violence","hate_speech","sexual","illegal","self_harm"]',
    content_action TEXT DEFAULT 'block',
    rate_limit_rpm INTEGER DEFAULT 60,
    rate_limit_rph INTEGER DEFAULT 1000,
    rate_limit_rpd INTEGER DEFAULT 10000,
    max_tokens_per_request INTEGER DEFAULT 4000,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id INTEGER NOT NULL,
    model TEXT NOT NULL,
    provider TEXT NOT NULL,
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    status TEXT DEFAULT 'allowed',
    blocked_reason TEXT,
    injection_score INTEGER DEFAULT 0,
    pii_detected TEXT,
    pii_redacted INTEGER DEFAULT 0,
    content_flags TEXT,
    latency_ms INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER,
    app_id INTEGER NOT NULL,
    violation_type TEXT NOT NULL,
    severity TEXT DEFAULT 'medium',
    details TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (request_id) REFERENCES requests(id),
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id INTEGER,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    data TEXT,
    created_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat()


class Database:
    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or DB_PATH

    async def initialize(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(SCHEMA)
            await db.commit()
            # Seed default policy if none exists
            cur = await db.execute("SELECT COUNT(*) FROM policies")
            count = (await cur.fetchone())[0]
            if count == 0:
                await db.execute(
                    "INSERT INTO policies (name, injection_threshold, pii_mode, content_categories, content_action, rate_limit_rpm, rate_limit_rph, rate_limit_rpd, max_tokens_per_request, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "default",
                        70,
                        "redact",
                        '["violence","hate_speech","sexual","illegal","self_harm"]',
                        "block",
                        60,
                        1000,
                        10000,
                        4000,
                        _now(),
                    ),
                )
                await db.commit()
        log.info(f"Database initialized at {self.db_path}")

    # ── Policies ──────────────────────────────────────────────────────

    async def get_policies(self) -> list[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM policies ORDER BY id")
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def get_policy(self, policy_id: int) -> dict | None:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM policies WHERE id = ?", (policy_id,))
            row = await cur.fetchone()
            return dict(row) if row else None

    async def get_policy_by_name(self, name: str) -> dict | None:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM policies WHERE name = ?", (name,))
            row = await cur.fetchone()
            return dict(row) if row else None

    async def create_policy(self, name: str, **kwargs) -> int:
        fields = {
            "injection_threshold": kwargs.get("injection_threshold", 70),
            "pii_mode": kwargs.get("pii_mode", "redact"),
            "content_categories": kwargs.get(
                "content_categories", '["violence","hate_speech","sexual","illegal","self_harm"]'
            ),
            "content_action": kwargs.get("content_action", "block"),
            "rate_limit_rpm": kwargs.get("rate_limit_rpm", 60),
            "rate_limit_rph": kwargs.get("rate_limit_rph", 1000),
            "rate_limit_rpd": kwargs.get("rate_limit_rpd", 10000),
            "max_tokens_per_request": kwargs.get("max_tokens_per_request", 4000),
        }
        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                "INSERT INTO policies (name, injection_threshold, pii_mode, content_categories, content_action, rate_limit_rpm, rate_limit_rph, rate_limit_rpd, max_tokens_per_request, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    name,
                    fields["injection_threshold"],
                    fields["pii_mode"],
                    fields["content_categories"],
                    fields["content_action"],
                    fields["rate_limit_rpm"],
                    fields["rate_limit_rph"],
                    fields["rate_limit_rpd"],
                    fields["max_tokens_per_request"],
                    _now(),
                ),
            )
            await db.commit()
            return cur.lastrowid

    # ── Apps ──────────────────────────────────────────────────────────

    async def get_apps(self) -> list[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT a.*, p.name as policy_name FROM apps a LEFT JOIN policies p ON a.policy_id = p.id ORDER BY a.id"
            )
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def get_app_by_key(self, api_key: str) -> dict | None:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM apps WHERE api_key = ? AND status = 'active'", (api_key,))
            row = await cur.fetchone()
            return dict(row) if row else None

    async def get_app(self, app_id: int) -> dict | None:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
            row = await cur.fetchone()
            return dict(row) if row else None

    async def register_app(self, name: str, policy_id: int | None = None) -> dict:
        api_key = f"sp_{secrets.token_hex(24)}"
        if policy_id is None:
            default = await self.get_policy_by_name("default")
            policy_id = default["id"] if default else None
        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                "INSERT INTO apps (name, api_key, policy_id, status, created_at) VALUES (?, ?, ?, 'active', ?)",
                (name, api_key, policy_id, _now()),
            )
            await db.commit()
            return {"id": cur.lastrowid, "name": name, "api_key": api_key, "policy_id": policy_id}

    async def delete_app(self, app_id: int):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM apps WHERE id = ?", (app_id,))
            await db.commit()

    # ── Requests ──────────────────────────────────────────────────────

    async def log_request(self, app_id: int, model: str, provider: str, **kwargs) -> int:
        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                "INSERT INTO requests (app_id, model, provider, input_tokens, output_tokens, status, blocked_reason, injection_score, pii_detected, pii_redacted, content_flags, latency_ms, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    app_id,
                    model,
                    provider,
                    kwargs.get("input_tokens", 0),
                    kwargs.get("output_tokens", 0),
                    kwargs.get("status", "allowed"),
                    kwargs.get("blocked_reason"),
                    kwargs.get("injection_score", 0),
                    json.dumps(kwargs.get("pii_detected")) if kwargs.get("pii_detected") else None,
                    kwargs.get("pii_redacted", 0),
                    json.dumps(kwargs.get("content_flags")) if kwargs.get("content_flags") else None,
                    kwargs.get("latency_ms", 0),
                    _now(),
                ),
            )
            await db.commit()
            return cur.lastrowid

    async def get_requests(self, limit: int = 100, app_id: int | None = None) -> list[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if app_id:
                cur = await db.execute(
                    "SELECT * FROM requests WHERE app_id = ? ORDER BY id DESC LIMIT ?", (app_id, limit)
                )
            else:
                cur = await db.execute("SELECT * FROM requests ORDER BY id DESC LIMIT ?", (limit,))
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    # ── Violations ────────────────────────────────────────────────────

    async def log_violation(
        self, request_id: int | None, app_id: int, violation_type: str, severity: str, details: str
    ) -> int:
        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                "INSERT INTO violations (request_id, app_id, violation_type, severity, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (request_id, app_id, violation_type, severity, details, _now()),
            )
            await db.commit()
            return cur.lastrowid

    async def get_violations(self, limit: int = 100, app_id: int | None = None) -> list[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if app_id:
                cur = await db.execute(
                    "SELECT v.*, a.name as app_name FROM violations v LEFT JOIN apps a ON v.app_id = a.id WHERE v.app_id = ? ORDER BY v.id DESC LIMIT ?",
                    (app_id, limit),
                )
            else:
                cur = await db.execute(
                    "SELECT v.*, a.name as app_name FROM violations v LEFT JOIN apps a ON v.app_id = a.id ORDER BY v.id DESC LIMIT ?",
                    (limit,),
                )
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    # ── Activity Log ──────────────────────────────────────────────────

    async def log_activity(self, event_type: str, message: str, app_id: int | None = None, data: dict | None = None):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO activity_log (app_id, event_type, message, data, created_at) VALUES (?, ?, ?, ?, ?)",
                (app_id, event_type, message, json.dumps(data) if data else None, _now()),
            )
            await db.commit()

    async def get_activity(self, limit: int = 100) -> list[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM activity_log ORDER BY id DESC LIMIT ?", (limit,))
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    # ── Stats ─────────────────────────────────────────────────────────

    async def get_stats(self) -> dict:
        async with aiosqlite.connect(self.db_path) as db:
            today = datetime.now(UTC).strftime("%Y-%m-%d")

            cur = await db.execute("SELECT COUNT(*) FROM requests WHERE created_at LIKE ?", (f"{today}%",))
            requests_today = (await cur.fetchone())[0]

            cur = await db.execute(
                "SELECT COUNT(*) FROM requests WHERE status = 'blocked' AND created_at LIKE ?", (f"{today}%",)
            )
            blocked_today = (await cur.fetchone())[0]

            cur = await db.execute(
                "SELECT COUNT(*) FROM requests WHERE pii_redacted > 0 AND created_at LIKE ?", (f"{today}%",)
            )
            pii_redacted_today = (await cur.fetchone())[0]

            cur = await db.execute(
                "SELECT COUNT(*) FROM violations WHERE violation_type = 'injection' AND created_at LIKE ?",
                (f"{today}%",),
            )
            injection_attempts_today = (await cur.fetchone())[0]

            cur = await db.execute("SELECT COUNT(*) FROM requests")
            total_requests = (await cur.fetchone())[0]

            cur = await db.execute("SELECT COUNT(*) FROM violations")
            total_violations = (await cur.fetchone())[0]

            cur = await db.execute("SELECT COUNT(*) FROM apps WHERE status = 'active'")
            active_apps = (await cur.fetchone())[0]

            return {
                "requests_today": requests_today,
                "blocked_today": blocked_today,
                "pii_redacted_today": pii_redacted_today,
                "injection_attempts_today": injection_attempts_today,
                "total_requests": total_requests,
                "total_violations": total_violations,
                "active_apps": active_apps,
            }

    async def get_daily_stats(self, days: int = 30) -> list[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """
                SELECT
                    DATE(created_at) as date,
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked,
                    SUM(CASE WHEN status = 'allowed' THEN 1 ELSE 0 END) as allowed
                FROM requests
                WHERE created_at >= DATE('now', ?)
                GROUP BY DATE(created_at)
                ORDER BY date
            """,
                (f"-{days} days",),
            )
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def get_violation_breakdown(self) -> list[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("""
                SELECT violation_type, COUNT(*) as count
                FROM violations
                GROUP BY violation_type
                ORDER BY count DESC
            """)
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def get_violation_analytics(self, hours: int = 24) -> dict:
        """Get violation analytics: per-hour/day stats, top types, top IPs, PII stats, injection trends."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            # Violations per hour (last N hours)
            cur = await db.execute(
                """
                SELECT
                    strftime('%Y-%m-%d %H:00', created_at) as hour,
                    COUNT(*) as count
                FROM violations
                WHERE created_at >= datetime('now', ?)
                GROUP BY hour
                ORDER BY hour
                """,
                (f"-{hours} hours",),
            )
            per_hour = [dict(r) for r in await cur.fetchall()]

            # Violations per day (last 30 days)
            cur = await db.execute(
                """
                SELECT
                    DATE(created_at) as day,
                    COUNT(*) as count
                FROM violations
                WHERE created_at >= DATE('now', '-30 days')
                GROUP BY day
                ORDER BY day
                """,
            )
            per_day = [dict(r) for r in await cur.fetchall()]

            # Top violation types
            cur = await db.execute(
                """
                SELECT violation_type, severity, COUNT(*) as count
                FROM violations
                GROUP BY violation_type, severity
                ORDER BY count DESC
                LIMIT 20
                """,
            )
            top_types = [dict(r) for r in await cur.fetchall()]

            # Top blocked IPs (from requests with blocked status that have PII ip_address detections)
            cur = await db.execute(
                """
                SELECT
                    v.details,
                    COUNT(*) as count
                FROM violations v
                WHERE v.violation_type = 'injection'
                GROUP BY v.details
                ORDER BY count DESC
                LIMIT 10
                """,
            )
            top_blocked = [dict(r) for r in await cur.fetchall()]

            # PII detection stats
            cur = await db.execute(
                """
                SELECT
                    COUNT(*) as total_requests_with_pii,
                    SUM(pii_redacted) as total_pii_redacted
                FROM requests
                WHERE pii_redacted > 0
                """,
            )
            pii_row = await cur.fetchone()
            pii_stats = dict(pii_row) if pii_row else {"total_requests_with_pii": 0, "total_pii_redacted": 0}

            # PII type breakdown from pii_detected JSON field
            cur = await db.execute(
                """
                SELECT pii_detected
                FROM requests
                WHERE pii_detected IS NOT NULL
                ORDER BY id DESC
                LIMIT 500
                """,
            )
            pii_rows = await cur.fetchall()
            pii_type_counts: dict[str, int] = {}
            for row in pii_rows:
                try:
                    detected = json.loads(row[0]) if row[0] else []
                    for item in detected:
                        pii_type = item.get("type", "unknown") if isinstance(item, dict) else str(item)
                        pii_type_counts[pii_type] = pii_type_counts.get(pii_type, 0) + 1
                except (json.JSONDecodeError, TypeError):
                    continue
            pii_stats["type_breakdown"] = pii_type_counts

            # Injection attempt trends (per day, last 30 days)
            cur = await db.execute(
                """
                SELECT
                    DATE(created_at) as day,
                    COUNT(*) as count
                FROM violations
                WHERE violation_type = 'injection'
                    AND created_at >= DATE('now', '-30 days')
                GROUP BY day
                ORDER BY day
                """,
            )
            injection_trends = [dict(r) for r in await cur.fetchall()]

            return {
                "violations_per_hour": per_hour,
                "violations_per_day": per_day,
                "top_violation_types": top_types,
                "top_blocked": top_blocked,
                "pii_stats": pii_stats,
                "injection_trends": injection_trends,
            }

    async def get_request_count_since(self, app_id: int, since_iso: str) -> int:
        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                "SELECT COUNT(*) FROM requests WHERE app_id = ? AND created_at >= ?",
                (app_id, since_iso),
            )
            return (await cur.fetchone())[0]
