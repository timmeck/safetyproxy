"""FastAPI application for SafetyProxy."""

import asyncio
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sse_starlette.sse import EventSourceResponse

from src.ai.llm import LLM
from src.config import AUDIT_RETENTION_DAYS, NEXUS_URL, SAFETYPROXY_PORT
from src.db.database import Database
from src.guard.engine import GuardEngine
from src.guard.policies import PolicyManager
from src.nexus_sdk import NexusAdapter
from src.utils.logger import get_logger
from src.web.auth import AuthMiddleware

log = get_logger("api")

db = Database()
llm = LLM()
engine = GuardEngine(db, llm)
policy_manager = PolicyManager(db)

# SSE event queue
_event_subscribers: list[asyncio.Queue] = []


def broadcast_event(event_type: str, data: dict):
    """Broadcast an event to all SSE subscribers."""
    payload = json.dumps({"type": event_type, **data})
    for q in _event_subscribers:
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.initialize()
    log.info(f"SafetyProxy starting on port {SAFETYPROXY_PORT}")
    yield
    log.info("SafetyProxy shutting down")


app = FastAPI(title="SafetyProxy", version="1.0.0", lifespan=lifespan)
app.add_middleware(AuthMiddleware)

nexus = NexusAdapter(
    app=app,
    agent_name="safetyproxy",
    nexus_url=NEXUS_URL,
    endpoint=f"http://localhost:{SAFETYPROXY_PORT}",
    description="AI Safety Proxy — prompt injection, PII detection, content filtering",
    capabilities=[
        {
            "name": "prompt_injection_detection",
            "description": "Detect prompt injection attacks",
            "languages": ["en"],
            "price_per_request": 0.005,
        },
        {
            "name": "pii_detection",
            "description": "Detect and flag PII in text",
            "languages": ["en"],
            "price_per_request": 0.005,
        },
    ],
    tags=["safety", "security", "pii", "injection"],
)


@nexus.handle("prompt_injection_detection")
async def handle_injection(query: str, params: dict) -> dict:
    result = await engine.process_request(
        messages=[{"role": "user", "content": query}], model="check-only", app_key="nexus", forward_to_llm=False
    )
    return {"result": json.dumps(result, default=str), "confidence": 0.90, "cost": 0.005}


@nexus.handle("pii_detection")
async def handle_pii(query: str, params: dict) -> dict:
    result = await engine.process_request(
        messages=[{"role": "user", "content": query}], model="check-only", app_key="nexus", forward_to_llm=False
    )
    return {"result": json.dumps(result, default=str), "confidence": 0.85, "cost": 0.005}


# ── Dashboard ─────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    from pathlib import Path

    template_path = Path(__file__).parent / "templates" / "dashboard.html"
    return HTMLResponse(template_path.read_text(encoding="utf-8"))


# ── Status ────────────────────────────────────────────────────────


@app.get("/api/status")
async def status():
    stats = await db.get_stats()
    return {
        "product": "SafetyProxy",
        "version": "1.0.0",
        "status": "operational",
        "llm_provider": llm.provider,
        "llm_model": llm.model,
        "llm_healthy": llm.is_healthy,
        "stats": stats,
    }


# ── Proxy ─────────────────────────────────────────────────────────


@app.post("/api/proxy/chat")
async def proxy_chat(request: Request):
    """Main proxy endpoint — accepts messages, runs through guards, forwards to LLM."""
    body = await request.json()
    messages = body.get("messages", [])
    model = body.get("model")
    app_key = body.get("app_key") or request.headers.get("X-App-Key")
    forward = body.get("forward_to_llm", True)

    if not messages:
        return JSONResponse({"error": "No messages provided"}, status_code=400)

    result = await engine.process_request(
        messages=messages,
        model=model,
        app_key=app_key,
        forward_to_llm=forward,
    )

    # Broadcast event
    broadcast_event(
        "request",
        {
            "status": result.status,
            "injection_score": result.injection_score,
            "pii_redacted": result.pii_redacted,
            "blocked_reason": result.blocked_reason,
        },
    )

    # Store audit log entry
    prompt_text = " ".join(m.get("content", "") for m in messages)
    await db.log_audit(
        app_id=0,  # Will be replaced once app lookup happens in engine
        model=model or "unknown",
        prompt=prompt_text,
        response=result.response,
        guard_results=result.to_dict(),
        status=result.status,
        blocked_reason=result.blocked_reason,
        latency_ms=result.latency_ms,
    )

    if not result.allowed:
        return JSONResponse(
            {
                "error": "Request blocked",
                "reason": result.blocked_reason,
                "details": result.to_dict(),
            },
            status_code=403,
        )

    return {
        "response": result.response,
        "status": result.status,
        "guard_details": {
            "injection_score": result.injection_score,
            "pii_redacted": result.pii_redacted,
            "content_flags": result.content_flags,
            "latency_ms": result.latency_ms,
        },
    }


# ── Apps ──────────────────────────────────────────────────────────


@app.get("/api/apps")
async def list_apps():
    apps = await db.get_apps()
    return {"apps": apps}


@app.post("/api/apps")
async def register_app(request: Request):
    body = await request.json()
    name = body.get("name")
    policy_id = body.get("policy_id")
    if not name:
        return JSONResponse({"error": "Name is required"}, status_code=400)
    try:
        app_data = await db.register_app(name, policy_id)
        broadcast_event("app_registered", {"name": name})
        return app_data
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@app.delete("/api/apps/{app_id}")
async def delete_app(app_id: int):
    await db.delete_app(app_id)
    return {"status": "deleted"}


# ── Policies (CRUD) ──────────────────────────────────────────────


@app.get("/api/policies")
async def list_policies():
    policies = await policy_manager.list_policies()
    return {"policies": policies}


@app.post("/api/policies")
async def create_policy(request: Request):
    body = await request.json()
    name = body.get("name")
    if not name:
        return JSONResponse({"error": "Name is required"}, status_code=400)

    preset = body.get("preset")
    if preset:
        pid = await policy_manager.create_from_preset(name, preset)
        if pid:
            return {"id": pid, "name": name, "preset": preset}
        return JSONResponse({"error": f"Unknown preset: {preset}"}, status_code=400)

    pid = await db.create_policy(name, **body)
    return {"id": pid, "name": name}


@app.put("/api/policies/{policy_id}")
async def update_policy(policy_id: int, request: Request):
    """Update an existing policy."""
    body = await request.json()
    if not body:
        return JSONResponse({"error": "No fields to update"}, status_code=400)

    # If content_categories is a list, serialize to JSON string
    if "content_categories" in body and isinstance(body["content_categories"], list):
        body["content_categories"] = json.dumps(body["content_categories"])

    updated = await db.update_policy(policy_id, **body)
    if not updated:
        return JSONResponse({"error": "Policy not found or no valid fields"}, status_code=404)

    policy = await db.get_policy(policy_id)
    return {"policy": policy}


@app.delete("/api/policies/{policy_id}")
async def delete_policy(policy_id: int):
    """Delete a policy (cannot delete the default policy)."""
    deleted = await db.delete_policy(policy_id)
    if not deleted:
        return JSONResponse(
            {"error": "Policy not found or cannot delete the default policy"},
            status_code=400,
        )
    return {"status": "deleted", "id": policy_id}


# ── Violations ────────────────────────────────────────────────────


@app.get("/api/violations")
async def list_violations(limit: int = 100, app_id: int | None = None):
    violations = await db.get_violations(limit=limit, app_id=app_id)
    return {"violations": violations}


# ── Requests ──────────────────────────────────────────────────────


@app.get("/api/requests")
async def list_requests(limit: int = 100, app_id: int | None = None):
    requests = await db.get_requests(limit=limit, app_id=app_id)
    return {"requests": requests}


# ── Stats ─────────────────────────────────────────────────────────


@app.get("/api/stats")
async def get_stats():
    stats = await db.get_stats()
    daily = await db.get_daily_stats()
    breakdown = await db.get_violation_breakdown()
    return {
        "stats": stats,
        "daily": daily,
        "violation_breakdown": breakdown,
    }


# ── Analytics ─────────────────────────────────────────────────────


@app.get("/api/analytics/violations")
async def violation_analytics(hours: int = 24):
    """Violation analytics: per-hour/day stats, top types, top blocked, PII stats, injection trends."""
    analytics = await db.get_violation_analytics(hours=hours)
    return {"analytics": analytics}


# ── Activity Log ──────────────────────────────────────────────────


@app.get("/api/activity")
async def get_activity(limit: int = 100):
    activity = await db.get_activity(limit=limit)
    return {"activity": activity}


# ── Audit Log ────────────────────────────────────────────────────


@app.get("/api/audit/log")
async def audit_log(page: int = 1, limit: int = 50):
    """Paginated audit log with full request/response details."""
    if limit > 200:
        limit = 200
    result = await db.get_audit_log(page=page, limit=limit)
    return result


@app.get("/api/audit/export")
async def export_audit(limit: int = 1000):
    """Export audit trail as JSON for compliance (EU AI Act)."""
    requests = await db.get_requests(limit=limit)
    violations = await db.get_violations(limit=limit)
    activity = await db.get_activity(limit=limit)
    return {
        "export_type": "compliance_audit",
        "product": "SafetyProxy",
        "requests": requests,
        "violations": violations,
        "activity": activity,
    }


@app.post("/api/audit/cleanup")
async def audit_cleanup(request: Request):
    """Manually trigger cleanup of old audit entries."""
    body = await request.json() if request.headers.get("content-type") == "application/json" else {}
    days = body.get("retention_days", AUDIT_RETENTION_DAYS)
    deleted = await db.cleanup_old_audit_entries(retention_days=days)
    return {"deleted": deleted, "retention_days": days}


@app.get("/api/audit/{audit_id}")
async def audit_detail(audit_id: int):
    """Full detail of a single audit entry including prompt, response, and all guard results."""
    entry = await db.get_audit_entry(audit_id)
    if not entry:
        return JSONResponse({"error": "Audit entry not found"}, status_code=404)
    return {"audit": entry}


@app.post("/api/audit/{audit_id}/replay")
async def audit_replay(audit_id: int):
    """Re-run guards on a stored audit entry (useful for testing policy changes)."""
    entry = await db.get_audit_entry(audit_id)
    if not entry:
        return JSONResponse({"error": "Audit entry not found"}, status_code=404)

    prompt = entry.get("prompt")
    if not prompt:
        return JSONResponse(
            {"error": "No prompt stored for this entry (AUDIT_FULL_CONTENT may be disabled)"},
            status_code=400,
        )

    # Re-run through the guard engine without forwarding to LLM
    result = await engine.process_request(
        messages=[{"role": "user", "content": prompt}],
        model=entry.get("model", "replay"),
        forward_to_llm=False,
    )

    return {
        "original": {
            "status": entry.get("status"),
            "blocked_reason": entry.get("blocked_reason"),
            "guard_results": entry.get("guard_results"),
        },
        "replay": result.to_dict(),
    }


# ── SSE ───────────────────────────────────────────────────────────


@app.get("/api/events/stream")
async def event_stream(request: Request):
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    _event_subscribers.append(queue)

    async def generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield {"event": "message", "data": data}
                except TimeoutError:
                    yield {"event": "ping", "data": "{}"}
        finally:
            _event_subscribers.remove(queue)

    return EventSourceResponse(generator())
