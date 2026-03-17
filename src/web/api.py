"""FastAPI application for SafetyProxy."""
import asyncio
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sse_starlette.sse import EventSourceResponse

from src.config import SAFETYPROXY_PORT
from src.db.database import Database
from src.ai.llm import LLM
from src.guard.engine import GuardEngine
from src.guard.policies import PolicyManager
from src.web.auth import AuthMiddleware
from src.utils.logger import get_logger

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


# ── Nexus Protocol Endpoint ────────────────────────────────────────

@app.post("/nexus/handle")
async def nexus_handle(request: Request):
    """Handle incoming NexusRequest from the Nexus protocol layer."""
    import time, uuid
    body = await request.json()
    start = time.perf_counter_ns()
    capability = body.get("capability", "")
    query = body.get("query", "")
    req_id = body.get("request_id", "")
    from_agent = body.get("from_agent", "")

    try:
        if capability == "prompt_injection_detection":
            result = await engine.process_request(
                messages=[{"role": "user", "content": query}],
                model="check-only", app_key="nexus", forward_to_llm=False,
            )
            answer = json.dumps(result, default=str)
            confidence = 0.90
        elif capability == "pii_detection":
            result = await engine.process_request(
                messages=[{"role": "user", "content": query}],
                model="check-only", app_key="nexus", forward_to_llm=False,
            )
            answer = json.dumps(result, default=str)
            confidence = 0.85
        else:
            elapsed = (time.perf_counter_ns() - start) // 1_000_000
            return {"response_id": uuid.uuid4().hex, "request_id": req_id,
                    "from_agent": "safetyproxy", "to_agent": from_agent,
                    "status": "failed", "answer": "", "confidence": 0.0,
                    "error": f"Unsupported capability: {capability}",
                    "processing_ms": elapsed, "cost": 0.0, "sources": [], "meta": {}}

        elapsed = (time.perf_counter_ns() - start) // 1_000_000
        return {"response_id": uuid.uuid4().hex, "request_id": req_id,
                "from_agent": "safetyproxy", "to_agent": from_agent,
                "status": "completed", "answer": answer, "confidence": confidence,
                "processing_ms": elapsed, "cost": 0.005, "sources": [], "meta": {"capability": capability}}
    except Exception as e:
        elapsed = (time.perf_counter_ns() - start) // 1_000_000
        return {"response_id": uuid.uuid4().hex, "request_id": req_id,
                "from_agent": "safetyproxy", "to_agent": from_agent,
                "status": "failed", "answer": "", "confidence": 0.0,
                "error": str(e), "processing_ms": elapsed, "cost": 0.0, "sources": [], "meta": {}}


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
    broadcast_event("request", {
        "status": result.status,
        "injection_score": result.injection_score,
        "pii_redacted": result.pii_redacted,
        "blocked_reason": result.blocked_reason,
    })

    if not result.allowed:
        return JSONResponse({
            "error": "Request blocked",
            "reason": result.blocked_reason,
            "details": result.to_dict(),
        }, status_code=403)

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


# ── Policies ──────────────────────────────────────────────────────

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


# ── Activity Log ──────────────────────────────────────────────────

@app.get("/api/activity")
async def get_activity(limit: int = 100):
    activity = await db.get_activity(limit=limit)
    return {"activity": activity}


# ── Audit Export ──────────────────────────────────────────────────

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
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": "{}"}
        finally:
            _event_subscribers.remove(queue)

    return EventSourceResponse(generator())
