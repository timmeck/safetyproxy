"""Core guard engine — orchestrates all security checks for SafetyProxy."""
import json
import time
from dataclasses import dataclass, field

from src.db.database import Database
from src.ai.llm import LLM
from src.guard.injection import detect_injection
from src.guard.pii import detect_pii, redact_pii
from src.guard.content import filter_content, is_flagged
from src.guard.ratelimit import RateLimiter
from src.guard.policies import PolicyManager
from src.utils.logger import get_logger

log = get_logger("engine")


@dataclass
class GuardResult:
    allowed: bool
    status: str  # "allowed", "blocked", "redacted"
    blocked_reason: str | None = None
    injection_score: int = 0
    pii_detected: list[dict] = field(default_factory=list)
    pii_redacted: int = 0
    content_flags: list[dict] = field(default_factory=list)
    processed_messages: list[dict] = field(default_factory=list)
    response: str | None = None
    latency_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "status": self.status,
            "blocked_reason": self.blocked_reason,
            "injection_score": self.injection_score,
            "pii_detected": self.pii_detected,
            "pii_redacted": self.pii_redacted,
            "content_flags": self.content_flags,
            "response": self.response,
            "latency_ms": self.latency_ms,
        }


class GuardEngine:
    """Orchestrates all safety checks on LLM requests."""

    def __init__(self, db: Database, llm: LLM | None = None):
        self.db = db
        self.llm = llm or LLM()
        self.rate_limiter = RateLimiter(db)
        self.policy_manager = PolicyManager(db)

    async def process_request(
        self,
        messages: list[dict],
        model: str | None = None,
        app_key: str | None = None,
        forward_to_llm: bool = True,
    ) -> GuardResult:
        """Process a request through all safety guards.

        Args:
            messages: List of {role, content} message dicts
            model: LLM model to use
            app_key: API key of the requesting app
            forward_to_llm: Whether to forward to LLM after passing guards

        Returns:
            GuardResult with status and details
        """
        start = time.time()
        model = model or self.llm.model

        # 1. Look up app and policy
        app = None
        policy = None
        if app_key:
            app = await self.db.get_app_by_key(app_key)
            if not app:
                return GuardResult(
                    allowed=False,
                    status="blocked",
                    blocked_reason="Invalid API key",
                    latency_ms=int((time.time() - start) * 1000),
                )
            policy = await self.policy_manager.get_policy_for_app(app)
        else:
            # Use default policy for unauthenticated requests
            policy = await self.db.get_policy_by_name("default")
            if not policy:
                from src.guard.policies import POLICY_PRESETS
                policy = POLICY_PRESETS["moderate"]

        app_id = app["id"] if app else 0
        injection_threshold = policy.get("injection_threshold", 70)
        pii_mode = policy.get("pii_mode", "redact")
        content_action = policy.get("content_action", "block")
        content_categories = self.policy_manager.get_content_categories(policy)

        # 2. Check rate limit
        if app:
            rate_check = await self.rate_limiter.check_rate_limit(app_id, policy)
            if not rate_check["allowed"]:
                result = GuardResult(
                    allowed=False,
                    status="blocked",
                    blocked_reason=rate_check["reason"],
                    latency_ms=int((time.time() - start) * 1000),
                )
                await self._log_request(app_id, model, result)
                await self._log_violation(None, app_id, "rate_limit", "medium", rate_check["reason"])
                return result

        # 3. Run injection detection on user messages
        all_pii = []
        total_pii_redacted = 0
        all_content_flags = []
        max_injection_score = 0
        processed_messages = []

        for msg in messages:
            content = msg.get("content", "")
            role = msg.get("role", "user")
            processed_content = content

            if role == "user":
                # Injection check
                injection_result = detect_injection(content)
                score = injection_result["score"]
                max_injection_score = max(max_injection_score, score)

                if score >= injection_threshold:
                    result = GuardResult(
                        allowed=False,
                        status="blocked",
                        blocked_reason=f"Prompt injection detected (score: {score}/{injection_threshold})",
                        injection_score=score,
                        latency_ms=int((time.time() - start) * 1000),
                    )
                    req_id = await self._log_request(app_id, model, result)
                    await self._log_violation(
                        req_id, app_id, "injection", "high",
                        json.dumps({"score": score, "findings": injection_result["findings"][:5]})
                    )
                    return result

                # PII detection
                pii_matches = detect_pii(content)
                if pii_matches:
                    pii_dicts = [m.to_dict() for m in pii_matches]
                    all_pii.extend(pii_dicts)

                    if pii_mode == "block":
                        types_found = list(set(m.type for m in pii_matches))
                        result = GuardResult(
                            allowed=False,
                            status="blocked",
                            blocked_reason=f"PII detected: {', '.join(types_found)}",
                            pii_detected=pii_dicts,
                            injection_score=max_injection_score,
                            latency_ms=int((time.time() - start) * 1000),
                        )
                        req_id = await self._log_request(app_id, model, result)
                        await self._log_violation(
                            req_id, app_id, "pii", "high",
                            f"PII types found: {', '.join(types_found)}"
                        )
                        return result
                    elif pii_mode == "redact":
                        processed_content = redact_pii(content, pii_matches)
                        total_pii_redacted += len(pii_matches)

                # Content filtering
                flags = filter_content(content, content_categories)
                if flags:
                    flag_dicts = [f.to_dict() for f in flags]
                    all_content_flags.extend(flag_dicts)

                    if content_action == "block" and is_flagged(flags):
                        cats = [f.category for f in flags]
                        result = GuardResult(
                            allowed=False,
                            status="blocked",
                            blocked_reason=f"Content policy violation: {', '.join(cats)}",
                            content_flags=flag_dicts,
                            injection_score=max_injection_score,
                            pii_detected=all_pii,
                            latency_ms=int((time.time() - start) * 1000),
                        )
                        req_id = await self._log_request(app_id, model, result)
                        await self._log_violation(
                            req_id, app_id, "content", "high",
                            f"Flagged categories: {', '.join(cats)}"
                        )
                        return result

            processed_messages.append({"role": role, "content": processed_content})

        # 4. Forward to LLM if all checks pass
        response_text = None
        if forward_to_llm and self.llm.is_healthy:
            # Build prompt from messages
            system_msg = ""
            user_msgs = []
            for msg in processed_messages:
                if msg["role"] == "system":
                    system_msg = msg["content"]
                else:
                    user_msgs.append(msg["content"])

            prompt = "\n".join(user_msgs)
            response_text = await self.llm.query(prompt, system=system_msg or "You are a helpful assistant.")

            # 5. Run content filter on response
            if response_text:
                response_flags = filter_content(response_text, content_categories)
                if response_flags and content_action == "block" and is_flagged(response_flags):
                    response_flag_dicts = [f.to_dict() for f in response_flags]
                    all_content_flags.extend(response_flag_dicts)
                    cats = [f.category for f in response_flags]
                    result = GuardResult(
                        allowed=False,
                        status="blocked",
                        blocked_reason=f"Response content policy violation: {', '.join(cats)}",
                        content_flags=all_content_flags,
                        injection_score=max_injection_score,
                        pii_detected=all_pii,
                        pii_redacted=total_pii_redacted,
                        latency_ms=int((time.time() - start) * 1000),
                    )
                    req_id = await self._log_request(app_id, model, result)
                    await self._log_violation(
                        req_id, app_id, "content_response", "medium",
                        f"Response flagged categories: {', '.join(cats)}"
                    )
                    return result

        # Record rate limit
        if app:
            self.rate_limiter.record_request(app_id)

        status = "redacted" if total_pii_redacted > 0 else "allowed"
        result = GuardResult(
            allowed=True,
            status=status,
            injection_score=max_injection_score,
            pii_detected=all_pii,
            pii_redacted=total_pii_redacted,
            content_flags=[f.to_dict() for f in filter_content("", [])] if not all_content_flags else all_content_flags,
            processed_messages=processed_messages,
            response=response_text,
            latency_ms=int((time.time() - start) * 1000),
        )

        await self._log_request(app_id, model, result)

        if all_pii and pii_mode == "detect":
            req_id = await self._log_request(app_id, model, result)
            await self._log_violation(
                req_id, app_id, "pii", "low",
                f"PII detected (log only): {json.dumps(all_pii[:5])}"
            )

        return result

    async def _log_request(self, app_id: int, model: str, result: GuardResult) -> int:
        if app_id == 0:
            return 0
        return await self.db.log_request(
            app_id=app_id,
            model=model,
            provider=self.llm.provider,
            status=result.status,
            blocked_reason=result.blocked_reason,
            injection_score=result.injection_score,
            pii_detected=result.pii_detected if result.pii_detected else None,
            pii_redacted=result.pii_redacted,
            content_flags=result.content_flags if result.content_flags else None,
            latency_ms=result.latency_ms,
        )

    async def _log_violation(self, request_id: int | None, app_id: int, violation_type: str, severity: str, details: str):
        if app_id == 0:
            return
        await self.db.log_violation(request_id, app_id, violation_type, severity, details)
        await self.db.log_activity(
            event_type=f"violation.{violation_type}",
            message=f"{violation_type.upper()} violation for app {app_id}: {details[:200]}",
            app_id=app_id,
            data={"severity": severity, "type": violation_type},
        )
