"""Policy management for SafetyProxy."""

import json

from src.db.database import Database
from src.utils.logger import get_logger

log = get_logger("policies")


# Built-in policy presets
POLICY_PRESETS: dict[str, dict] = {
    "strict": {
        "injection_threshold": 40,
        "pii_mode": "block",
        "content_categories": '["violence","hate_speech","sexual","illegal","self_harm"]',
        "content_action": "block",
        "rate_limit_rpm": 30,
        "rate_limit_rph": 500,
        "rate_limit_rpd": 5000,
        "max_tokens_per_request": 2000,
    },
    "moderate": {
        "injection_threshold": 70,
        "pii_mode": "redact",
        "content_categories": '["violence","hate_speech","sexual","illegal","self_harm"]',
        "content_action": "block",
        "rate_limit_rpm": 60,
        "rate_limit_rph": 1000,
        "rate_limit_rpd": 10000,
        "max_tokens_per_request": 4000,
    },
    "permissive": {
        "injection_threshold": 90,
        "pii_mode": "detect",
        "content_categories": '["hate_speech","sexual","illegal"]',
        "content_action": "warn",
        "rate_limit_rpm": 120,
        "rate_limit_rph": 3000,
        "rate_limit_rpd": 50000,
        "max_tokens_per_request": 8000,
    },
}


class PolicyManager:
    """Manages security policies for apps."""

    def __init__(self, db: Database):
        self.db = db

    async def get_policy_for_app(self, app: dict) -> dict:
        """Get the policy for an app. Falls back to default if not set."""
        policy_id = app.get("policy_id")
        if policy_id:
            policy = await self.db.get_policy(policy_id)
            if policy:
                return policy

        # Fall back to default
        default = await self.db.get_policy_by_name("default")
        if default:
            return default

        # Absolute fallback
        return POLICY_PRESETS["moderate"]

    async def create_from_preset(self, name: str, preset: str, overrides: dict | None = None) -> int | None:
        """Create a policy from a preset, with optional overrides for each guard layer."""
        if preset not in POLICY_PRESETS:
            log.warning(f"Unknown preset: {preset}")
            return None

        params = dict(POLICY_PRESETS[preset])
        if overrides:
            allowed_keys = set(params.keys())
            for k, v in overrides.items():
                if k in allowed_keys:
                    # Serialize lists to JSON strings for content_categories
                    if k == "content_categories" and isinstance(v, list):
                        params[k] = json.dumps(v)
                    else:
                        params[k] = v

        return await self.db.create_policy(name, **params)

    async def list_policies(self) -> list[dict]:
        """List all policies with parsed categories."""
        policies = await self.db.get_policies()
        for p in policies:
            if isinstance(p.get("content_categories"), str):
                try:
                    p["content_categories_list"] = json.loads(p["content_categories"])
                except json.JSONDecodeError:
                    p["content_categories_list"] = []
            # Determine which preset this matches, if any
            p["preset"] = self._detect_preset(p)
        return policies

    async def update_policy(self, policy_id: int, **kwargs) -> bool:
        """Update an existing policy."""
        return await self.db.update_policy(policy_id, **kwargs)

    async def delete_policy(self, policy_id: int) -> bool:
        """Delete a policy (cannot delete default)."""
        return await self.db.delete_policy(policy_id)

    def get_content_categories(self, policy: dict) -> list[str]:
        """Parse content categories from policy."""
        cats = policy.get("content_categories", "[]")
        if isinstance(cats, str):
            try:
                return json.loads(cats)
            except json.JSONDecodeError:
                return []
        return cats if isinstance(cats, list) else []

    def _detect_preset(self, policy: dict) -> str | None:
        """Detect if a policy matches a known preset."""
        for preset_name, preset_vals in POLICY_PRESETS.items():
            match = True
            for k, v in preset_vals.items():
                if policy.get(k) != v:
                    match = False
                    break
            if match:
                return preset_name
        return None
