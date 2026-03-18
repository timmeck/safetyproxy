# SafetyProxy

Self-hosted API proxy that sits in front of any LLM and blocks prompt injection, detects PII, filters content, and logs compliance.

## Features

- **Prompt Injection Detection** — Pattern matching, base64 decoding, homoglyph detection, zero-width character detection
- **PII Detection & Redaction** — Emails, phones, SSNs, credit cards, IP addresses
- **Content Filtering** — Violence, hate speech, sexual, illegal, self-harm categories
- **Rate Limiting** — Per-minute, per-hour, per-day configurable limits
- **Policy Management** — Named policies with presets (strict, moderate, permissive)
- **Compliance Logging** — Full audit trail, EU AI Act ready, JSON export
- **Real-time Dashboard** — Purple/shield themed security dashboard with SSE

## Quick Start

```bash
# Install
pip install -r requirements.txt

# Configure
cp .env.example .env

# Run
python run.py serve
```

Open http://localhost:8700 for the dashboard.

## CLI Commands

```bash
python run.py status              # Show system status
python run.py apps                # List registered apps
python run.py register <name>     # Register new app
python run.py policies            # List policies
python run.py create-policy <n>   # Create policy (--preset strict|moderate|permissive)
python run.py violations          # Show recent violations
python run.py serve               # Start server on port 8700
```

## API

```bash
# Proxy a chat request
curl -X POST http://localhost:8700/api/proxy/chat \
  -H "Content-Type: application/json" \
  -d '{"messages": [{"role": "user", "content": "Hello"}], "app_key": "sp_..."}'

# Register an app
curl -X POST http://localhost:8700/api/apps \
  -d '{"name": "my-app"}'

# Export audit log
curl http://localhost:8700/api/audit/export
```

## Docker

```bash
docker-compose up -d
```

## Nexus Protocol

SafetyProxy integrates with [Nexus](https://github.com/timmeck/nexus) via the NexusAdapter SDK.

| Capability | Description | Price |
|-----------|-------------|-------|
| `prompt_injection_detection` | Detect prompt injection attacks | 0.005 |
| `pii_detection` | Detect and flag PII in text | 0.005 |

**Features**: HMAC signature verification, automatic heartbeats (30s), auto-registration with Nexus on startup.

## Testing

```bash
pip install pytest pytest-asyncio
pytest tests/ -v
```

## License

MIT
