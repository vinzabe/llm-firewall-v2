# LLM Firewall v2

Drop-in OpenAI-compatible firewall for LLM traffic with:
- Adaptive **per-tenant policies** (block/warn thresholds, category weights, allow/denylists)
- Full **OWASP LLM Top 10** detector suite (LLM01..LLM10)
- **Self-tuning detector** — online learning from FP/FN feedback
- LLM-as-judge **escalation** for ambiguous cases
- Inbound + outbound scanning, with **auto-PII redaction**
- SQLite-backed telemetry and live web dashboard

## Architecture

```
client ──> /v1/chat/completions ──> [INBOUND scan] ──> upstream LLM
                                       │                      │
                                       ▼                      ▼
                                    [block?]           [OUTBOUND scan]
                                                              │
                                                              ▼
                                                    [block / redact / pass]
```

## Install

```bash
git clone https://github.com/vinzabe/llm-firewall-v2.git
cd llm-firewall-v2
pip install -r requirements.txt
```

## Configure

Set the upstream LLM endpoint (any OpenAI-compatible API):

```bash
export LLM_BASE_URL="https://your-llm-endpoint/v1"
export LLM_API_KEY="sk-..."
export LLM_MODEL="glm-5.1"            # default chat model
export LLM_VISION_MODEL="gpt-4o-mini" # default vision model
```

## Run

```bash
python -m firewall.gateway          # http://localhost:8080
# or:
uvicorn firewall.gateway:app --host 0.0.0.0 --port 8080
```

Dashboard: http://localhost:8080/dashboard

## Use as drop-in proxy

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8080/v1", api_key="anything")
client.chat.completions.create(
    model="glm-5.1",
    messages=[{"role": "user", "content": "hi"}],
    extra_headers={"x-tenant-id": "tenant-a"},
)
```

Blocked requests get HTTP 403 with structured error.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/chat/completions` | OpenAI-compatible firewalled proxy |
| `POST` | `/firewall/scan` | Standalone scan of arbitrary text |
| `GET/PUT` | `/firewall/policies/{tenant_id}` | Per-tenant policy CRUD |
| `GET` | `/firewall/telemetry` | Query events + breakdowns |
| `POST` | `/firewall/feedback` | Submit FP/FN/TP/TN labels (drives learner) |
| `GET` | `/dashboard` | Live web UI |

## Smoke tests

```bash
python tests/test_firewall.py
```

17/17 tests pass against a live LLM endpoint.

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability disclosure policy.

## License

MIT — see [LICENSE](./LICENSE).
