"""FastAPI gateway: OpenAI-compatible drop-in proxy that firewalls every request."""
from __future__ import annotations

import json
import os
import sys
import time
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

# Add shared client to path

# --- standalone-repo shim: add project root to sys.path ---
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_PROJECT_ROOT = _os.path.normpath(_os.path.join(_HERE, '..'))

sys.path.insert(0, _PROJECT_ROOT)
from llm_client import LLMClient  # noqa: E402

from .engine import FirewallEngine
from .owasp import OWASP_LLM_TOP10
from .policies import Policy, PolicyStore
from .telemetry import TelemetryStore

DATA_DIR = os.environ.get("FW_DATA_DIR", os.path.join(_PROJECT_ROOT, "data"))
os.makedirs(DATA_DIR, exist_ok=True)

UPSTREAM_BASE = os.environ.get("LLM_BASE_URL", "http://23.82.125.198:9440/v1")
UPSTREAM_KEY = os.environ.get("LLM_API_KEY",
                              "grant-8e10fc68302653bd8415aaf0c00974fe8c909b8a1b2afbbf881dde21")

policy_store = PolicyStore(os.path.join(DATA_DIR, "policies.db"))
telemetry = TelemetryStore(os.path.join(DATA_DIR, "telemetry.db"))
_llm_client = LLMClient()
engine = FirewallEngine(policy_store, telemetry, _llm_client)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="LLM Firewall v2", version="2.0.0", lifespan=lifespan)


def _tenant_from_request(req: Request) -> str:
    return req.headers.get("x-tenant-id", "default")


@app.get("/")
def root() -> dict:
    return {
        "name": "llm-firewall-v2",
        "version": "2.0.0",
        "endpoints": {
            "proxy": "POST /v1/chat/completions",
            "scan": "POST /firewall/scan",
            "policies": "GET/PUT /firewall/policies/{tenant_id}",
            "telemetry": "GET /firewall/telemetry",
            "feedback": "POST /firewall/feedback",
            "dashboard": "GET /dashboard",
        },
        "owasp": {k: v.title for k, v in OWASP_LLM_TOP10.items()},
    }


class ScanRequest(BaseModel):
    text: str
    tenant_id: str = "default"
    direction: str = "inbound"


@app.post("/firewall/scan")
def scan_endpoint(req: ScanRequest) -> dict:
    decision = engine.scan(req.text, tenant_id=req.tenant_id, direction=req.direction)
    return decision.to_dict()


@app.get("/firewall/policies/{tenant_id}")
def get_policy(tenant_id: str) -> dict:
    return policy_store.get(tenant_id).to_dict()


@app.put("/firewall/policies/{tenant_id}")
async def put_policy(tenant_id: str, req: Request) -> dict:
    body = await req.json()
    body["tenant_id"] = tenant_id
    p = Policy(**body)
    policy_store.put(p)
    return p.to_dict()


@app.get("/firewall/telemetry")
def get_telemetry(
    tenant_id: str | None = None, since: float = 0.0, limit: int = 50,
) -> dict:
    events = telemetry.query(tenant_id=tenant_id, since=since, limit=limit)
    return {
        "events": events,
        "category_breakdown": telemetry.category_breakdown(tenant_id=tenant_id, since=since),
        "action_counts": telemetry.action_counts(tenant_id=tenant_id, since=since),
    }


class FeedbackRequest(BaseModel):
    tenant_id: str
    request_id: str
    label: str  # 'tp', 'fp', 'fn', 'tn'


@app.post("/firewall/feedback")
def feedback_endpoint(req: FeedbackRequest) -> dict:
    engine.feedback(req.tenant_id, req.request_id, req.label)
    learner = engine.learners.get(req.tenant_id)
    return {"ok": True, "stats": learner.stats() if learner else {}}


@app.post("/v1/chat/completions")
async def chat_proxy(req: Request) -> Any:
    body = await req.json()
    tenant_id = _tenant_from_request(req)
    model = body.get("model", "glm-5.1")

    # 1. Inbound scan: concatenate user/system messages
    msgs = body.get("messages", [])
    inbound_text = "\n".join(
        m.get("content", "") if isinstance(m.get("content"), str)
        else json.dumps(m.get("content"))
        for m in msgs
    )
    in_decision = engine.scan(inbound_text, tenant_id=tenant_id,
                              direction="inbound", model=model)
    if in_decision.action == "block":
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "type": "firewall_blocked",
                    "code": "LLM_FIREWALL_INBOUND_BLOCK",
                    "message": in_decision.blocked_reason or "request blocked by firewall",
                    "request_id": in_decision.request_id,
                    "decision": in_decision.to_dict(),
                }
            },
        )

    # 2. Forward to upstream
    headers = {
        "Authorization": f"Bearer {UPSTREAM_KEY}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        r = await client.post(f"{UPSTREAM_BASE}/chat/completions",
                              headers=headers, json=body)
    if r.status_code != 200:
        return JSONResponse(status_code=r.status_code,
                            content={"upstream_error": r.text})
    data = r.json()

    # 3. Outbound scan
    output_text = data["choices"][0]["message"].get("content", "") if data.get("choices") else ""
    out_decision = engine.scan(output_text, tenant_id=tenant_id,
                               direction="outbound", model=model)
    if out_decision.action == "block":
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "type": "firewall_blocked",
                    "code": "LLM_FIREWALL_OUTBOUND_BLOCK",
                    "message": out_decision.blocked_reason
                               or "response blocked by firewall",
                    "request_id": out_decision.request_id,
                    "decision": out_decision.to_dict(),
                }
            },
        )
    if out_decision.redacted_text is not None:
        data["choices"][0]["message"]["content"] = out_decision.redacted_text
        data["firewall"] = {"redacted": True,
                            "request_id": out_decision.request_id}

    data["firewall_decisions"] = {
        "inbound": in_decision.to_dict(),
        "outbound": out_decision.to_dict(),
    }
    return data


DASHBOARD_HTML = """
<!doctype html><html><head><title>LLM Firewall v2</title>
<style>
body{font-family:system-ui,sans-serif;max-width:1200px;margin:2em auto;padding:0 1em;background:#0d1117;color:#c9d1d9}
table{border-collapse:collapse;width:100%;margin:1em 0}
th,td{border:1px solid #30363d;padding:6px 10px;text-align:left;font-size:13px}
th{background:#161b22}
.allow{color:#3fb950}.warn{color:#d29922}.block{color:#f85149}
h1,h2{color:#58a6ff}
.kpi{display:inline-block;background:#161b22;padding:1em;margin:0.5em;border-radius:6px;min-width:140px}
.kpi b{font-size:1.6em;display:block}
code{background:#161b22;padding:2px 5px;border-radius:3px}
</style></head><body>
<h1>LLM Firewall v2 Dashboard</h1>
<div id=kpis></div>
<h2>OWASP Category Breakdown</h2>
<table id=cats><thead><tr><th>Category</th><th>Title</th><th>Events</th></tr></thead><tbody></tbody></table>
<h2>Recent Events</h2>
<table id=events><thead><tr><th>Time</th><th>Tenant</th><th>Dir</th><th>Action</th><th>Score</th><th>Cat</th><th>Preview</th></tr></thead><tbody></tbody></table>
<script>
const OWASP = """ + json.dumps({k: v.title for k, v in OWASP_LLM_TOP10.items()}) + """;
async function refresh(){
  const r = await fetch('/firewall/telemetry?limit=50');
  const d = await r.json();
  let kp = '';
  const ac = d.action_counts;
  ['allow','warn','block'].forEach(a=>{kp += `<div class=kpi><span class=${a}>${a.toUpperCase()}</span><b>${ac[a]||0}</b></div>`});
  document.getElementById('kpis').innerHTML = kp;
  let cb = '';
  for (const [c,n] of Object.entries(d.category_breakdown)) {
    cb += `<tr><td><code>${c}</code></td><td>${OWASP[c]||'-'}</td><td>${n}</td></tr>`;
  }
  document.querySelector('#cats tbody').innerHTML = cb;
  let ev = '';
  for (const e of d.events) {
    const t = new Date(e.ts*1000).toISOString().slice(11,19);
    ev += `<tr><td>${t}</td><td>${e.tenant_id}</td><td>${e.direction}</td><td class=${e.action}>${e.action}</td><td>${e.overall_score.toFixed(2)}</td><td>${e.top_category||'-'}</td><td><code>${(e.text_preview||'').slice(0,80).replace(/</g,'&lt;')}</code></td></tr>`;
  }
  document.querySelector('#events tbody').innerHTML = ev;
}
refresh();
setInterval(refresh, 3000);
</script></body></html>
"""


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> str:
    return DASHBOARD_HTML


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
