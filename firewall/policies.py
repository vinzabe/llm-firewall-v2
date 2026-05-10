"""Per-tenant adaptive policy engine."""
from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from typing import Any

import yaml


@dataclass
class Policy:
    tenant_id: str
    name: str = "default"
    block_threshold: float = 0.75
    warn_threshold: float = 0.4
    # Per-category weights (multiply detector scores)
    category_weights: dict[str, float] = field(default_factory=lambda: {
        "LLM01": 1.0, "LLM02": 1.0, "LLM05": 1.0, "LLM07": 0.7, "LLM10": 0.6,
    })
    # Detectors enabled
    enabled_detectors: list[str] = field(default_factory=lambda: [
        "heuristic_injection", "pii_scanner", "output_handler",
        "consumption", "system_prompt_leak",
    ])
    use_llm_judge: bool = True
    llm_judge_threshold: float = 0.4  # only escalate ambiguous
    # Adaptive learning
    adaptive: bool = True
    learning_rate: float = 0.05
    # Allow/deny patterns (regex strings)
    allowlist: list[str] = field(default_factory=list)
    denylist: list[str] = field(default_factory=list)
    # Rate limiting
    max_requests_per_min: int = 120
    max_tokens_per_min: int = 50_000

    def to_dict(self) -> dict:
        return asdict(self)


class PolicyStore:
    def __init__(self, path: str) -> None:
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._init()

    def _init(self) -> None:
        cur = self._conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS policies(
            tenant_id TEXT PRIMARY KEY,
            policy_json TEXT NOT NULL,
            updated_at REAL NOT NULL
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS feedback(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            label TEXT NOT NULL,
            text TEXT,
            ts REAL NOT NULL
        )""")
        self._conn.commit()

    def get(self, tenant_id: str) -> Policy:
        cur = self._conn.cursor()
        row = cur.execute(
            "SELECT policy_json FROM policies WHERE tenant_id=?", (tenant_id,),
        ).fetchone()
        if row:
            d = json.loads(row[0])
            return Policy(**d)
        p = Policy(tenant_id=tenant_id)
        self.put(p)
        return p

    def put(self, policy: Policy) -> None:
        cur = self._conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO policies(tenant_id, policy_json, updated_at) VALUES (?,?,?)",
            (policy.tenant_id, json.dumps(policy.to_dict()), time.time()),
        )
        self._conn.commit()

    def record_feedback(self, tenant_id: str, request_id: str, label: str, text: str = "") -> None:
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO feedback(tenant_id, request_id, label, text, ts) VALUES (?,?,?,?,?)",
            (tenant_id, request_id, label, text, time.time()),
        )
        self._conn.commit()

    def list_tenants(self) -> list[str]:
        cur = self._conn.cursor()
        return [r[0] for r in cur.execute("SELECT tenant_id FROM policies").fetchall()]

    def feedback_stats(self, tenant_id: str) -> dict[str, int]:
        cur = self._conn.cursor()
        rows = cur.execute(
            "SELECT label, COUNT(*) FROM feedback WHERE tenant_id=? GROUP BY label",
            (tenant_id,),
        ).fetchall()
        return {r[0]: r[1] for r in rows}


def load_yaml_policy(path: str) -> Policy:
    with open(path) as f:
        d = yaml.safe_load(f)
    return Policy(**d)
