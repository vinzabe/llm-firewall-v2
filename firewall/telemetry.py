"""Telemetry: persistent log of all decisions, queryable by OWASP category."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from threading import Lock


@dataclass
class FirewallEvent:
    request_id: str
    ts: float
    tenant_id: str
    direction: str  # 'inbound' or 'outbound'
    action: str    # 'allow', 'warn', 'block'
    overall_score: float
    top_category: str | None
    verdicts: list[dict]
    text_hash: str
    text_preview: str
    latency_ms: int
    model: str | None = None


class TelemetryStore:
    def __init__(self, path: str) -> None:
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = Lock()
        self._init()

    def _init(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""CREATE TABLE IF NOT EXISTS events(
                request_id TEXT PRIMARY KEY,
                ts REAL NOT NULL,
                tenant_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                action TEXT NOT NULL,
                overall_score REAL NOT NULL,
                top_category TEXT,
                verdicts_json TEXT NOT NULL,
                text_hash TEXT NOT NULL,
                text_preview TEXT NOT NULL,
                latency_ms INTEGER NOT NULL,
                model TEXT
            )""")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_tenant ON events(tenant_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_cat ON events(top_category)")
            self._conn.commit()

    def record(self, ev: FirewallEvent) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (
                ev.request_id, ev.ts, ev.tenant_id, ev.direction, ev.action,
                ev.overall_score, ev.top_category, json.dumps(ev.verdicts),
                ev.text_hash, ev.text_preview, ev.latency_ms, ev.model,
            ))
            self._conn.commit()

    def query(self, tenant_id: str | None = None, since: float = 0.0,
              limit: int = 100) -> list[dict]:
        with self._lock:
            cur = self._conn.cursor()
            sql = "SELECT * FROM events WHERE ts >= ?"
            args: list = [since]
            if tenant_id:
                sql += " AND tenant_id = ?"
                args.append(tenant_id)
            sql += " ORDER BY ts DESC LIMIT ?"
            args.append(limit)
            rows = cur.execute(sql, args).fetchall()
            cols = [d[0] for d in cur.description]
            out = []
            for r in rows:
                d = dict(zip(cols, r))
                d["verdicts"] = json.loads(d.pop("verdicts_json"))
                out.append(d)
            return out

    def category_breakdown(self, tenant_id: str | None = None,
                           since: float = 0.0) -> dict[str, int]:
        with self._lock:
            cur = self._conn.cursor()
            sql = "SELECT top_category, COUNT(*) FROM events WHERE ts >= ?"
            args: list = [since]
            if tenant_id:
                sql += " AND tenant_id = ?"
                args.append(tenant_id)
            sql += " GROUP BY top_category"
            return {r[0] or "none": r[1] for r in cur.execute(sql, args).fetchall()}

    def action_counts(self, tenant_id: str | None = None,
                      since: float = 0.0) -> dict[str, int]:
        with self._lock:
            cur = self._conn.cursor()
            sql = "SELECT action, COUNT(*) FROM events WHERE ts >= ?"
            args: list = [since]
            if tenant_id:
                sql += " AND tenant_id = ?"
                args.append(tenant_id)
            sql += " GROUP BY action"
            return {r[0]: r[1] for r in cur.execute(sql, args).fetchall()}
