"""Firewall engine: scans inbound/outbound text, applies policy, records telemetry."""
from __future__ import annotations

import hashlib
import re
import time
import uuid
from dataclasses import dataclass

from .detectors import (
    ConsumptionDetector,
    HeuristicInjectionDetector,
    LLMJudgeDetector,
    OutputHandlingDetector,
    PIIDetector,
    SystemPromptLeakDetector,
    aggregate,
)
from .learner import AdaptiveLearner
from .policies import Policy, PolicyStore
from .telemetry import FirewallEvent, TelemetryStore


@dataclass
class FirewallDecision:
    request_id: str
    action: str          # 'allow', 'warn', 'block'
    overall_score: float
    top_category: str | None
    verdicts: list[dict]
    latency_ms: int
    blocked_reason: str | None = None
    redacted_text: str | None = None  # if PII auto-redacted

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "action": self.action,
            "overall_score": round(self.overall_score, 4),
            "top_category": self.top_category,
            "verdicts": self.verdicts,
            "latency_ms": self.latency_ms,
            "blocked_reason": self.blocked_reason,
            "redacted_text": self.redacted_text,
        }


class FirewallEngine:
    def __init__(
        self,
        policy_store: PolicyStore,
        telemetry: TelemetryStore,
        llm_client=None,
    ) -> None:
        self.policies = policy_store
        self.telemetry = telemetry
        self.llm = llm_client
        self.learners: dict[str, AdaptiveLearner] = {}
        # Pre-built detectors (stateless, safe to share)
        self._detectors = {
            "heuristic_injection": HeuristicInjectionDetector(),
            "pii_scanner": PIIDetector(),
            "output_handler": OutputHandlingDetector(),
            "consumption": ConsumptionDetector(),
            "system_prompt_leak": SystemPromptLeakDetector(),
        }
        self._judge = LLMJudgeDetector(llm_client) if llm_client else None

    def _learner(self, tenant_id: str) -> AdaptiveLearner:
        if tenant_id not in self.learners:
            self.learners[tenant_id] = AdaptiveLearner()
        return self.learners[tenant_id]

    def scan(
        self,
        text: str,
        tenant_id: str = "default",
        direction: str = "inbound",
        model: str | None = None,
    ) -> FirewallDecision:
        t0 = time.time()
        request_id = uuid.uuid4().hex[:16]
        policy = self.policies.get(tenant_id)

        # Quick allow/deny lists
        for pat in policy.denylist:
            if re.search(pat, text, re.IGNORECASE):
                latency = int((time.time() - t0) * 1000)
                decision = FirewallDecision(
                    request_id, "block", 1.0, "LLM01",
                    [{"detector": "denylist", "category": "LLM01", "score": 1.0,
                      "matched": [pat[:60]], "explanation": "matched tenant denylist"}],
                    latency, blocked_reason=f"denylist_match:{pat[:30]}",
                )
                self._record(decision, tenant_id, direction, text, model)
                return decision

        for pat in policy.allowlist:
            if re.search(pat, text, re.IGNORECASE):
                latency = int((time.time() - t0) * 1000)
                decision = FirewallDecision(
                    request_id, "allow", 0.0, None,
                    [{"detector": "allowlist", "category": "ALLOW",
                      "score": 0.0, "matched": [pat[:60]],
                      "explanation": "matched tenant allowlist"}],
                    latency,
                )
                self._record(decision, tenant_id, direction, text, model)
                return decision

        # Run enabled detectors
        verdicts = []
        for name in policy.enabled_detectors:
            det = self._detectors.get(name)
            if det is None:
                continue
            v = det.scan(text)
            # Apply tenant category weight
            w = policy.category_weights.get(v.category, 1.0)
            v.score = min(1.0, v.score * w)
            verdicts.append(v)

        overall, ranked = aggregate(verdicts)

        # LLM judge escalation only when ambiguous
        if (
            self._judge is not None
            and policy.use_llm_judge
            and direction == "inbound"
            and policy.llm_judge_threshold <= overall < policy.block_threshold
        ):
            jv = self._judge.scan(text)
            verdicts.append(jv)
            overall, ranked = aggregate(verdicts)

        # Adaptive threshold
        learner = self._learner(tenant_id)
        block_thresh = policy.block_threshold
        if policy.adaptive:
            block_thresh = learner.update_threshold(block_thresh)

        # Decide action
        if overall >= block_thresh:
            action = "block"
            reason = ranked[0].explanation if ranked else "high overall score"
        elif overall >= policy.warn_threshold:
            action = "warn"
            reason = None
        else:
            action = "allow"
            reason = None

        # Auto-redact PII on outbound if configured
        redacted: str | None = None
        if direction == "outbound" and any(
            v.category == "LLM02" and v.score > 0.5 for v in verdicts
        ):
            redacted = self._redact_pii(text)

        latency = int((time.time() - t0) * 1000)
        decision = FirewallDecision(
            request_id=request_id,
            action=action,
            overall_score=overall,
            top_category=ranked[0].category if ranked else None,
            verdicts=[v.to_dict() for v in verdicts],
            latency_ms=latency,
            blocked_reason=reason,
            redacted_text=redacted,
        )
        learner.record(overall, action == "block")
        self._record(decision, tenant_id, direction, text, model)
        return decision

    def _record(
        self,
        decision: FirewallDecision,
        tenant_id: str,
        direction: str,
        text: str,
        model: str | None,
    ) -> None:
        ev = FirewallEvent(
            request_id=decision.request_id,
            ts=time.time(),
            tenant_id=tenant_id,
            direction=direction,
            action=decision.action,
            overall_score=decision.overall_score,
            top_category=decision.top_category,
            verdicts=decision.verdicts,
            text_hash=hashlib.sha256(text.encode()).hexdigest()[:16],
            text_preview=text[:200],
            latency_ms=decision.latency_ms,
            model=model,
        )
        self.telemetry.record(ev)

    def feedback(self, tenant_id: str, request_id: str, label: str) -> None:
        """Record FP/FN/TP/TN for adaptive learning."""
        self.policies.record_feedback(tenant_id, request_id, label)
        # Also update in-memory learner
        events = self.telemetry.query(tenant_id=tenant_id, limit=500)
        for ev in events:
            if ev["request_id"] == request_id:
                self._learner(tenant_id).label_last(ev["overall_score"], label)
                break

    @staticmethod
    def _redact_pii(text: str) -> str:
        from .detectors import PII_PATTERNS
        out = text
        for pat, label, _ in PII_PATTERNS:
            out = re.sub(pat, f"[REDACTED:{label}]", out)
        return out
