"""Self-tuning detector: learns thresholds from production feedback."""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Deque


@dataclass
class TrafficStat:
    ts: float
    score: float
    blocked: bool
    label: str | None = None  # 'fp' (false positive), 'tp' (true positive), 'fn', 'tn', or None


@dataclass
class AdaptiveLearner:
    """Online learner that adjusts thresholds based on FP/FN feedback.

    Strategy:
    - Track rolling FP & FN rates per tenant.
    - If FP rate > target: raise block_threshold (be less strict).
    - If FN rate > target: lower block_threshold (be more strict).
    - Bounded between [0.3, 0.95].
    """
    window_size: int = 1000
    target_fp_rate: float = 0.05
    target_fn_rate: float = 0.02
    min_threshold: float = 0.3
    max_threshold: float = 0.95
    history: Deque[TrafficStat] = field(default_factory=lambda: deque(maxlen=1000))
    lock: Lock = field(default_factory=Lock)

    def record(self, score: float, blocked: bool, label: str | None = None) -> None:
        with self.lock:
            self.history.append(TrafficStat(time.time(), score, blocked, label))

    def label_last(self, request_id_score: float, label: str) -> None:
        """Mark the most recent matching score as fp/tp/fn/tn."""
        with self.lock:
            for s in reversed(self.history):
                if abs(s.score - request_id_score) < 1e-6 and s.label is None:
                    s.label = label
                    return

    def update_threshold(self, current: float) -> float:
        with self.lock:
            labeled = [s for s in self.history if s.label is not None]
            if len(labeled) < 20:
                return current
            fps = sum(1 for s in labeled if s.label == "fp")
            fns = sum(1 for s in labeled if s.label == "fn")
            n = len(labeled)
            fp_rate = fps / n
            fn_rate = fns / n
            new = current
            if fp_rate > self.target_fp_rate:
                new += 0.02 * (fp_rate - self.target_fp_rate) / max(self.target_fp_rate, 0.01)
            if fn_rate > self.target_fn_rate:
                new -= 0.05 * (fn_rate - self.target_fn_rate) / max(self.target_fn_rate, 0.01)
            return max(self.min_threshold, min(self.max_threshold, new))

    def stats(self) -> dict:
        with self.lock:
            n = len(self.history)
            blocked = sum(1 for s in self.history if s.blocked)
            labeled = [s for s in self.history if s.label]
            tps = sum(1 for s in labeled if s.label == "tp")
            fps = sum(1 for s in labeled if s.label == "fp")
            fns = sum(1 for s in labeled if s.label == "fn")
            tns = sum(1 for s in labeled if s.label == "tn")
            precision = tps / max(tps + fps, 1)
            recall = tps / max(tps + fns, 1)
            return {
                "total": n,
                "blocked": blocked,
                "labeled": len(labeled),
                "true_positive": tps,
                "false_positive": fps,
                "false_negative": fns,
                "true_negative": tns,
                "precision": round(precision, 3),
                "recall": round(recall, 3),
            }
