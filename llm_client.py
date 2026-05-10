"""Shared LLM client for all 5 projects. OpenAI-compatible.

Endpoint configured via env: LLM_BASE_URL, LLM_API_KEY, LLM_MODEL
Defaults to the provided endpoint.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any

import httpx

DEFAULT_BASE = "http://23.82.125.198:9440/v1"
DEFAULT_KEY = "grant-8e10fc68302653bd8415aaf0c00974fe8c909b8a1b2afbbf881dde21"
DEFAULT_MODEL = "glm-5.1"
DEFAULT_VISION_MODEL = "gemini-2.5-flash"


@dataclass
class LLMResponse:
    content: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    raw: dict[str, Any]
    latency_ms: int


class LLMClient:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.base_url = (base_url or os.environ.get("LLM_BASE_URL", DEFAULT_BASE)).rstrip("/")
        self.api_key = api_key or os.environ.get("LLM_API_KEY", DEFAULT_KEY)
        self.model = model or os.environ.get("LLM_MODEL", DEFAULT_MODEL)
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def chat(
        self,
        messages: list[dict[str, Any]],
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": model or self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if extra:
            payload.update(extra)
        t0 = time.time()
        r = self._client.post(
            f"{self.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            content=json.dumps(payload),
        )
        latency_ms = int((time.time() - t0) * 1000)
        r.raise_for_status()
        data = r.json()
        return LLMResponse(
            content=data["choices"][0]["message"]["content"],
            model=data.get("model", payload["model"]),
            prompt_tokens=data.get("usage", {}).get("prompt_tokens", 0),
            completion_tokens=data.get("usage", {}).get("completion_tokens", 0),
            raw=data,
            latency_ms=latency_ms,
        )

    def chat_simple(self, prompt: str, system: str | None = None, **kw: Any) -> str:
        msgs: list[dict[str, Any]] = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        return self.chat(msgs, **kw).content

    def embed(self, texts: list[str], model: str = "text-embedding-3-small") -> list[list[float]]:
        """Falls back to local hash-embedding if remote /embeddings missing."""
        try:
            r = self._client.post(
                f"{self.base_url}/embeddings",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"model": model, "input": texts},
            )
            if r.status_code == 200:
                return [d["embedding"] for d in r.json()["data"]]
        except Exception:
            pass
        # Local fallback (deterministic but not semantically meaningful)
        import hashlib
        out: list[list[float]] = []
        for t in texts:
            h = hashlib.sha256(t.encode()).digest()
            vec = [(b - 128) / 128.0 for b in h] * 12  # 384-dim
            out.append(vec[:384])
        return out

    def vision(self, prompt: str, image_url: str, model: str | None = None) -> str:
        return self.chat(
            [{
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": image_url}},
                ],
            }],
            model=model or DEFAULT_VISION_MODEL,
        ).content


_default_client: LLMClient | None = None


def get_client() -> LLMClient:
    global _default_client
    if _default_client is None:
        _default_client = LLMClient()
    return _default_client


if __name__ == "__main__":
    c = LLMClient()
    print("Model:", c.model)
    r = c.chat_simple("Reply with exactly: OK")
    print("Response:", r)
