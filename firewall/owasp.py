"""OWASP LLM Top 10 (2025) categories and mappings."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OWASPCategory:
    code: str
    title: str
    description: str


OWASP_LLM_TOP10 = {
    "LLM01": OWASPCategory("LLM01", "Prompt Injection",
                           "Direct or indirect manipulation of LLM input to alter behavior."),
    "LLM02": OWASPCategory("LLM02", "Sensitive Information Disclosure",
                           "Exposure of PII, secrets, system prompts, or proprietary data."),
    "LLM03": OWASPCategory("LLM03", "Supply Chain",
                           "Compromised models, datasets, plugins, or pre-trained components."),
    "LLM04": OWASPCategory("LLM04", "Data and Model Poisoning",
                           "Manipulation of training/fine-tuning/embedding data."),
    "LLM05": OWASPCategory("LLM05", "Improper Output Handling",
                           "Insufficient validation/sanitization of LLM outputs (XSS, SSRF, RCE)."),
    "LLM06": OWASPCategory("LLM06", "Excessive Agency",
                           "LLM-driven systems with too much functionality/permissions/autonomy."),
    "LLM07": OWASPCategory("LLM07", "System Prompt Leakage",
                           "Exposure of system prompts revealing internal logic/credentials."),
    "LLM08": OWASPCategory("LLM08", "Vector and Embedding Weaknesses",
                           "Flaws in RAG: poisoned embeddings, retrieval injection, leakage."),
    "LLM09": OWASPCategory("LLM09", "Misinformation",
                           "Hallucinations, false outputs, dangerous overreliance."),
    "LLM10": OWASPCategory("LLM10", "Unbounded Consumption",
                           "Resource exhaustion: token floods, model DoS, wallet drain."),
}
