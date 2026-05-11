# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in **LLM Firewall v2**, please
report it privately. Do **not** open a public GitHub issue.

**Email:** security@vinzabe.dev (or open a GitHub Security Advisory)

Please include:
- A clear description of the issue
- Steps to reproduce (PoC preferred)
- The version / commit SHA you tested against
- Any suggested mitigation

We aim to acknowledge new reports within **72 hours** and to publish a
fix or mitigation within **30 days** for high-severity issues.

## Scope

In scope:
- Bypass of any OWASP LLM Top 10 detector (LLM01..LLM10)
- Authentication / authorization issues on the proxy endpoint
- PII redaction failures (data leakage to upstream LLM or in responses)
- Telemetry / dashboard XSS, SQLi, path-traversal
- Tenant policy isolation breaks
- DoS vectors against the proxy

Out of scope:
- Issues that require attacker control of the upstream LLM endpoint
- Issues that require root on the host running the firewall
- Adversarial-prompt research that defeats *all* known LLM defenses
  (please publish responsibly via standard academic channels)

## Threat model

The firewall sits **between** an untrusted client and a trusted upstream
LLM. We assume:

- The client is untrusted (may be an attacker)
- The upstream LLM is trusted but **may produce harmful output**
  (jailbroken, hallucinated, leaked secrets) — outbound scan exists for this
- The host running the firewall is trusted
- TLS termination happens upstream of this process (run behind nginx /
  Cloudflare / a load balancer for production)

## Hardening checklist for production deployments

- [ ] Run behind TLS (terminator + valid cert)
- [ ] Set `LLM_API_KEY` via secret-store, not env file in repo
- [ ] Mount `data/` on a non-root filesystem with appropriate quotas
- [ ] Rate-limit the public proxy endpoint at the edge
- [ ] Set `--workers` to match CPU count, not 1
- [ ] Enable upstream timeout (`HTTPX_TIMEOUT` env var)
- [ ] Pin `policies/*.yaml` via config-management; do not allow live edits
      without audit
- [ ] Forward telemetry SQLite to a SIEM (or replace with Postgres)
- [ ] Restrict `/dashboard` and `/firewall/policies/*` to operator IPs

## Supply chain

- All Python deps are pinned via `requirements.txt`
- Recommended: install with `pip install --require-hashes -r requirements.lock`
- The shared `llm_client.py` is vendored (not a third-party package)

## Contact

Responsible disclosure: **g@abejar.net**
