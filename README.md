# ZeroLLM — AI Firewall & Prompt Injection Sandbox

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](#)
[![Python](https://img.shields.io/badge/python-3.9%20|%203.10%20|%203.11%20|%203.12%20|%203.13%20|%203.14-blue)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#)

**ZeroLLM is a reverse-proxy AI firewall.** It sits in front of any
OpenAI-compatible LLM endpoint and inspects *every* request and response —
including live SSE token streams — for prompt injection, jailbreaks, and
credential/PII exfiltration, then blocks, redacts, or flags per your policy.

Engineered by **[ZeroHack.org](https://zerohack.org)**.

## Why

Your model provider's safety layers only run *before* the model. Nothing stops
the model from writing secrets back to you, and nothing stops a prompt-
injection in retrieved context from overriding your system prompt. ZeroLLM
enforces a zero-trust DLP boundary around your model traffic:

- **Request inspection** — scans nested JSON (system prompts, messages, tool
  args) for injections and secrets *before* upstream.
- **Response inspection** — buffers JSON responses, and for SSE streaming uses
  a **lookahead window** to redact dangerous tokens or **kill the stream
  mid-flight** before harmful text reaches the client.
- **Policy engine** — per-detector decisions (`block` / `redact` / `flag` /
  `allow`) with `fail-closed` by default, tenant scoping, and confidence
  thresholds.
- **Full auditability** — hash-chained, optionally **Ed25519-signed** JSONL
  audit log that survives rotation (`verify_chain()`).
- **Haardenable** — API-key (hashed), OIDC/JWT, and mTLS auth; Redis-backed
  per-tenant quotas; OpenTelemetry tracing; Prometheus metrics.

## Install

```bash
pip install zerollm
pip install "zerollm[otel]"   # OpenTelemetry tracing
pip install "zerollm[ha]"     # Redis rate limiting / HA
pip install "zerollm[s3]"     # audit records to S3
```

## Quickstart

```bash
zerollm config init --output zerollm.yaml    # generate a valid default
zerollm config check zerollm.yaml            # validate (great for CI)
export OPENAI_API_KEY=sk-...
zerollm proxy --config zerollm.yaml
```

Point your existing SDK at ZeroLLM instead of the provider:

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8080/v1")
```

A prompt-injection request is now rejected:

```json
{"error": {"message": "zerollm blocked request (prompt_injection)", "type": "zerollm_error"}}
```

Run the built-in attack simulator:

```bash
zerollm start
```

## Feature matrix

| Area | Capability |
|------|-----------|
| **Proxy core** | Weighted multi-upstream pool, circuit breakers, timeouts, TLS, graceful shutdown, route/method mapping |
| **Detection** | 20+ detectors: prompt injection, DAN/indirect jailbreaks, SQL/code-exec, `sk-`/AWS/GitHub/JWT/bearer/private-key secrets, Luhn-validated cards, SSN/email/phone/IP, passwords; optional external `llm_judge` |
| **Streaming (SSE)** | Token reassembly, lookahead redaction, mid-stream block, `[DONE]` handling |
| **Policy** | per-detector block/redact/flag/allow, confidence, tenants, fail-open/closed, redaction precedence |
| **Auth** | none / api-key (hashed) / OIDC (JWKS) / mTLS |
| **Rate limits** | in-memory or Redis-backed rpm/rpd/tokens-per-min per tenant |
| **Audit** | hash-chain + Ed25519 signing, size rotation, sinks (file/stdout/HTTP/S3), multi-file `verify_chain` |
| **Observability** | `/healthz` `/readyz` `/metrics` `/api/v1/telemetry`, JSON logs, OpenTelemetry spans, attest dashboard (`zerollm web`) |
| **CLI** | `proxy`, `config init/check/schema`, `keys hash`, `start` (demo), `web` (dashboard) |
| **Deploy** | Docker (distroless-ish, non-root, hardy probes), Helm chart (HPA/PDB/ServiceMonitor/secrets), Kubernetes manifests, Compose |
| **Supply chain** | CI lint/type/test across Python versions, `pip-audit`, SBOM (SPDX) + signing on release |

## Documentation

- [Quickstart](docs/quickstart.md)
- [Configuration reference](docs/configuration.md)
- [Policies & detectors](docs/policy.md)
- [Deployment (Docker / Helm / K8s)](docs/deployment.md)
- [Observability & audit](docs/observability.md)
- [Security hardening](docs/security.md)
- [Changelog](CHANGELOG.md)

## Development

```bash
pip install -e '.[dev]'
pytest                     # unit + integration (aiohttp in-process servers)
ruff check src tests && ruff format --check src tests
mypy src/zerollm
```

## License

MIT / ZeroHack Commercial. `solutions@zerohack.org`.