# Changelog

## [1.0.0] - 2026-09-22

Initial open-core release of the ZeroLLM AI Firewall.

### Features
- Reverse-proxy gateway for OpenAI-compatible LLM endpoints.
- Request / response / SSE-stream inspection with lookahead redaction and
  mid-stream blocking.
- Detection engine (custom cipher patterns + classifiers) covering prompt
  injection, jailbreak, indirect injection, credential & PII exfiltration.
- Policy engine: allow/block/redact/flag, confidence thresholds, tenant
  scoping, fail-open/fail-closed modes.
- Auth: none, api-key (sha-256 hashed), OIDC/JWT (JWKS), mTLS.
- Per-tenant rate limiting with optional Redis backend.
- Tamper-evident, optionally Ed25519-signed audit log with size rotation and
  multi-sink fan-out (file/stdout/http/s3).
- Prometheus metrics, OpenTelemetry tracing, structured JSON logging,
  telemetry endpoints, and a web dashboard.
- CLI: `proxy`, `config init|check|schema`, `keys hash`, `start`, `web`.
- Deployment: Dockerfile, Helm chart, Kubernetes manifest, docker-compose.
- CI/CD: lint + type + tests matrix, release pipeline with SBOM + signing.