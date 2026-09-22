# Observability & audit

## HTTP endpoints

| Endpoint | Purpose |
|----------|---------|
| `/healthz` | Liveness — always `{"status":"ok"}` |
| `/readyz` | Readiness — 503 until the upstream pool has at least one healthy target |
| `/metrics` | Prometheus text exposition |
| `/api/v1/telemetry` | JSON status: mode, uptime, routes, detector ids, upstream health |
| `/api/v1/proxies` | Upstream pool health per endpoint |

Not exposed on the public proxy path by default; place the control endpoints
behind a private network/ingress.

## Prometheus metrics

`zerollm_requests_total{route,status}`, `zerollm_blocks_total{phase}`,
`zerollm_attacks_blocked_total{detector}`, `zerollm_scrubbed_total{detector}`,
`zerollm_unauthorized_total`, `zerollm_rate_limited_total{tenant}`,
`zerollm_responses_total{route,status}`, `zerollm_client_errors_total`,
`zerollm_http_request_duration_seconds{route}`, plus audit counters.
Scrape with the included Helm `ServiceMonitor` or any Prometheus config.

## Structured logging

`logging.format: json` emits one JSON line per request with the request id,
route, tenant, decision action, detectors hit, latency, and response status.
A correlation `request_id` is set per request and echoed to upstreams as
`x-zerollm-request-id`.

## Tracing (OpenTelemetry)

```yaml
otel:
  enabled: true
  service_name: zerollm
  endpoint: http://otel-collector:4318
```

One span per proxy request (`zerollm.proxy`) with `http.route`,
`http.request_id`; upstream calls carry propagated trace headers
(`traceparent`).

## Tamper-evident audit log

Every security-relevant event (block, redact, flag, auth failure, rate limit)
is written to a hash-chained JSONL log:

```json
{"payload": {"event": "block", "severity": "critical", "details": {...}},
 "previous_hash": "<sha256 of prior record>",
 "record_hash": "<sha256 of this record>",
 "signature": "<ed25519 base64>", "signing_key": "<public PEM>"}
```

- **Chain integrity**: each `record_hash` covers `payload + previous_hash`.
  `verify_chain()` walks rotated backups too, so deletion or tampering of any
  record (or file) breaks the chain and is detected.
- **Signing**: generate `audit_signing_key.private.pem` with
  `scripts/audit-signing-keygen.sh`; set `audit.signing.private_key_file`.
  The public key can verify every record offline.
- **Rotation**: size-based (`max_bytes` / `max_files`). Because chaining
  requires the genesis record, keep `max_files` large enough that records are
  not evicted before SIEM/archive ingestion.
- **Sinks**: fan-out to `file` (default), `stdout`, `http` (Splunk HEC,
  Loki-compatible), or `s3`.

Verify a log offline:

```python
from zerollm.audit import ZeroLLMAuditLogger
assert ZeroLLMAuditLogger("zerollm_audit.jsonl").verify_chain()
assert ZeroLLMAuditLogger("zerollm_audit.jsonl").verify_chain(public_key_pem="...")
```

## Web dashboard

```bash
zerollm web --port 9494     # telemetry dashboard on localhost
```

The `web` server serves a read-only status page + the JSON telemetry and
metrics endpoints with a CSP-tightened, cookie-less response surface.