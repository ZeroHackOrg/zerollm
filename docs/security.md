# Security hardening & threat model

This is a summary for operators. For detector details see
[policy.md](policy.md); for the config schema see [configuration.md](configuration.md).

## Supported auth modes

| Mode | How it works |
|------|--------------|
| `none` | No gateway auth — use only on trusted/VPC networks. |
| `api-key` | Static keys. ZeroLLM stores only `sha256:<hex>` digests; distribute keys with `scripts/keygen.sh`. |
| `oidc` | Validate JWT Bearer tokens against issuer + audience via JWKS; map `roles_claim`/`tenant_claim` to tenants and scopes. |
| `mtls` | Client-certificate auth against `auth.mtls.ca_cert_file`. |

Secrets never appear in config files: reference them via `api_key_env` /
`${VAR}` expansion, which are read from the environment and excluded from
request forwarding and logging.

## What ZeroLLM protects against

- **Prompt injection** (direct + indirect) and **jailbreaks** (DAN, etc.).
- **Exfiltration of credentials/PII** in upstream responses — both buffered
  responses and live **SSE token streams** (redact or block mid-stream via the
  lookahead window before harmful text reaches the client).
- **System-prompt reveal**, **SQL/code execution** requests.
- **Rule bypass** — `fail-closed` default means an unmatched finding still
  blocks, so *new/unknown* detector categories cannot be smuggled past.

## Built-in hardening

- Request/response size caps (`max_body_bytes`, `max_sse_buffered_bytes`),
  request timeouts, and graceful shutdown.
- `Content-Security-Policy` header on the status/dashboard responses; no
  wildcard CORS.
- Hop-by-hop headers (`host`, `transfer-encoding`, `proxy-authorization`, …)
  are stripped before forwarding; the internal `zerollm.request_id` header is
  not leaked upstream.
- Structured JSON logging records request ids, route, tenant, outcome — but
  **never** the raw body (no secrets in logs).
- Rendered Docker image: non-root uid/geet 1001, read-only rootfs,
  `cap_drop: ALL`, no shell tooling exposed; Helm sets a seccomp profile.

## Operational threat model assumptions

1. The machine running ZeroLLM is trusted (keys in env, signing keys on disk).
2. TLS is terminated at the edge or via `server.tls`; use `auth.mtls` for
   client certs. Data in transit is not inspected (it is piped through).
3. LLM responses are untrusted *by definition* — everything from an
   upstream is scanned before the client receives it.
4. The audit chain guarantees **detection** of tampering, not prevention;
   archive signed logs off-box, and keep enough rotation capacity that
   records survive until archived (`verify_chain()` requires the genesis).

## Checklist before production

- [ ] `mode: fail-closed` (default) and decisions cover every detector you care about
- [ ] `auth.mode` set; API keys hashed; OIDC/mTLS terminated before the proxy
- [ ] upstream keys injected via env (not committed)
- [ ] audit enabled, signed, rotated, shipped to SIEM/S3
- [ ] `/metrics` and `/api/v1/*` restricted to a private network/ingress
- [ ] CI runs `zerollm config check` on the config, `pip-audit` on deps
- [ ] verified the SSE stream policy with `zerollm start` simulator

## Test your deployment

```bash
zerollm start    # fires representative payloads through the demo firewall
```

Curl a canonical attack and confirm a 403 JSON body (see
[quickstart.md](quickstart.md) step 4).