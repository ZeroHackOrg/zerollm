# Configuration reference

Every knob lives in a single YAML file validated against the JSON schema at
`zerollm config schema`. Load order: file → environment-variable expansion
(`${VAR}` and `$VAR` are expanded) → validation → typed `Config`.

## Top level

| Key        | Type            | Details |
|------------|-----------------|---------|
| `schema`   | string          | Schema URL; optional but recommended. |
| `mode`     | `fail-open` / `fail-closed` | In `fail-closed`, a finding with **no** matching decision rule blocks the phase. In `fail-open`, it is flagged but allowed. Default `fail-closed`. |
| `server`   | object          | Listen host/port, TLS (cert/key), and limits (max body bytes, request timeout, SSE buffered bytes, graceful shutdown). |
| `auth`     | object          | `none`, `api-key`, `oidc`, or `mtls`. See [security.md](security.md). |
| `tenants`  | array           | Optional per-tenant id + sliding-window quotas (`rpm`, `rpd`, `tokens_per_min`). |
| `upstreams`| array           | LLM backends: `id`, `base_url`, `api_key_env`, `timeout_s`, `weight`, `verify_tls`, `circuit_breaker`. |
| `routes`   | array           | Map a path (+ methods) to ordered upstream ids and a policy. |
| `policies` | object          | Named policies keyed by id; `default` is used when a route omits `policy`. |
| `detectors`| array           | Optional external `llm_judge` detectors. |
| `audit`    | object          | Tamper-evident log: path, signing, rotation, sinks (file/stdout/http/s3). |
| `otel`     | object          | OpenTelemetry tracing (enabled, service_name, endpoint). |
| `redis`    | object          | Optional Redis-backed rate limiting / coordination (`ha` extra). |
| `logging`  | object          | `level` and `format` (`json` or `text`). |

## Decisions inside a policy

Each decision is one row of the policy matrix:

```yaml
policies:
  default:
    decisions:
      - id: block-injection          # decision id (appears in metrics/audit)
        action: block                # allow | block | redact | flag
        on: request                  # request | response | both | stream
        detector: prompt_injection
        min_confidence: 0.65         # only fire at/above this confidence
        tenants: ["*"]               # limit to tenants; default "*"
        replace_with: "[REDACTED]"   # only meaningful for action: redact
        reason: "prompt injection"
```

Precedence when multiple rules match a finding: **block > redact > flag > allow**.

> **YAML footgun:** PyYAML (and other YAML 1.1 parsers) treat an unquoted
> decision key `on:` as the boolean `True`. Always write `"on": request`.

## Environment expansion

Values like `"${OPENAI_API_KEY}"` are expanded from the process environment
before validation, so secrets never need to live in the YAML file:

```yaml
upstreams:
  - id: openai
    base_url: https://api.openai.com/v1
    api_key_env: OPENAI_API_KEY     # read at request time, never logged
```

## Startup validation

`load_config` fails fast on unknown keys (`additionalProperties: false`)
rather than silently ignoring typos — useful in CI:

```bash
zerollm config check config/prod.yaml
```