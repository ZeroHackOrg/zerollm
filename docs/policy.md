# Policies & detectors

## Detection pipeline

1. **Request phase** — the JSON body is traversed (nested messages, system
   prompts, tool calls, content blocks, custom fields) and every string chunk
   is scanned. A detected span is reported with `detector`, `severity`,
   `confidence`, and character offsets.
2. **Policy decision** — findings are passed to the policy engine, which
   returns one action: `allow`, `block`, `redact`, or `flag`.
3. **Response phase (non-stream)** — the same scanning runs over the upstream
   JSON response before it is forwarded.
4. **Stream phase** — SSE `chat.completion.chunk` deltas are reassembled into
   running assistant text inside a **lookahead window** (default 64 KB of
   buffered content). Deltas are held back until a decision commits, which
   lets ZeroLLM:
   - **redact** tokens that already left the upstream (per-delta rewriting), or
   - **block mid-stream** before any harmful token is flushed to the client.

## Detector catalogue

Built-in detectors (list at runtime via `zerollm config check` / telemetry):

| Detector                 | Severity  | What it finds |
|--------------------------|-----------|---------------|
| `prompt_injection`       | critical  | "Ignore previous instructions…", system-prompt reveal attempts |
| `prompt_injection_low`   | low       | weak/ambiguous injection signals |
| `dan_jailbreak`          | critical  | "DAN", "do anything now", unfiltered-access jailbreaks |
| `indirect_injection`     | medium    | instructions embedded in quoted/external content ("Ignore your rules…") |
| `code_execution_shell`   | high      | `os.system`, `subprocess`, bash eval requests |
| `sql_injection_ext`      | high      | SQL keywords in prompts |
| `secret_openai`          | critical  | `sk-…` OpenAI keys |
| `secret_aws`             | critical  | `AKIA…` AWS access keys |
| `secret_google`          | critical  | Google/GCP service-account keys |
| `secret_github`          | critical  | GitHub personal access tokens |
| `secret_bearer`          | critical  | generic bearer tokens |
| `secret_jwt`             | critical  | `eyJ…` JWTs (header+payload+signature) |
| `secret_private_key`     | critical  | PEM private keys (PKCS#1 / PKCS#8 / EC) |
| `pii_credit_card`        | high      | **Luhn-validated** card numbers |
| `pii_email`              | low       | email addresses |
| `pii_ssn`                | critical  | US Social Security numbers |
| `pii_phone`              | low       | phone numbers |
| `pii_ip`                 | low       | IP literals |
| `secret_generic_password`| medium    | `password=…` assignments |

External `llm_judge` detectors extend this with model-based classification,
fused into the same policy engine (severity/confidence + decision table).

## Decision precedence

For a single finding, the strongest matched rule wins:

```
block  >  redact  >  flag  >  allow
```

## Fail-open vs fail-closed

- **fail-closed** (default): any finding that matches NO decision (including a
  detector you did not write a rule for) **blocks** the request/response.
- **fail-open**: unmatched findings are flagged and traffic continues. Use
  during rollout/tuning, then switch.

Unhandled *server* exceptions also follow the mode — fail-closed returns 500
rather than leaking a traceback.

## Redaction model

`action: redact` replaces matched spans with `replace_with` per detector.
Because redaction is span-based, a single rewrite can also hide PII embedded
in otherwise benign text. Redacted JSON preserves structure (paths are
re-applied via `jsonutil.apply_redaction`), so downstream parsing never breaks.