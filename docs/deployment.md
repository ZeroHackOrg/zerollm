# Deployment

ZeroLLM is a pure-Python asyncio (aiohttp) service. Run it directly, in
Docker, on Kubernetes, or behind any L4/L7 load balancer.

## Direct

```bash
pip install zerollm
zerollm proxy --config zerollm.yaml
```

## Docker

```bash
docker build -t zerollm .
docker run --rm -p 8080:8080 \
  -v "$PWD/zerollm.yaml:/etc/zerollm/zerollm.yaml:ro" \
  -e OPENAI_API_KEY=sk-... \
  zerollm
```

The image runs as UID 1001, has a healthcheck on `/healthz`, and ships extras
(`otel ha s3`) by default. Build with specific extras:

```bash
docker build --build-arg ZEROLM_EXTRAS="" -t zerollm .
```

## Docker Compose

See [examples/docker-compose.yml](../examples/docker-compose.yml) — boots
ZeroLLM with Redis (HA rate limiting) and mounts the example config.

## Kubernetes

### Helm chart

```bash
helm repo add zerohack https://zerohack.org/charts   # or: local chart
helm install zerollm deploy/helm/zerollm \
  --set config.contents="$(cat zerollm.yaml | sed 's/^/  /')" \
  --set-json upstreams='[{"id":"openai","base_url":"https://api.openai.com/v1","key":"sk-...","apiKeyEnv":"OPENAI_API_KEY"}]'
```

Chart features:

- ConfigMap holds `zerollm.yaml` (verbatim, no YAML-1.1 pitfalls).
- Secrets hold upstream keys + optional Ed25519 audit-signing PEM.
- Hardened PodSecurityContext (non-root, RO rootfs, `ALL` capabilities
  dropped), liveness/readiness probes, optional HPA + PDB + ServiceMonitor.

### Manifest (no Helm)

See [examples/k8s/zerollm.yaml](../examples/k8s/zerollm.yaml).

## Horizontal scaling

- Stateless per-instance; the pool routes by configured weights.
- `zerollm[ha]` + `redis.enabled=true` shares rate-limit counters across
  replicas. Without Redis each replica enforces its own quotas.
- Keep the audit log path on shared/persisted storage (or use the `http` /
  `s3` audit sinks) if multiple replicas write it.

## TLS

Terminate TLS at the edge (ingress/ALB) or set `server.tls` (PEM cert/key)
for end-to-end. mTLS in front of upstreams is supported via `auth.mtls`.

## Upstream health & circuit breaking

Each upstream has an optional circuit breaker (`max_failures`, `cooldown_s`,
`threshold`). `pool.status()` (exposed at `/api/v1/telemetry`) shows per-
upstream health; if every upstream is open you get a 502 JSON error, and
`/readyz` stays 503 until at least one upstream is usable.