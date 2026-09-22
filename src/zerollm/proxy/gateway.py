"""ZeroLLM HTTP gateway: the real reverse-proxy firewall.

Inspects requests and responses (streaming-aware), enforces policy, applies
auth/quota, routes across healthy upstreams with weighted load balancing and
circuit breakers, and emits Prometheus metrics + OTel traces + audit events.
"""

from __future__ import annotations

import asyncio
import json
import signal
import ssl
import time
import uuid
from contextlib import suppress
from functools import partial
from typing import List, Optional, Tuple

from aiohttp import web
from aiohttp.client import ClientResponse
from aiohttp.web_middlewares import middleware

from ..audit import ZeroLLMAuditLogger
from ..auth import Authenticator, UnauthorizedError, upstream_auth_headers
from ..config import Config, RouteConfig, UpstreamConfig
from ..detect.engine import DetectionEngine, Finding
from ..detect.judge import LLMJudge
from ..log import clear_request_context, get_logger, set_request_context
from ..metrics import DEFAULT_METRICS
from ..policy import PolicyDecision, PolicyEngine
from ..quotas import QuotaStore
from ..trace import get_tracer
from . import jsonutil
from .pool import UpstreamPool
from .sse import SSEBlocked, SSEStreamInspector

_log = get_logger("gateway")

REDACTED_BODY_LEN = 240
ERROR_CONTENT_TYPE = "application/json"


class RequestError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class ZeroLLMHTTPGateway:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.engine = self._build_engine(config)
        self.policy_engine = PolicyEngine(config, known_detectors=self.engine.detector_ids())
        self.audit = ZeroLLMAuditLogger(config=config.audit) if config.audit.enabled else None
        self.quotas = QuotaStore(config.redis)
        self.auth = Authenticator(config.auth, [t.id for t in config.tenants])
        self.tracer = get_tracer()
        self.pool = UpstreamPool(config)
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self._started_at = time.time()
        self._ready = False
        self.app = self._build_app()

    # -- construction ---------------------------------------------------------
    @staticmethod
    def _build_engine(config: Config) -> DetectionEngine:
        judges = [
            LLMJudge(
                detector_id=d.id,
                endpoint=d.endpoint,
                api_key_env=d.api_key_env,
                model=d.model,
                threshold=d.threshold,
                timeout_s=d.timeout_s,
            )
            for d in config.detectors
            if d.type == "llm_judge" and d.endpoint
        ]
        return DetectionEngine(judges=judges)

    def _build_app(self) -> web.Application:
        app = web.Application(middlewares=[self._middleware])
        app["zerollm.gateway"] = self
        for route in self.config.routes:
            for method in route.methods:
                app.router.add_route(method, route.path, partial(self._proxy_handler, route=route))
        app.router.add_get("/healthz", self._healthz)
        app.router.add_get("/livez", self._healthz)
        app.router.add_get("/readyz", self._readyz)
        app.router.add_get("/metrics", self._metrics)
        app.router.add_get("/api/v1/telemetry", self._telemetry)
        app.router.add_get("/api/v1/upstreams", self._upstreams_status)
        app.router.add_get("/", self._index)
        return app

    # -- lifecycle ------------------------------------------------------------
    async def start(self, host: str, port: int) -> None:
        self._runner = web.AppRunner(self.app, access_log=None)
        await self._runner.setup()
        ssl_context = None
        if self.config.server.tls.enabled:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.config.server.tls.cert_file, self.config.server.tls.key_file)
            if self.auth.mode == "mtls" and self.config.auth.mtls.ca_cert_file:
                context.load_verify_locations(cafile=self.config.auth.mtls.ca_cert_file)
                context.verify_mode = ssl.CERT_REQUIRED
            ssl_context = context
        self._site = web.TCPSite(self._runner, host, port, ssl_context=ssl_context)
        await self._site.start()
        self._ready = True
        _log.info("zerollm proxy listening", extra={"event": "server_start", "host": host, "port": port})

    async def stop(self) -> None:
        self._ready = False
        await self.quotas.aclose()
        await self.pool.close()
        if self._runner is not None:
            await self._runner.cleanup()
        _log.info("zerollm proxy stopped", extra={"event": "server_stop"})

    # -- public endpoints -------------------------------------------------------
    async def _healthz(self, request: web.Request) -> web.Response:
        return web.json_response({"status": "ok", "service": "zerollm"})

    async def _readyz(self, request: web.Request) -> web.Response:
        if not self._ready:
            return web.json_response({"status": "not_ready"}, status=503)
        return web.json_response({"status": "ready", "uptime_s": int(time.time() - self._started_at)})

    async def _metrics(self, request: web.Request) -> web.Response:
        return web.Response(body=DEFAULT_METRICS.prometheus_text(), content_type="text/plain")

    async def _telemetry(self, request: web.Request) -> web.Response:
        if self.auth.mode != "none":
            context = await self.auth.authenticate_async(request)
            if not context.authenticated:
                raise UnauthorizedError("credentials required for telemetry")
        return web.json_response(
            {
                "engine": "ZeroLLM",
                "mode": self.config.mode,
                "uptime_s": int(time.time() - self._started_at),
                "metrics": DEFAULT_METRICS.snapshot(),
                "routes": [
                    {"path": r.path, "upstreams": r.upstreams, "policy": r.policy} for r in self.config.routes
                ],
                "detectors": self.engine.detector_ids(),
            }
        )

    async def _upstreams_status(self, request: web.Request) -> web.Response:
        return web.json_response(self.pool.status())

    async def _index(self, request: web.Request) -> web.Response:
        body = (
            "<html><body style='font-family:monospace;background:#050b0f;color:#00ffcc;padding:30px'>"
            "<h1>ZeroLLM // Reverse Proxy Firewall</h1>"
            "<p><a href='/readyz'>/readyz</a></p>"
            "<p><a href='/metrics'>/metrics</a></p>"
            "<p><a href='/api/v1/telemetry'>/api/v1/telemetry</a></p>"
            "</body></html>"
        )
        return web.Response(body=body, content_type="text/html")

    # -- middleware ---------------------------------------------------------------
    @middleware
    async def _middleware(self, request: web.Request, handler):
        start = time.perf_counter()
        route = (
            request.match_info.route.resource.canonical if request.match_info.route.resource else request.path
        )
        request_id = set_request_context(uuid.uuid4().hex, route=route)
        request["zerollm.request_id"] = request_id
        status = 200
        try:
            with self.tracer.span(
                "zerollm.proxy", attributes={"http.route": route, "http.request_id": request_id}
            ):
                response = await handler(request)
                status = response.status
            return response
        except UnauthorizedError as error:
            status = error.status
            self._count("unauthorized_total", 1, {"route": route})
            return self._error(status, error.args[0] if error.args else "unauthorized")
        except RequestError as error:
            status = error.status
            self._count("client_errors_total", 1, {"route": route, "code": str(status)})
            return self._error(status, error.message)
        except web.HTTPException:
            raise
        except Exception:  # last-resort: fail closed/open per mode
            status = 500
            _log.exception("unhandled proxy error", extra={"event": "proxy_error", "route": route})
            if self.config.mode == "fail-closed":
                return self._error(500, "zerollm upstream error")
            raise
        finally:
            elapsed = time.perf_counter() - start
            DEFAULT_METRICS.observe_latency("http_request_duration_seconds", elapsed, {"route": route})
            self._count("requests_total", 1, {"route": route, "status": str(status)})
            clear_request_context()

    # -- proxy handler ------------------------------------------------------------
    async def _proxy_handler(self, request: web.Request, route: RouteConfig) -> web.Response:
        tenant = await self._gate_authentication(request)
        set_request_context(request["zerollm.request_id"], tenant=tenant, route=route.path)

        body = await self._read_body(request)

        quotas = self._tenant_quota(tenant)
        if quotas:
            quota = await self.quotas.check(tenant, quotas, request.method)
            if not quota.allowed:
                self._count("rate_limited_total", 1, {"route": route.path, "tenant": tenant})
                raise RequestError(429, f"rate limit exceeded, retry in {quota.retry_after_s}s")

        decision, redacted_body = await self._inspect_request(body, route, tenant)
        if decision.action == "block":
            self._record_block(decision, request, "request", tenant)
            raise RequestError(403, self._block_message(decision))
        if decision.action == "flag":
            await self._audit_flag(decision, request, tenant, "request")
        forwarded = redacted_body if redacted_body is not None else body

        return await self._forward(request, route, forwarded, tenant)

    async def _gate_authentication(self, request: web.Request) -> str:
        context = await self.auth.authenticate_async(request)
        if self.auth.mode != "none" and not context.authenticated:
            raise UnauthorizedError("authentication required")
        if not context.tenant and self.config.tenants:
            context.tenant = request.headers.get("X-ZeroLLM-Tenant", "").strip()
        return context.tenant

    # -- request inspection ----------------------------------------------------
    async def _inspect_request(
        self, body: bytes, route: RouteConfig, tenant: str
    ) -> Tuple[PolicyDecision, Optional[bytes]]:
        data = jsonutil.raw_to_json(body)
        if data is None:
            return PolicyDecision(action="allow", fail_mode=self.config.mode), None
        per_chunk: List[Tuple[List[str], str, List[Finding]]] = []
        all_findings: List[Finding] = []
        for path, chunk_text in jsonutil.extract_chunks(data):
            findings = await self.engine.scan_async(chunk_text)
            if findings:
                per_chunk.append((path, chunk_text, findings))
                all_findings.extend(findings)
        decision = self.policy_engine.evaluate("request", all_findings, route.policy, tenant)
        if decision.action != "redact":
            return decision, None
        redacted = data
        for path, chunk_text, findings in per_chunk:
            rules = [r for r in decision.rule_hits if r.action == "redact"]
            replace = self._replacement_for(rules, findings)
            if not replace:
                continue
            from ..detect.engine import redact_spans

            new_text = redact_spans(chunk_text, replace, findings)
            redacted = jsonutil.apply_redaction(redacted, path, new_text)
        return decision, json.dumps(redacted, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _replacement_for(rules, findings: List[Finding]) -> Optional[str]:
        for rule in rules:
            if any(f.detector == rule.detector for f in findings):
                return rule.replace_with
        return None

    # -- forwarding -----------------------------------------------------------
    async def _forward(self, request: web.Request, route: RouteConfig, body: bytes, tenant: str):
        is_stream = self._is_stream_request(body)
        upstream_ids = list(route.upstreams)
        timeout_s = self.config.server.limits.request_timeout_s
        path_and_query = request.rel_url.query_string
        upstream_headers = self._upstream_headers(request, tenant)
        self.tracer.inject_headers(upstream_headers)

        while upstream_ids:
            upstream = self.pool.pick(upstream_ids)
            if upstream is None:
                raise RequestError(502, "no healthy upstream available")
            try:
                upstream_headers.update(upstream_auth_headers(upstream))
                response = await self.pool.send(
                    upstream,
                    request.method,
                    request.path + (("?" + path_and_query) if path_and_query else ""),
                    upstream_headers,
                    body,
                    timeout_s,
                )
                if response.status not in (200, 201, 204) and is_stream:
                    raise RequestError(response.status, f"upstream error {response.status}")
                if is_stream and response.status == 200:
                    result = await self._stream_response(request, route, response, tenant, upstream)
                    return result
                data = await response.read()
                decision, redacted = await self._inspect_response(data, route, tenant)
                if decision.action == "block":
                    self._record_block(decision, request, "response", tenant, upstream_id=upstream.id)
                    raise RequestError(403, self._block_message(decision))
                if decision.action == "flag":
                    await self._audit_flag(decision, request, tenant, "response", upstream_id=upstream.id)
                payload = redacted if redacted is not None else data
                self._count(
                    "responses_total",
                    1,
                    {"route": route.path, "upstream": upstream.id, "status": str(response.status)},
                )
                return web.Response(
                    body=payload,
                    status=response.status,
                    content_type=self._safe_content_type(
                        response.headers.get("Content-Type", "application/json")
                    ),
                )
            except SSEBlocked:
                raise
            except RequestError:
                raise
            except Exception:
                _log.warning(
                    "upstream attempt failed",
                    extra={"event": "upstream_attempt_failed", "upstream": upstream.id},
                    exc_info=True,
                )
                upstream_ids.remove(upstream.id)
        raise RequestError(502, "all upstreams failed")

    async def _stream_response(
        self, request, route, upstream_response: ClientResponse, tenant, upstream: UpstreamConfig
    ):
        content_type = self._safe_content_type(
            upstream_response.headers.get("Content-Type", "text/event-stream")
        )
        response = web.StreamResponse(
            status=200, headers={"Content-Type": content_type, "Cache-Control": "no-cache"}
        )
        await response.prepare(request)
        detector_ids = [
            d.detector
            for d in self.config.policies.get(route.policy, self.config.policies["default"]).decisions
            if d.on in ("stream", "both")
        ]
        inspector = SSEStreamInspector(
            self.engine,
            self.policy_engine,
            policy_id=route.policy,
            tenant=tenant,
            lookahead=self.config.server.limits.max_sse_buffered_bytes // 4,
            detectors=detector_ids or None,
        )
        decision: Optional[PolicyDecision] = None
        try:
            async for chunk in upstream_response.content.iter_any():
                inspected = await inspector.inspect(chunk)
                if inspected:
                    await response.write(inspected)
            tail, decision = await inspector.finish()
            if tail:
                await response.write(tail)
        except SSEBlocked as error:
            decision = error.decision
            self._record_block(decision, request, "stream", tenant, upstream_id=upstream.id)
            await response.write(self._sse_block_events(decision))
            await response.write_eof()
            return response
        self._count("responses_total", 1, {"route": route.path, "upstream": upstream.id, "status": "200"})
        if decision and decision.action in ("redact", "flag") and decision.rule_hits:
            summary = sorted({f.detector for r in decision.rule_hits for f in r.findings})
            if decision.action == "flag":
                await self._audit_flag(decision, request, tenant, "stream", upstream_id=upstream.id)
            for detector in summary:
                self._count("scrubbed_total", 1, {"detector": detector})
        await response.write_eof()
        return response

    # -- response inspection -----------------------------------------------------
    async def _inspect_response(
        self, data: bytes, route: RouteConfig, tenant: str
    ) -> Tuple[PolicyDecision, Optional[bytes]]:
        parsed = jsonutil.raw_to_json(data)
        if parsed is None:
            return PolicyDecision(action="allow", fail_mode=self.config.mode), None
        all_findings: List[Finding] = []
        per_chunk: List[Tuple[List[str], str, List[Finding]]] = []
        for path, chunk_text in jsonutil.extract_chunks(parsed):
            findings = await self.engine.scan_async(chunk_text)
            if findings:
                per_chunk.append((path, chunk_text, findings))
                all_findings.extend(findings)
        decision = self.policy_engine.evaluate("response", all_findings, route.policy, tenant)
        if decision.action != "redact":
            return decision, None
        from ..detect.engine import redact_spans

        redacted = parsed
        for path, chunk_text, findings in per_chunk:
            replace = self._replacement_for(list(decision.rule_hits), findings)
            if not replace:
                continue
            new_text = redact_spans(chunk_text, replace, findings)
            redacted = jsonutil.apply_redaction(redacted, path, new_text)
        return decision, json.dumps(redacted, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    # -- helpers ---------------------------------------------------------------
    async def _read_body(self, request: web.Request) -> bytes:
        limit = self.config.server.limits.max_body_bytes
        if request.content_length and request.content_length > limit:
            raise RequestError(413, "request body too large")
        body = await request.content.read(limit + 1)
        if len(body) > limit:
            raise RequestError(413, "request body too large")
        return body

    @staticmethod
    def _is_stream_request(body: bytes) -> bool:
        try:
            data = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return False
        return bool(data.get("stream"))

    @staticmethod
    def _safe_content_type(value: str) -> str:
        return (value or "application/json").split(";", 1)[0].strip()

    def _upstream_headers(self, request: web.Request, tenant: str) -> dict:
        hop = {
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "upgrade",
            "proxy-authorization",
            "te",
            "zerollm.request_id",
        }
        headers = {k: v for k, v in request.headers.items() if k.lower() not in hop}
        headers.pop("content-length", None)
        headers["x-zerollm-request-id"] = request.get("zerollm.request_id", "")
        if tenant:
            headers["x-zerollm-tenant"] = tenant
        return headers

    def _tenant_quota(self, tenant: str):
        if not tenant:
            return None
        for t in self.config.tenants:
            if t.id == tenant:
                return t.quotas
        return None

    def _record_block(
        self, decision: PolicyDecision, request, phase: str, tenant: str = "", upstream_id: str = ""
    ):
        for rule in decision.rule_hits:
            for finding in rule.findings:
                if rule.action == "block":
                    self._count("attacks_blocked", 1, {"detector": finding.detector, "action": "block"})
        self._count("blocks_total", 1, {"phase": phase})
        if self.audit is not None:
            asyncio.create_task(
                self.audit.alog(
                    "attack_blocked",
                    {
                        "phase": phase,
                        "route": request.path,
                        "tenant": tenant,
                        "request_id": request.get("zerollm.request_id", ""),
                        "offense": self._summarize(decision),
                        "upstream_id": upstream_id,
                    },
                    severity="critical",
                )
            )

    async def _audit_flag(
        self, decision: PolicyDecision, request, tenant: str, phase: str, upstream_id: str = ""
    ):
        for rule in decision.rule_hits:
            for finding in rule.findings:
                self._count("flagged_total", 1, {"detector": finding.detector})

    @staticmethod
    def _sse_block_events(decision: PolicyDecision) -> bytes:
        error = {
            "error": {
                "message": "zerollm blocked stream",
                "type": "zerollm_blocked",
                "detectors": ZeroLLMHTTPGateway._summarize(decision),
            }
        }
        events = "data: " + json.dumps(error, default=str) + "\n\ndata: [DONE]\n\n"
        return events.encode("utf-8")

    @staticmethod
    def _block_message(decision: PolicyDecision) -> str:
        detectors = sorted(
            {f.detector for r in decision.rule_hits for f in r.findings}
            or [f.detector for f in decision.findings]
        )
        return f"zerollm blocked request ({', '.join(detectors)})"

    @staticmethod
    def _summarize(decision: PolicyDecision) -> List[dict]:
        return [
            {
                "detector": f.detector,
                "severity": f.severity,
                "confidence": f.confidence,
                "rule": r.rule_id,
                "reason": r.reason,
            }
            for r in decision.rule_hits
            for f in r.findings
        ]

    @staticmethod
    def _error(status: int, message: str) -> web.Response:
        return web.json_response(
            {"error": {"message": message, "type": "zerollm_error"}},
            status=status,
            headers={"X-ZeroLLM-Error": "true"},
        )

    @staticmethod
    def _count(name: str, value: int, labels: dict) -> None:
        DEFAULT_METRICS.counter(name, value, labels)


async def run_gateway(config: Config) -> None:
    """Run the gateway until SIGINT/SIGTERM (used by the CLI)."""
    from ..log import configure_logging

    configure_logging(config.logging.level, config.logging.format)
    if config.otel.enabled:
        from ..trace import enable_tracing

        enable_tracing(config.otel.service_name, config.otel.endpoint)

    gateway = ZeroLLMHTTPGateway(config)
    await gateway.start(config.server.host, config.server.port)
    _log.info(f"zerollm ready at http://{config.server.host}:{config.server.port}")

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    with suppress(NotImplementedError, RuntimeError):
        for signal_name in ("SIGINT", "SIGTERM"):
            loop.add_signal_handler(getattr(signal, signal_name), stop_event.set)

    try:
        await stop_event.wait()
    finally:
        with suppress(NotImplementedError, RuntimeError, ValueError):
            for signal_name in ("SIGINT", "SIGTERM"):
                loop.remove_signal_handler(getattr(signal, signal_name))
        await gateway.stop()


def main(config_path: str) -> int:
    from ..config import load_config

    cfg = load_config(config_path)
    try:
        asyncio.run(run_gateway(cfg))
        return 0
    except KeyboardInterrupt:
        return 0
