"""OpenTelemetry tracing with a no-op fallback.

Tracing is enabled only when ``otel.enabled`` is true and the
``opentelemetry-*`` extras are installed. The rest of the codebase calls
through :func:`get_tracer` / :func:`with_span` regardless, so a deployment
without tracing still works seamlessly.
"""

from __future__ import annotations

import contextlib
import threading
from typing import Any, Optional

__all__ = ["Tracer", "enable_tracing", "get_tracer", "set_service_name"]

_state = {"service": "zerollm"}
_lock = threading.Lock()
_tracer_cache: Any = None
_tracer_provider: Any = None


class NoopTracer:
    """Pass-through tracer used when OpenTelemetry is unavailable."""

    def start_as_current_span(self, name: str, **kwargs: Any):
        return contextlib.nullcontext()

    def start_span(self, name: str, **kwargs: Any):
        return _NoopSpan()

    def inject(self, headers: dict) -> dict:
        return headers


class _NoopSpan:
    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, *args: Any, **kwargs: Any) -> None:
        pass

    def end(self, *args: Any, **kwargs: Any) -> None:
        pass


class Tracer:
    """Facade over OpenTelemetry (or the no-op fallback)."""

    def __init__(self, impl: Any) -> None:
        self._impl = impl
        self._enabled = True

    @property
    def enabled(self) -> bool:
        return self._enabled

    @contextlib.contextmanager
    def span(self, name: str, kind: Optional[str] = None, attributes: Optional[dict] = None):
        if not self._enabled:
            yield None
            return
        try:
            context = self._impl.start_as_current_span(name, attributes=attributes or {})
        except Exception:
            yield None
            return
        with context as span:
            yield span

    def inject_headers(self, headers: Optional[dict] = None) -> dict:
        headers = headers or {}
        if self._enabled:
            try:
                from opentelemetry import propagate
            except ModuleNotFoundError:
                return headers
            try:
                ctx = _tracer_provider.get().current()
                headers_out: dict = {}
                propagate.inject(headers_out, ctx)
                headers.update(headers_out)
            except Exception:
                pass
        return headers


def enable_tracing(service_name: str, endpoint: str = "") -> None:
    """Configure the global OTel tracer provider (safe no-op if extra missing)."""
    global _tracer_provider, _tracer_cache
    with _lock:
        try:
            from opentelemetry import trace
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
        except ModuleNotFoundError:
            _tracer_cache = NoopTracer()
            return

        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        if endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
                from opentelemetry.sdk.trace.export import BatchSpanProcessor

                processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
            except ModuleNotFoundError:
                processor = None
            if processor is not None:
                provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)
        _tracer_provider = provider
        _tracer_cache = Tracer(trace.get_tracer(service_name))


def set_service_name(service_name: str) -> None:
    _state["service"] = service_name


def get_tracer() -> Tracer:
    """Return the process-wide :class:`Tracer`."""
    global _tracer_cache
    with _lock:
        if _tracer_cache is None:
            _tracer_cache = Tracer(NoopTracer())
        return _tracer_cache
