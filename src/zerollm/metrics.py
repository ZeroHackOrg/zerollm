"""Prometheus metrics with labels and histograms.

Backward compatible with the original zero-dependency registry (``counter``,
``gauge``, ``snapshot``, ``prometheus_text``) while adding labelled counters
and latency histograms required for p95/p99 dashboards.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, Optional, Sequence, Union

import prometheus_client as pc

__all__ = ["DEFAULT_METRICS", "ZeroLLMMetricsRegistry"]

_LabelValues = Optional[Sequence[Union[str, int, float]]]

DEFAULT_BUCKETS = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
    60.0,
    120.0,
)


class ZeroLLMMetricsRegistry:
    """Thread-safe labelled metric registry backed by prometheus_client."""

    def __init__(self, prefix: str = "zerollm"):
        self._prefix = prefix
        self._registry = pc.CollectorRegistry()
        try:
            pc.process_collector.ProcessCollector(registry=self._registry)
            pc.platform_collector.PlatformCollector(registry=self._registry)
            pc.GCCollector(registry=self._registry)
        except Exception:
            pass
        self._counters: Dict[str, Any] = {}
        self._gauges: Dict[str, Any] = {}
        self._histograms: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def _labelnames(self) -> Optional[tuple]:
        return None

    def counter(self, name: str, value: int = 1, labels: Optional[Dict[str, str]] = None) -> None:
        with self._lock:
            metric = self._counters.get(name)
            if metric is None:
                metric = pc.Counter(
                    self._prefix + "_" + name,
                    f"zerollm counter {name}",
                    labelnames=tuple(sorted(labels)) if labels else (),
                    registry=self._registry,
                )
                self._counters[name] = metric
            target = metric.labels(**labels) if labels else metric
            target.inc(value)

    def gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        with self._lock:
            metric = self._gauges.get(name)
            if metric is None:
                metric = pc.Gauge(
                    self._prefix + "_" + name,
                    f"zerollm gauge {name}",
                    labelnames=tuple(sorted(labels)) if labels else (),
                    registry=self._registry,
                )
                self._gauges[name] = metric
            target = metric.labels(**labels) if labels else metric
            target.set(value)

    def histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        with self._lock:
            metric = self._histograms.get(name)
            if metric is None:
                metric = pc.Histogram(
                    self._prefix + "_" + name,
                    f"zerollm histogram {name}",
                    labelnames=tuple(sorted(labels)) if labels else (),
                    buckets=DEFAULT_BUCKETS,
                    registry=self._registry,
                )
                self._histograms[name] = metric
            target = metric.labels(**labels) if labels else metric
            target.observe(value)

    def observe_latency(self, name: str, seconds: float, labels: Optional[Dict[str, str]] = None) -> None:
        self.histogram(name, seconds, labels)

    def mark_blocked(self, detector: str, action: str = "block") -> None:
        self.counter("attacks_blocked", labels={"detector": detector, "action": action})

    @staticmethod
    def _sum_samples(metric: Any) -> Dict[str, float]:
        """Aggregate ``count`` / ``sum`` across every label set of a metric."""
        counts: float = 0.0
        total: float = 0.0
        try:
            for family in metric.collect():
                for sample in family.samples:
                    if sample.name.endswith("_count"):
                        counts += float(sample.value)
                    elif sample.name.endswith("_sum"):
                        total += float(sample.value)
        except Exception:
            pass
        return {"count": counts, "sum": total}

    def snapshot(self) -> dict:
        """Aggregate view for the JSON telemetry endpoint."""
        counters: Dict[str, float] = {}
        for key, metric in self._counters.items():
            try:
                counters[key] = float(metric.collect()[0].samples[0].value)
            except Exception:
                counters[key] = 0.0
        gauges: Dict[str, float] = {}
        for key, metric in self._gauges.items():
            try:
                gauges[key] = float(metric.collect()[0].samples[0].value)
            except Exception:
                gauges[key] = 0.0
        return {
            "counters": counters,
            "gauges": gauges,
            "histograms": {key: self._sum_samples(m) for key, m in self._histograms.items()},
        }

    def prometheus_text(self) -> str:
        return pc.generate_latest(self._registry).decode("utf-8")


DEFAULT_METRICS = ZeroLLMMetricsRegistry()
