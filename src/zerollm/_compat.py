"""Optional-dependency availability helpers."""

from __future__ import annotations

_available: dict = {}


def _check(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ModuleNotFoundError:
        return False


def boto3_available() -> bool:
    if "boto3" not in _available:
        _available["boto3"] = _check("boto3")
    return _available["boto3"]


def opentelemetry_available() -> bool:
    if "otel" not in _available:
        import importlib.util

        _available["otel"] = importlib.util.find_spec("opentelemetry") is not None
    return _available["otel"]


def redis_available() -> bool:
    if "redis" not in _available:
        _available["redis"] = _check("redis")
    return _available["redis"]
