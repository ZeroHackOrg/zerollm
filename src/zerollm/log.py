"""Structured JSON logging with correlation fields.

Every log line carries ``request_id``, ``tenant``, ``route`` and ``event`` as
attributes so logs can be piped straight into a SIEM without ETL.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
import uuid
from typing import Any, Optional

_CTX = threading.local()


def set_request_context(request_id: Optional[str] = None, tenant: str = "", route: str = "") -> str:
    request_id = request_id or uuid.uuid4().hex
    _CTX.request_id = request_id
    _CTX.tenant = tenant
    _CTX.route = route
    return request_id


def clear_request_context() -> None:
    _CTX.request_id = None
    _CTX.tenant = ""
    _CTX.route = ""


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: Any = {
            "ts": time.time(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if getattr(_CTX, "request_id", None):
            entry["request_id"] = _CTX.request_id
        if getattr(_CTX, "tenant", ""):
            entry["tenant"] = _CTX.tenant
        if getattr(_CTX, "route", ""):
            entry["route"] = _CTX.route
        for key in ("event", "upstream", "status", "duration_ms", "upstream_id"):
            if hasattr(record, key):
                entry[key] = getattr(record, key)
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        request_id = getattr(_CTX, "request_id", None)
        tenant = getattr(_CTX, "tenant", "")
        prefix = f"{record.levelname:<8} {record.name}"
        ctx = " ".join(
            piece
            for piece in (
                f"req={request_id}" if request_id else "",
                f"tenant={tenant}" if tenant else "",
                f"route={getattr(record, 'route', '')}" if hasattr(record, "route") and record.route else "",
            )
            if piece
        )
        return f"{prefix} [{ctx}] {record.getMessage()}"


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    root = logging.getLogger("zerollm")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    request_handler = logging.StreamHandler(sys.stderr)
    request_handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    root.addHandler(request_handler)
    root.propagate = False
    # Quiet noisy third-party loggers.
    for noisy in ("aiohttp.access", "aiohttp.server", "chardet", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str = "zerollm"):
    return logging.getLogger("zerollm" + (("." + name) if name != "zerollm" else ""))


def log_event(logger, event: str, level: int = logging.INFO, **fields: Any) -> None:
    logger.log(level, event, extra={"event": event, **fields})
