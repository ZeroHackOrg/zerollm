"""Upstream pool: weighted routing, circuit breakers, failover and retries."""

from __future__ import annotations

import random
import ssl
import threading
import time
from typing import Dict, Iterable, List, Optional

import aiohttp

from ..config import CircuitBreakerConfig, Config, UpstreamConfig
from ..log import get_logger

_log = get_logger(__name__)


class CircuitBreaker:
    def __init__(self, name: str, cfg: CircuitBreakerConfig) -> None:
        self.name = name
        self.cfg = cfg
        self._failures = 0
        self._sliding: List[float] = []
        self._state = "closed"  # closed | open | half-open
        self._opened_at = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            if self._state == "open" and time.time() - self._opened_at >= self.cfg.cooldown_s:
                self._state = "half-open"
                self._failures = 0
            return self._state

    def allow(self) -> bool:
        state = self.state
        if state == "open":
            return False
        if state == "half-open":
            return True  # probe
        return True

    def record(self, ok: bool) -> None:
        with self._lock:
            now = time.time()
            if ok:
                self._failures = 0
                self._sliding = []
                self._state = "closed"
                return
            self._failures += 1
            self._sliding = [t for t in self._sliding if now - t < 60] + [now]
            if self._state in ("closed", "half-open") and self._failures >= self.cfg.max_failures:
                self._state = "open"
                self._opened_at = now


class UpstreamPool:
    """Selects and talks to healthy upstreams for a routed request."""

    def __init__(self, config: Config, session_factory=None) -> None:
        self.config = config
        self._session_factory = session_factory
        self._sessions: Dict[str, Optional[aiohttp.ClientSession]] = {}
        self._breakers: Dict[str, CircuitBreaker] = {}
        for upstream in config.upstreams:
            self._breakers[upstream.id] = CircuitBreaker(upstream.id, upstream.circuit_breaker)
            self._sessions[upstream.id] = None

    @property
    def upstreams(self) -> List[UpstreamConfig]:
        return self.config.upstreams

    def healthy(self, upstream_ids: Iterable[str]) -> List[UpstreamConfig]:
        return [
            u for u in self.config.upstreams if u.id in set(upstream_ids) and self._breakers[u.id].allow()
        ]

    def pick(self, upstream_ids: List[str]) -> Optional[UpstreamConfig]:
        healthy = self.healthy(upstream_ids)
        if not healthy:
            return None
        weights = [max(1, u.weight) for u in healthy]
        return random.choices(healthy, weights=weights, k=1)[0]

    async def send(
        self,
        upstream: UpstreamConfig,
        method: str,
        path_and_query: str,
        headers: dict,
        body: bytes,
        timeout_s: float,
    ) -> aiohttp.ClientResponse:
        """Send a request to ``upstream`` and return an aiohttp ClientResponse."""
        session = self._session(upstream.id)
        url = upstream.base_url + path_and_query
        breaker = self._breakers[upstream.id]
        try:
            resp = await session.request(
                method,
                url,
                headers=headers,
                data=body,
                timeout=aiohttp.ClientTimeout(total=timeout_s),
                ssl=False if not upstream.verify_tls else None,
            )
            breaker.record(ok=resp.status < 500)
            return resp
        except (aiohttp.ClientError, TimeoutError, ssl.SSLError):
            breaker.record(ok=False)
            raise

    def _session(self, upstream_id: str) -> aiohttp.ClientSession:
        session = self._sessions.get(upstream_id)
        if session is None:
            if self._session_factory is not None:
                session = self._session_factory(upstream_id)
            else:
                session = aiohttp.ClientSession(trust_env=True)
            self._sessions[upstream_id] = session
        return session

    async def close(self) -> None:
        for session in self._sessions.values():
            if session is not None:
                await session.close()

    def status(self) -> List[dict]:
        return [
            {
                "id": u.id,
                "type": u.type,
                "base_url": u.base_url,
                "state": self._breakers[u.id].state,
            }
            for u in self.config.upstreams
        ]
