"""Rate limiting and tenant quotas.

A fixed-window counter per tenant/quota backed by either shared Redis
(``redis.enabled``, multi-instance safe) or process-local state.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from ._compat import redis_available
from .config import QuotaConfig, RedisConfig

__all__ = ["QuotaResult", "QuotaStore"]


@dataclass
class QuotaResult:
    allowed: bool
    limit: int
    remaining: int
    retry_after_s: int = 0


class _MemoryRooms:
    """Thread-safe fixed-window counters keyed by (key, window_start)."""

    def __init__(self) -> None:
        self._windows: Dict[Tuple[str, int], int] = {}
        self._lock = threading.Lock()

    def count(self, key: str, window_s: int, amount: int = 1) -> int:
        now = int(time.time())
        window_start = now - (now % window_s)
        with self._lock:
            bucket = self._windows.get((key, window_start), 0) + amount
            self._windows[(key, window_start)] = bucket
            if len(self._windows) > 10_000:
                cutoff = now - 2 * max(window_s, 3600)
                self._windows = {k: v for k, v in self._windows.items() if k[1] >= cutoff}
            return bucket


class QuotaStore:
    """Evaluates per-tenant request/token quotas with Redis or memory backend."""

    def __init__(self, rediscfg: Optional[RedisConfig] = None) -> None:
        self.config = rediscfg or RedisConfig(enabled=False)
        self._memory = _MemoryRooms()
        self._redis = None
        if self.config.enabled and redis_available():
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(self.config.url)

    async def check(self, tenant_id: str, quota: QuotaConfig, method: str) -> QuotaResult:
        if quota.rpm <= 0:
            return QuotaResult(allowed=True, limit=0, remaining=-1)
        key = f"zerollm:rpm:{tenant_id}"
        current = await self._incr(key, 60, 1)
        remaining = max(0, quota.rpm - current)
        if current > quota.rpm:
            retry_after = 60 - int(time.time()) % 60
            return QuotaResult(allowed=False, limit=quota.rpm, remaining=0, retry_after_s=retry_after)
        return QuotaResult(allowed=True, limit=quota.rpm, remaining=remaining)

    async def check_tokens(self, tenant_id: str, quota: QuotaConfig, approx_tokens: int) -> QuotaResult:
        if quota.tokens_per_min <= 0 or approx_tokens <= 0:
            return QuotaResult(allowed=True, limit=0, remaining=-1)
        key = f"zerollm:tpm:{tenant_id}"
        current = await self._incr(key, 60, approx_tokens)
        remaining = max(0, quota.tokens_per_min - current)
        if current > quota.tokens_per_min:
            retry_after = 60 - int(time.time()) % 60
            return QuotaResult(
                allowed=False, limit=quota.tokens_per_min, remaining=0, retry_after_s=retry_after
            )
        return QuotaResult(allowed=True, limit=quota.tokens_per_min, remaining=remaining)

    async def _incr(self, key: str, window_s: int, amount: int) -> int:
        if self._redis is not None:
            now = int(time.time())
            bucket = now - (now % window_s)
            full_key = f"{key}:{bucket}"
            count = await self._redis.incrby(full_key, amount)
            if count == amount:
                await self._redis.expire(full_key, window_s + 60)
            return int(count)
        return self._memory.count(key, window_s, amount)

    async def aclose(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()
