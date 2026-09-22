"""Reverse-proxy firewall facade (backward-compatible).

``ZeroLLMProxy`` wraps the detection + policy engines from the full gateway
with the original single-call API. Production traffic goes through
``zerollm.proxy.gateway``; this class powers the demo and programmatic use.
"""

from __future__ import annotations

from typing import Optional

from ..config import Config
from ..detect.engine import DetectionEngine, Finding

__all__ = ["SecurityException", "ZeroLLMProxy"]

_BLOCK_DETECTORS = {
    "prompt_injection",
    "prompt_injection_low",
    "indirect_injection",
    "dan_jailbreak",
}

_REDACT_TOKEN = "[REDACTED_FINANCIAL_DATA]"


class SecurityException(Exception):
    """Raised when a request is detected as an injection/attack."""


class ZeroLLMProxy:
    """Signature-compatible firewall proxy over the detection engine."""

    def __init__(self, config: Optional[Config] = None) -> None:
        self._config = config
        self.engine = DetectionEngine()

    def detect(self, text: str) -> list:
        """Run the full detection engine and return findings."""
        return self.engine.scan(text)

    def sanitize_prompt(self, user_prompt: str) -> str:
        """Block injections and scrub PII/secrets from a prompt."""
        findings = self.engine.scan(user_prompt)
        self._raise_if_blocked(findings)
        return self.redact_prompt(user_prompt, findings)

    def redact_prompt(self, text: str, findings: Optional[list] = None) -> str:
        findings = findings if findings is not None else self.engine.scan(text)
        sensitive = [f for f in findings if not self._is_block(f)]
        if not sensitive:
            return text
        regions: list = []
        for f in sorted(sensitive, key=lambda x: (x.start, -(x.end - x.start))):
            if f.start < 0 or f.end < 0:
                continue
            if not regions or f.start > regions[-1][1]:
                regions.append([f.start, f.end, f.detector])
            else:
                regions[-1][1] = max(regions[-1][1], f.end)
                if regions[-1][2] == "pii_credit_card" or f.detector == "pii_credit_card":
                    regions[-1][2] = "pii_credit_card"
        parts = []
        cursor = 0
        for start, end, detector in regions:
            parts.append(text[cursor:start])
            parts.append("[REDACTED_FINANCIAL_DATA]" if detector == "pii_credit_card" else "[REDACTED]")
            cursor = end
        parts.append(text[cursor:])
        return "".join(parts)

    def _raise_if_blocked(self, findings: list) -> None:
        for finding in findings:
            if finding.detector in _BLOCK_DETECTORS:
                raise SecurityException(
                    f"[ZeroLLM Attack Blocked] Intercepted: '{finding.detector}' "
                    f"(confidence {finding.confidence:.2f})"
                )

    @staticmethod
    def _is_block(finding: Finding) -> bool:
        return finding.detector in _BLOCK_DETECTORS


class ProxyConfigAdapter:
    """Loose adapter from a :class:`Config` into the demo CLI."""

    def __init__(self, config: Config) -> None:
        self.config = config
