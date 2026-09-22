"""Detection engine: prompt-injection, jailbreak, PII, secrets and DLP.

Findings carry ``detector``, ``label``, ``severity`` and ``confidence`` so the
policy engine can decide allow / block / redact / flag per tenant and
endpoint. Model-based detection (LLM judge) is pluggable and optional.
"""

from .engine import (
    DetectionEngine,
    DetectorSpec,
    Finding,
    list_detectors,
    redact_spans,
)

__all__ = ["DetectionEngine", "DetectorSpec", "Finding", "list_detectors", "redact_spans"]
