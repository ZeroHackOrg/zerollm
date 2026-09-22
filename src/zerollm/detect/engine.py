"""Detection engine orchestration.

Combines the built-in signature catalogue with optional LLM-judge detectors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Union

from . import patterns as _patterns
from .judge import LLMJudge


@dataclass
class Finding:
    """A single detection result mapped to a span of the inspected text."""

    detector: str
    label: str
    severity: str
    confidence: float
    start: int = -1
    end: int = -1
    extra: dict = field(default_factory=dict)

    def severity_rank(self) -> int:
        return _patterns.rank(self.severity)


@dataclass
class DetectorSpec:
    id: str
    label: str
    severity: str
    confidence: float = 0.8
    matcher: Optional[Callable[[str], List[tuple]]] = None

    def scan(self, text: str) -> List[Finding]:
        spans = self.matcher(text) if self.matcher is not None else []
        return [self._finding(start, end) for start, end in spans]

    def _finding(self, start: int, end: int) -> Finding:
        return Finding(
            detector=self.id,
            label=self.label,
            severity=self.severity,
            confidence=self.confidence,
            start=start,
            end=end,
        )


class DetectionEngine:
    """Scans text across all (or a subset of) detectors."""

    def __init__(self, judges: Optional[List[LLMJudge]] = None) -> None:
        self._specs: Dict[str, DetectorSpec] = {}
        self._judges: List[LLMJudge] = []
        for judge in judges or []:
            self._judges.append(judge)
        for spec_id, spec in _patterns.SPECS.items():
            matcher: Optional[Callable[[str], List[tuple]]] = None
            if "match" in spec and callable(spec.get("match")):
                matcher = spec["match"]
            self._specs[spec_id] = DetectorSpec(
                id=spec["id"],
                label=spec["label"],
                severity=spec["severity"],
                confidence=float(spec.get("confidence", 0.8)),
                matcher=matcher,
            )
            if "patterns" in spec:
                patterns = spec["patterns"]

                def _regex_scan(text: str, _patterns: List[re.Pattern] = patterns) -> List[tuple]:
                    return [(m.start(), m.end()) for p in _patterns for m in p.finditer(text)]

                self._specs[spec_id].matcher = _regex_scan

    def detector_ids(self) -> List[str]:
        return list(self._specs) + [j.detector_id for j in self._judges]

    def scan(self, text: str, detector_ids: Optional[Union[str, List[str]]] = None) -> List[Finding]:
        """Run requested (regex/signature) detectors - judges need the async path."""
        if not text:
            return []
        wanted = [d for d in self._resolve(detector_ids) if d not in {j.detector_id for j in self._judges}]
        findings: List[Finding] = []
        for spec_id in wanted:
            findings.extend(self._specs[spec_id].scan(text))
        findings.sort(key=lambda f: (-f.severity_rank(), -f.confidence, f.start))
        return findings

    async def scan_async(
        self, text: str, detector_ids: Optional[Union[str, List[str]]] = None
    ) -> List[Finding]:
        result = self.scan(text, detector_ids)
        wanted = set(self._resolve(detector_ids))
        for judge in self._judges:
            if judge.detector_id in wanted:
                for item in await judge.scan(text):
                    result.append(
                        Finding(
                            detector=item["detector"],
                            label=item["label"],
                            severity=item["severity"],
                            confidence=item["confidence"],
                            start=item["start"],
                            end=item["end"],
                            extra={"latency_s": item.get("judge_latency_s", 0.0)},
                        )
                    )
        return result

    def _resolve(self, detector_ids: Optional[Union[str, List[str]]]) -> List[str]:
        known = set(self._specs) | {j.detector_id for j in self._judges}
        if detector_ids is None:
            return sorted(known - {"prompt_injection_low"})
        if isinstance(detector_ids, str):
            detector_ids = [detector_ids]
        unknown = [d for d in detector_ids if d not in known]
        if unknown:
            raise ValueError(f"unknown detectors: {unknown}")
        return list(detector_ids)


def list_detectors() -> List[str]:
    return sorted(_patterns.SPECS)


def redact_spans(text: str, replace_with: str, findings: List[Finding]) -> str:
    """Replace (merged) detection spans with a redaction token."""
    if not findings:
        return text
    regions: List[tuple] = []
    for f in sorted(findings, key=lambda x: (x.start, -(x.end - x.start))):
        if f.start < 0 or f.end < 0:
            continue
        if not regions or f.start > regions[-1][1]:
            regions.append((f.start, f.end))
        else:
            regions[-1] = (regions[-1][0], max(regions[-1][1], f.end))
    parts = []
    cursor = 0
    for start, end in regions:
        parts.append(text[cursor:start])
        parts.append(replace_with)
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)
