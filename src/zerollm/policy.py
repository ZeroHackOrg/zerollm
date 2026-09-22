"""Policy engine: map detection findings to allow / block / redact / flag.

Rules are defined per policy (default ``policies.default``) and can match on
the request, response or streaming phase. When findings exist but no rule
matches, the engine falls back to the configured fail mode:
``fail-closed`` blocks, ``fail-open`` passes through and flags.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .config import Config, DecisionConfig, PolicyConfig
from .detect.engine import Finding
from .detect.patterns import rank as _severity_rank

__all__ = ["PHASES", "PolicyDecision", "PolicyEngine", "RuleHit"]

PHASES = ("request", "response", "stream")


@dataclass
class RuleHit:
    rule_id: str
    action: str
    detector: str
    replace_with: str = ""
    reason: str = ""
    findings: List[Finding] = field(default_factory=list)


@dataclass
class PolicyDecision:
    action: str  # allow | block | redact | flag
    blocked: bool = False
    flagged: bool = False
    rule_hits: List[RuleHit] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    fail_mode: str = "fail-closed"

    def as_dict(self) -> dict:
        return {
            "action": self.action,
            "blocked": self.blocked,
            "flagged": self.flagged,
            "fail_mode": self.fail_mode,
            "rules": [
                {"id": h.rule_id, "action": h.action, "detector": h.detector, "reason": h.reason}
                for h in self.rule_hits
            ],
            "findings": [
                {
                    "detector": f.detector,
                    "label": f.label,
                    "severity": f.severity,
                    "confidence": f.confidence,
                }
                for f in self.findings
            ],
        }


def default_outcome(action: str, fail_mode: str) -> PolicyDecision:
    return PolicyDecision(
        action=action,
        blocked=action == "block",
        flagged=action == "flag",
        fail_mode=fail_mode,
    )


class PolicyEngine:
    """Evaluates findings against configured rules for a given phase/tenant."""

    def __init__(self, config: Config, known_detectors: List[str]) -> None:
        self.config = config
        self.fail_mode = config.mode
        self._detectors = set(known_detectors)
        self._policies: Dict[str, PolicyConfig] = config.policies
        self._validate_rules()

    def _validate_rules(self) -> None:
        for policy in self._policies.values():
            for decision in policy.decisions:
                if decision.detector not in self._detectors:
                    raise ValueError(
                        f"policy {policy.id!r} decision {decision.id!r} references unknown "
                        f"detector {decision.detector!r} (known: {sorted(self._detectors)})"
                    )

    def evaluate(
        self, phase: str, findings: List[Finding], policy_id: str = "default", tenant: str = ""
    ) -> PolicyDecision:
        if phase not in PHASES:
            raise ValueError(f"phase must be one of {PHASES}")
        policy = self._policies.get(policy_id, self._policies["default"])
        hits = self._match(policy.decisions, phase, findings, tenant)

        if any(h.action == "block" for h in hits):
            return PolicyDecision(
                action="block",
                blocked=True,
                rule_hits=hits,
                findings=findings,
                fail_mode=self.fail_mode,
            )
        if any(h.action == "redact" for h in hits):
            return PolicyDecision(
                action="redact",
                rule_hits=hits,
                findings=[f for h in hits if h.action == "redact" for f in h.findings],
                fail_mode=self.fail_mode,
            )
        if any(h.action == "flag" for h in hits):
            return PolicyDecision(
                action="flag",
                flagged=True,
                rule_hits=hits,
                findings=findings,
                fail_mode=self.fail_mode,
            )
        if any(h.action == "allow" for h in hits):
            return PolicyDecision(action="allow", fail_mode=self.fail_mode)

        # Findings present but no rule matched -> decide by fail mode.
        if findings:
            if self.fail_mode == "fail-closed":
                return PolicyDecision(
                    action="block",
                    blocked=True,
                    findings=findings,
                    fail_mode=self.fail_mode,
                )
            return PolicyDecision(action="flag", flagged=True, findings=findings, fail_mode=self.fail_mode)

        return PolicyDecision(action="allow", fail_mode=self.fail_mode)

    def _match(
        self, decisions: List[DecisionConfig], phase: str, findings: List[Finding], tenant: str
    ) -> List[RuleHit]:
        hits: List[RuleHit] = []
        for decision in decisions:
            if decision.on != "both" and decision.on != phase:
                continue
            if self._tenants_match(decision.tenants, tenant):
                matching = [
                    f
                    for f in findings
                    if f.detector == decision.detector
                    and f.confidence >= decision.min_confidence
                    and _severity_rank(f.severity) <= _severity_rank(decision.max_severity)
                ]
                if matching:
                    hits.append(
                        RuleHit(
                            rule_id=decision.id,
                            action=decision.action,
                            detector=decision.detector,
                            replace_with=decision.replace_with,
                            reason=decision.reason,
                            findings=matching,
                        )
                    )
        return hits

    @staticmethod
    def _tenants_match(allowed: List[str], tenant: str) -> bool:
        return "*" in allowed or tenant in allowed
