"""Signature and rule catalogues for prompt-injection / jailbreak / DLP / PII.

Each spec is `{id, label, severity, confidence, patterns|match}`. ``patterns``
are precompiled regexes; ``match`` is a callable ``(text, spec) -> spans`` used
for computed checks such as Luhn-validated credit cards.
"""

from __future__ import annotations

import re
from typing import List, Tuple

Span = Tuple[int, int]

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _re(*patterns: str) -> List[re.Pattern]:
    return [re.compile(p, re.IGNORECASE | re.MULTILINE | re.DOTALL) for p in patterns]


def _match_credit_card(text: str) -> List[Span]:
    spans: List[Span] = []
    for m in re.finditer(r"(?:\d[ -]*){13,19}", text):
        digits = text[m.start() : m.end()].replace(" ", "").replace("-", "")
        if 13 <= len(digits) <= 19 and _luhn(digits):
            spans.append((m.start(), m.end()))
    return spans


def _luhn(digits: str) -> bool:
    checksum = 0
    for i, ch in enumerate(reversed(digits)):
        digit = int(ch)
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _match_ssn(text: str) -> List[Span]:
    spans: List[Span] = []
    for m in re.finditer(r"\b(?!000|666|9\d\d)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b", text):
        spans.append((m.start(), m.end()))
    return spans


def _match_aws(text: str) -> List[Span]:
    spans: List[Span] = []
    for m in re.finditer(
        r"\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|AGPA|A3T[A-Z0-9]|A3G[A-Z0-9]|A3S[A-Z0-9]|A3B[A-Z0-9]|A3B[A-Z0-9])[A-Z0-9]{16}\b",
        text,
    ):
        spans.append((m.start(), m.end()))
    return spans


def _match_private_key(text: str) -> List[Span]:
    spans: List[Span] = []
    for m in re.finditer(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        text,
        re.DOTALL,
    ):
        spans.append((m.start(), m.end()))
    return spans


def _match_generic_bearer(text: str) -> List[Span]:
    spans: List[Span] = []
    for m in re.finditer(r"\B(Bearer|bearer|token|api[-_ ]?key)[^\w]+\S{12,}", text):
        spans.append((m.start(), m.end()))
    return spans


def _match_github_token(text: str) -> List[Span]:
    spans: List[Span] = []
    for m in re.finditer(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b", text):
        spans.append((m.start(), m.end()))
    return spans


def _match_slack_token(text: str) -> List[Span]:
    spans: List[Span] = []
    for m in re.finditer(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", text):
        spans.append((m.start(), m.end()))
    return spans


def _match_openai_token(text: str) -> List[Span]:
    spans: List[Span] = []
    for m in re.finditer(r"\bsk-[A-Za-z0-9]{20,}\b", text):
        spans.append((m.start(), m.end()))
    return spans


def _match_jwt(text: str) -> List[Span]:
    spans: List[Span] = []
    for m in re.finditer(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b", text):
        spans.append((m.start(), m.end()))
    return spans


# --- Spec catalogue ---------------------------------------------------------
# Detector id -> spec; the policy engine references these ids.
SPECS: dict = {}


def _spec(spec: dict) -> None:
    spec.setdefault("severity", "medium")
    SPECS[spec["id"]] = spec


_spec(
    {
        "id": "prompt_injection",
        "label": "High-confidence prompt injection",
        "severity": "critical",
        "confidence": 0.95,
        "patterns": _re(
            r"ignore (all |any |the )?previous instructions",
            r"ignore everything (above|before) and (say|repeat|do|output)",
            r"disregard (all |any )?prior instructions",
            r"forget (all |any )?previous instructions",
            r"you are now (free|unbounded|uncensored|an ai without)?\s*$",
            r"disregard your (system |initial )?prompt",
            r"override your (system|initial) instructions",
            r"print (the )?(master|root|system|admin) (key|password|password|token|secret)",
            r"output (the )?(system|config|database|source) (configuration|files?|contents)",
            r"reveal (the )?(hidden|internal|secret) (system|system prompt|instructions)",
            r"expose your (system prompt|training data|instructions)",
            r"act as a (malicious|jailbroken|censored|unfiltered|unrestricted) (terminal|assistant|ai)",
            r"developer mode (enabled|allowed|unrestricted)",
            r"simulate (a )?(jailbreak|developer mode)",
            r"you are do anything now",
            r"do anything now(dan)?",
            r"(^|\n)\s*system(:|\s$)",
        ),
    }
)

_spec(
    {
        "id": "prompt_injection_low",
        "label": "Possible prompt injection",
        "severity": "medium",
        "confidence": 0.6,
        "patterns": _re(
            r"new instructions",
            r"higher priority than",
            r"precedence over",
            r"ignore safety",
            r"bypass filters",
            r"without restrictions",
            r"don.t follow.*rules?",
            r"role.?play as",
            r"(^|\n)\s*(user|assistant)(:|\s$)",
        ),
    }
)

_spec(
    {
        "id": "indirect_injection",
        "label": "Indirect prompt injection (context tampering)",
        "severity": "high",
        "confidence": 0.85,
        "patterns": _re(
            r"instructions (embedded|contained) (in|within)",
            r"check (the |any )?instructions (in|from) (the )?(text|document|below|content)",
            r"(the )?text (contains|includes) (new )?instructions",
            r"follow (the )?instructions (in|found in) (the |this )(text|page|email|file)",
            r"system prompt is:",
            r"\bhuman: override",
            r"<\|im_start\|>system",
            r"\binput contains directions? for you",
        ),
    }
)

_spec(
    {
        "id": "dan_jailbreak",
        "label": "DAN / jailbreak bypass",
        "severity": "high",
        "confidence": 0.8,
        "patterns": _re(
            r"\bd\.a\.n\.\b",
            r"\bdo anything now\b",
            r"\bbypass (all |the )?(restrictions|safety|filters|guardrails)",
            r"\buncensored (mode|version)",
            r"\bjailbreak\b",
            r"\bremove (all )?(restrictions|guidelines|limitations)",
            r"\bgive (me )?(unfiltered|unlimited|raw) (access|answers|responses)",
            r"\bfreedom mode",
        ),
    }
)

_spec(
    {
        "id": "pii_credit_card",
        "label": "Credit card number (Luhn validated)",
        "severity": "high",
        "confidence": 0.98,
        "match": _match_credit_card,
    }
)

_spec(
    {
        "id": "pii_ssn",
        "label": "US Social Security number",
        "severity": "high",
        "confidence": 0.9,
        "match": _match_ssn,
    }
)

_spec(
    {
        "id": "pii_email",
        "label": "Email address",
        "severity": "low",
        "confidence": 0.9,
        "patterns": _re(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    }
)

_spec(
    {
        "id": "pii_phone",
        "label": "Phone number",
        "severity": "low",
        "confidence": 0.7,
        "patterns": _re(r"\b(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}\b"),
    }
)

_spec(
    {
        "id": "pii_ip",
        "label": "IP address",
        "severity": "info",
        "confidence": 0.8,
        "patterns": _re(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    }
)

_spec(
    {
        "id": "secret_aws",
        "label": "AWS access key",
        "severity": "critical",
        "confidence": 0.97,
        "match": _match_aws,
    }
)

_spec(
    {
        "id": "secret_github",
        "label": "GitHub token",
        "severity": "critical",
        "confidence": 0.95,
        "match": _match_github_token,
    }
)

_spec(
    {
        "id": "secret_slack",
        "label": "Slack token",
        "severity": "critical",
        "confidence": 0.9,
        "match": _match_slack_token,
    }
)

_spec(
    {
        "id": "secret_openai",
        "label": "OpenAI API key",
        "severity": "critical",
        "confidence": 0.9,
        "match": _match_openai_token,
    }
)

_spec(
    {
        "id": "secret_jwt",
        "label": "JWT token",
        "severity": "high",
        "confidence": 0.8,
        "match": _match_jwt,
    }
)

_spec(
    {
        "id": "secret_private_key",
        "label": "Private key (PEM)",
        "severity": "critical",
        "confidence": 0.98,
        "match": _match_private_key,
    }
)

_spec(
    {
        "id": "secret_bearer",
        "label": "Bearer/token/API-key in plaintext",
        "severity": "high",
        "confidence": 0.7,
        "match": _match_generic_bearer,
    }
)


def rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity, 0)
