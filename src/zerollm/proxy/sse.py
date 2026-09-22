"""Streaming (SSE) response inspection with token-stream redaction/blocking.

SSE responses are reassembled into running assistant text. A lookahead window
holds back ``lookahead`` characters of output so that detectors can decide on
a token stream *before* the text is flushed to the client — enabling both
mid-stream blocking of prompt-injection/exfiltration and per-delta redaction
of PII/secrets.
"""

from __future__ import annotations

import json
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple

from ..detect.engine import DetectionEngine, Finding
from ..policy import PolicyDecision, PolicyEngine


class SSEBlocked(Exception):
    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__("stream blocked")
        self.decision = decision


class SSEStreamInspector:
    """Incremental SSE parser + policy enforcer for +45 delta content."""

    def __init__(
        self,
        engine: DetectionEngine,
        policy_engine: PolicyEngine,
        policy_id: str = "default",
        tenant: str = "",
        lookahead: int = 256,
        detectors: Optional[List[str]] = None,
    ) -> None:
        self.engine = engine
        self.policy_engine = policy_engine
        self.policy_id = policy_id
        self.tenant = tenant
        self.lookahead = max(64, lookahead)
        self.detectors = detectors

        self._buffer = b""
        self._content = ""  # rolling unflushed assistant text
        self._flushed_abs = 0  # absolute content length already emitted
        self._events: Deque[Dict] = deque()
        self._findings: List[Finding] = []
        self._last_scan_abs = -1
        self._decision: Optional[PolicyDecision] = None

    @property
    def content_length(self) -> int:
        return self._flushed_abs + len(self._content)

    async def inspect(self, chunk: bytes) -> bytes:
        self._buffer += chunk
        out = bytearray()
        events = self._consume_events()
        for event in events:
            delta = event.get("delta")
            event["start_abs"] = self.content_length
            if delta is not None:
                event["end_abs"] = self.content_length + len(delta)
                self._content += delta
            else:
                event["end_abs"] = event["start_abs"]
            self._events.append(event)

        await self._scan_if_needed()
        blocked = self._check_blocked()
        if blocked is not None:
            raise SSEBlocked(blocked)
        out.extend(self._flush())
        return bytes(out)

    async def finish(self) -> Tuple[bytes, PolicyDecision]:
        self._buffer = b""
        if self._content:
            await self._scan_if_needed(force=True)
        blocked = self._check_blocked(force=True)
        out = bytearray()
        if blocked is not None:
            raise SSEBlocked(blocked)
        out.extend(self._flush(force=True))
        decision = self._decision or PolicyDecision(action="allow", fail_mode=self.policy_engine.fail_mode)
        return bytes(out), decision

    # --- parsing ------------------------------------------------------------
    def _consume_events(self) -> List[Dict]:
        events: List[Dict] = []
        while True:
            idx_crlf = self._buffer.find(b"\r\n\r\n")
            idx_lf = self._buffer.find(b"\n\n")
            if idx_crlf == -1:
                boundary, advance = idx_lf, 2
            elif idx_lf == -1:
                boundary, advance = idx_crlf, 4
            else:
                boundary, advance = (idx_crlf, 4) if idx_crlf <= idx_lf else (idx_lf, 2)
            if boundary == -1:
                break
            raw = self._buffer[:boundary]
            self._buffer = self._buffer[boundary + advance :]
            parsed = self._parse_event(raw)
            if parsed is not None:
                events.append(parsed)
        return events

    def _parse_event(self, raw: bytes) -> Optional[Dict]:
        if not raw.strip():
            return None
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            return None
        data_parts: List[str] = []
        for line in text.splitlines():
            if line.startswith("data:"):
                data_parts.append(line[5:].strip())
            elif line.startswith("data :") or line.strip().startswith("data"):
                continue
        if not data_parts:
            return {"raw": raw, "data": None, "delta": None, "done": False}
        data = "\n".join(data_parts)
        if data == "[DONE]":
            return {"raw": raw, "data": None, "delta": None, "done": True}
        try:
            payload = json.loads(data)
        except ValueError:
            return {"raw": raw, "data": data, "delta": None, "done": False}
        delta = self._delta_text(payload)
        return {
            "raw": raw,
            "data": data,
            "json": payload,
            "delta": delta,
            "done": False,
        }

    @staticmethod
    def _delta_text(payload: dict) -> Optional[str]:
        for choice in payload.get("choices") or []:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message")
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                return message["content"]
            delta = choice.get("delta")
            if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                return delta["content"]
        return None

    # --- detection / decision ----------------------------------------------
    async def _scan_if_needed(self, force: bool = False) -> None:
        if not self._content:
            return
        changed = self._flushed_abs + len(self._content) - self._last_scan_abs
        if not force and changed < 32:
            return
        self._last_scan_abs = self.content_length
        self._findings = await self.engine.scan_async(self._content, self.detectors)
        decision = self.policy_engine.evaluate("stream", self._findings, self.policy_id, self.tenant)
        self._decision = decision if decision.action != "allow" else self._decision

    def _check_blocked(self, force: bool = False) -> Optional[PolicyDecision]:
        if self._decision is None:
            return None
        candidate = self.content_length if force else self.content_length - self.lookahead
        decision = self._decision
        if decision.action == "block":
            for finding in decision.findings:
                start_abs = self._flushed_abs + finding.start
                end_abs = self._flushed_abs + finding.end
                if start_abs >= self._flushed_abs and end_abs <= candidate:
                    return decision
            for rule in decision.rule_hits:
                if rule.action == "block":
                    for finding in rule.findings:
                        start_abs = self._flushed_abs + finding.start
                        end_abs = self._flushed_abs + finding.end
                        if start_abs >= self._flushed_abs and end_abs <= candidate:
                            return decision
        return None

    # --- emission -------------------------------------------------------------
    def _flush(self, force: bool = False) -> bytes:
        out = bytearray()
        boundary_abs = self.content_length if force else self.content_length - self.lookahead
        base = self._flushed_abs  # content base during this flush call
        redact_rules = [
            r for r in (self._decision.rule_hits if self._decision else []) if r.action == "redact"
        ]

        new_flushed = base
        while self._events:
            event = self._events[0]
            end_abs = event["end_abs"]
            if not force and end_abs > boundary_abs:
                break
            self._events.popleft()
            out.extend(self._emit_event(event, redact_rules, base))
            if event.get("delta"):
                new_flushed = end_abs

        dropped = new_flushed - base
        if dropped > 0:
            self._content = self._content[dropped:]
            self._findings = [
                Finding(
                    detector=f.detector,
                    label=f.label,
                    severity=f.severity,
                    confidence=f.confidence,
                    start=f.start - dropped,
                    end=f.end - dropped,
                    extra=f.extra,
                )
                for f in self._findings
                if f.end > dropped
            ]
            self._flushed_abs = new_flushed
        return bytes(out)

    def _emit_event(self, event: Dict, redact_rules: List, base: int) -> bytes:
        raw = event.get("raw")
        delta = event.get("delta")
        if delta is None or not raw:
            if event.get("done"):
                return raw or b"data: [DONE]\n\n"
            return raw or b""
        redacted = self._apply_replace(delta, event["start_abs"], event["end_abs"], redact_rules, base)
        if redacted is None or redacted == delta:
            return raw
        payload = json.loads(json.dumps(event.get("json")))
        payload = self._set_delta(payload, redacted)
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        text = raw.decode("utf-8", errors="replace")
        return self._replace_data_line(text, data).encode("utf-8")

    def _apply_replace(
        self,
        text: str,
        start_abs: int,
        end_abs: int,
        redact_rules: List,
        base: int,
    ) -> Optional[str]:
        """Redact ``text`` (one delta) where redaction findings overlap it.

        Returns ``None`` when nothing overlaps (keeps the delta untouched).
        """
        spans: List[Tuple[int, int]] = []
        replace = redact_rules[0].replace_with if redact_rules else "[REDACTED]"
        for rule in redact_rules:
            for finding in rule.findings:
                fa = base + finding.start  # absolute finding span
                fb = base + finding.end
                lo = max(fa, start_abs) - start_abs
                hi = min(fb, end_abs) - start_abs
                if lo < hi:
                    spans.append((lo, hi))
        if not spans:
            return None
        spans.sort()
        merged: List[Tuple[int, int]] = []
        for lo, hi in spans:
            if merged and lo <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
            else:
                merged.append((lo, hi))
        parts = []
        cursor = 0
        for lo, hi in merged:
            parts.append(text[cursor:lo])
            parts.append(replace)
            cursor = hi
        parts.append(text[cursor:])
        return "".join(parts)

    @staticmethod
    def _overlaps(finding: Finding, span: Tuple[int, int]) -> bool:
        fs, fe = finding.start, finding.end
        return fs < span[1] and fe > span[0]

    @staticmethod
    def _set_delta(payload: dict, content: str) -> dict:
        payload = json.loads(json.dumps(payload))
        for choice in payload.get("choices") or []:
            if not isinstance(choice, dict):
                continue
            if isinstance(choice.get("message"), dict):
                choice["message"]["content"] = content
            if isinstance(choice.get("delta"), dict) and "content" in choice["delta"]:
                choice["delta"]["content"] = content
                return payload
        return payload

    @staticmethod
    def _replace_data_line(text: str, new_data: str) -> str:
        lines = []
        replaced = False
        for line in text.splitlines():
            if not replaced and line.startswith("data:"):
                lines.append(f"data:{new_data}")
                replaced = True
            else:
                lines.append(line)
        return "\n".join(lines) + "\n\n"
