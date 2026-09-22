"""Locate and rewrite text fields inside LLM request/response JSON bodies.

Fields are addressed by JSON-pointer-style paths so redaction can be applied
precisely without re-serialising the whole object tree incorrectly.
"""

from __future__ import annotations

import json
from typing import Any, List, Tuple

TextChunk = Tuple[List[str], str]  # JSON pointer path segments, text value

_TEXT_FIELD_NAMES = ("content", "prompt", "text", "system", "query", "input", "description")


def extract_chunks(body: Any) -> List[TextChunk]:
    """Collect every string that may carry user/model content from an LLM body."""
    chunks: List[TextChunk] = []
    _walk(body, [], chunks)
    return chunks


def _walk(value: Any, path: List[str], out: List[TextChunk]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _walk(item, [*path, str(key)], out)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk(item, [*path, str(index)], out)
    elif isinstance(value, str):
        base = path[-1].lower() if path else ""
        if base in _TEXT_FIELD_NAMES or not _looks_like_meta(path):
            out.append((path, value))
    elif isinstance(value, (int, float)):
        return


def _looks_like_meta(path: List[str]) -> bool:
    flat = {str(p).lower() for p in path}
    return bool(flat & {"model", "id", "usage"})  # keep model/ids out of scanning


def apply_redaction(body: Any, path: List[str], replacement: str) -> Any:
    """Deep-copy ``body`` with the string at ``path`` replaced by ``replacement``."""
    node = body
    for part in path[:-1]:
        if isinstance(node, dict):
            node = node.get(part)
        elif isinstance(node, list):
            try:
                node = node[int(part)]
            except (ValueError, IndexError):
                return body
        else:
            return body
    last = path[-1]
    target = node
    if isinstance(target, dict) and last in target and isinstance(target[last], str):
        return _set_path(body, path, replacement)
    if isinstance(target, list):
        try:
            idx = int(last)
        except ValueError:
            return body
        if 0 <= idx < len(target) and isinstance(target[idx], str):
            return _set_path(body, path, replacement)
    return body


def _set_path(body: Any, path: List[str], value: Any) -> Any:
    result = _deep_copy(body)
    node = result
    for part in path[:-1]:
        if isinstance(node, dict):
            node = node.get(part)
        elif isinstance(node, list):
            node = node[int(part)]
        else:
            return body
    last = path[-1]
    if isinstance(node, dict):
        node[last] = value
    elif isinstance(node, list):
        node[int(last)] = value
    return result


def _deep_copy(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def body_text(body: str) -> str:
    """Best-effort plain-text view of a raw body for raw-mode scanning."""
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return body
    chunks = [text for _, text in extract_chunks(parsed)]
    return "\n".join(chunks)


def raw_to_json(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
