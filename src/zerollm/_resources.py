"""Bundled package resources (JSON Schema, defaults)."""

from __future__ import annotations

import json
from typing import Any, Dict

_SCHEMAS: Dict[str, Any] = {}


def load_schema(name: str) -> Dict[str, Any]:
    """Load a bundled JSON Schema, cached after first read."""
    if name in _SCHEMAS:
        return _SCHEMAS[name]
    import os

    here = os.path.dirname(__file__)
    with open(os.path.join(here, "schema", name), "r", encoding="utf-8") as handle:
        data = json.load(handle)
    _SCHEMAS[name] = data
    return data
