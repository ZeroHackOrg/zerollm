# tests/conftest.py
import asyncio
import hashlib

import pytest

from zerollm.config import load_config_dict

SCHEMA_URL = "https://zerohack.org/schemas/zerollm/config.schema.json"


def _hash(secret: str) -> str:
    return "sha256:" + hashlib.sha256(secret.encode("utf-8")).hexdigest()


def base_raw_config(**overrides) -> dict:
    raw = {
        "schema": SCHEMA_URL,
        "mode": "fail-closed",
        "server": {
            "host": "127.0.0.1",
            "port": 8080,
            "limits": {"max_body_bytes": 1024 * 1024, "request_timeout_s": 30},
        },
        "auth": {"mode": "none"},
        "tenants": [{"id": "default"}, {"id": "acme"}],
        "upstreams": [{"id": "up", "type": "openai", "base_url": "http://127.0.0.1:1", "verify_tls": False}],
        "routes": [
            {"path": "/v1/chat/completions", "upstreams": ["up"], "policy": "default", "methods": ["POST"]},
            {"path": "/v1/completions", "upstreams": ["up"], "policy": "default", "methods": ["POST"]},
        ],
        "policies": {
            "default": {
                "decisions": [
                    {
                        "id": "block-inj",
                        "action": "block",
                        "on": "request",
                        "detector": "prompt_injection",
                        "min_confidence": 0.7,
                    },
                    {
                        "id": "block-jb",
                        "action": "block",
                        "on": "request",
                        "detector": "dan_jailbreak",
                        "min_confidence": 0.75,
                    },
                    {
                        "id": "redact-cc",
                        "action": "redact",
                        "on": "both",
                        "detector": "pii_credit_card",
                        "replace_with": "[REDACTED]",
                    },
                    {
                        "id": "redact-aws",
                        "action": "redact",
                        "on": "both",
                        "detector": "secret_aws",
                        "replace_with": "[REDACTED]",
                    },
                ]
            }
        },
        "audit": {"enabled": False},
    }
    raw.update(overrides)
    return raw


@pytest.fixture
def config_factory(tmp_path):
    def _make(**overrides) -> tuple:
        raw = base_raw_config(**overrides)
        cfg = load_config_dict(raw)
        return cfg

    return _make


@pytest.fixture
def raw_config():
    return base_raw_config()


@pytest.fixture
def run_async():
    return lambda coro: asyncio.get_event_loop().run_until_complete(coro)
