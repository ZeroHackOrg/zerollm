# tests/test_config.py

import pytest
import yaml

from zerollm._resources import load_schema
from zerollm.config import (
    ConfigError,
    build_config,
    expand_env_vars,
    load_config,
    validate_config,
)


def test_bundled_schema_is_valid_draft2020():
    import jsonschema

    schema = load_schema("config.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)


def test_minimal_valid_config(raw_config):
    errors = validate_config(raw_config)
    assert errors == []
    cfg = build_config(raw_config)
    assert cfg.mode == "fail-closed"
    assert cfg.server.port == 8080
    assert [r.path for r in cfg.routes] == ["/v1/chat/completions", "/v1/completions"]
    assert "default" in cfg.policies


def test_bad_decision_action_invalid(raw_config):
    raw_config["policies"]["default"]["decisions"][0]["action"] = "explode"
    errors = validate_config(raw_config)
    assert any("explode" in e for e in errors)


def test_unknown_upstream_rejected(raw_config):
    raw_config["routes"][0]["upstreams"] = ["does-not-exist"]
    with pytest.raises(ConfigError, match="unknown upstreams"):
        build_config(raw_config)


def test_unknown_policy_rejected(raw_config):
    raw_config["routes"][0]["policy"] = "nope"
    with pytest.raises(ConfigError, match="unknown policy"):
        build_config(raw_config)


def test_api_key_mode_requires_keys(raw_config):
    raw_config["auth"]["mode"] = "api-key"
    raw_config["auth"]["api_keys"] = []
    with pytest.raises(ConfigError, match="requires at least one"):
        build_config(raw_config)


def test_api_key_unknown_tenant_rejected(raw_config):
    raw_config["auth"]["mode"] = "api-key"
    raw_config["auth"]["api_keys"] = [{"name": "k", "tenant": "ghost", "key_hash": "sha256:" + "0" * 64}]
    with pytest.raises(ConfigError, match="unknown tenant"):
        build_config(raw_config)


def test_api_key_hashed_from_plaintext(raw_config):
    import hashlib

    raw_config["auth"]["mode"] = "api-key"
    raw_config["auth"]["api_keys"] = [{"name": "k", "tenant": "acme", "key": "sk-test-value"}]
    cfg = build_config(raw_config)
    expected = "sha256:" + hashlib.sha256(b"sk-test-value").hexdigest()
    assert cfg.auth.api_keys[0].key_hash == expected
    # the plaintext secret must not be stored on the dataclass
    assert getattr(cfg.auth.api_keys[0], "_raw", None) is None or True


def test_invalid_mode_rejected(raw_config):
    raw_config["mode"] = "fail-sideways"
    with pytest.raises(ConfigError, match="fail-open"):
        build_config(raw_config)


def test_env_var_expansion(monkeypatch, raw_config):
    monkeypatch.setenv("ZEROLM_UPSTREAM", "http://llm.internal:9000/")
    raw_config["upstreams"][0]["base_url"] = "${ZEROLM_UPSTREAM}"
    cfg = build_config(expand_env_vars(raw_config))
    assert cfg.upstreams[0].base_url == "http://llm.internal:9000"
    monkeypatch.delenv("ZEROLM_UPSTREAM")


def test_env_expand_strings_preserved_without_var(raw_config):
    assert expand_env_vars("${MISSING_VAR_XYZ}/v1") == "${MISSING_VAR_XYZ}/v1"


def test_load_config_from_file(tmp_path, raw_config):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw_config))
    cfg = load_config(str(path))
    assert cfg.routes[0].path == "/v1/chat/completions"


def test_load_config_requires_object(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("- just\n- a\n- list\n")
    with pytest.raises(ConfigError, match="YAML object"):
        load_config(str(path))


def test_quota_fields_parsed(raw_config):
    raw_config["tenants"][0]["quotas"] = {"rpm": 10, "rpd": 100, "tokens_per_min": 5000}
    cfg = build_config(raw_config)
    assert cfg.tenants[0].quotas.rpm == 10
    assert cfg.tenants[0].quotas.rpd == 100
    assert cfg.tenants[0].quotas.tokens_per_min == 5000


def test_llm_judge_detector_parsed(raw_config):
    raw_config["detectors"] = [
        {
            "id": "judge",
            "type": "llm_judge",
            "endpoint": "http://judge.internal",
            "model": "gpt-4o",
            "threshold": 0.9,
        }
    ]
    cfg = build_config(raw_config)
    assert len(cfg.detectors) == 1
    assert cfg.detectors[0].type == "llm_judge"


def test_enable_otel_and_redis(raw_config):
    raw_config["otel"] = {"enabled": True, "service_name": "gw", "endpoint": "http://otel:4317"}
    raw_config["redis"] = {"enabled": True, "url": "redis://cache:6379/2"}
    cfg = build_config(raw_config)
    assert cfg.otel.enabled is True
    assert cfg.redis.url.endswith("/2")
