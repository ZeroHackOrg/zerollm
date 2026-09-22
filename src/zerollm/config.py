"""ZeroLLM configuration: load, validate, merge env overrides.

Configuration is YAML validated against a JSON Schema (``config.schema.json``),
then cross-referenced semantically. String values may embed ``${ENV_VAR}``
references which are expanded at load time, so secrets and per-environment
tuning never need to live inside the committed file.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml
from jsonschema import Draft202012Validator

from . import _resources

__all__ = [
    "Config",
    "ConfigError",
    "expand_env_vars",
    "load_config",
    "validate_config",
]

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MiB
DEFAULT_REQUEST_TIMEOUT_S = 120.0
DEFAULT_GRACEFUL_SHUTDOWN_S = 10.0
DEFAULT_SSE_BUFFER_BYTES = 64 * 1024


class ConfigError(Exception):
    """Raised when configuration is malformed or semantically invalid."""


@dataclass
class LimitsConfig:
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    request_timeout_s: float = DEFAULT_REQUEST_TIMEOUT_S
    max_sse_buffered_bytes: int = DEFAULT_SSE_BUFFER_BYTES
    graceful_shutdown_timeout_s: float = DEFAULT_GRACEFUL_SHUTDOWN_S


@dataclass
class TLSConfig:
    cert_file: str = ""
    key_file: str = ""

    @property
    def enabled(self) -> bool:
        return bool(self.cert_file and self.key_file)


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    tls: TLSConfig = field(default_factory=TLSConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)


@dataclass
class ApiKeyConfig:
    name: str
    tenant: str
    key_hash: str = ""
    scopes: List[str] = field(default_factory=list)
    _raw: Optional[str] = None


@dataclass
class OIDCConfig:
    issuer: str = ""
    audience: str = ""
    jwks_url: str = ""
    roles_claim: str = "roles"
    tenant_claim: str = "tenant"


@dataclass
class MTLSConfig:
    ca_cert_file: str = ""


@dataclass
class AuthConfig:
    mode: str = "none"
    header: str = "Authorization"
    api_keys: List[ApiKeyConfig] = field(default_factory=list)
    oidc: OIDCConfig = field(default_factory=OIDCConfig)
    mtls: MTLSConfig = field(default_factory=MTLSConfig)


@dataclass
class QuotaConfig:
    rpm: int = 0
    rpd: int = 0
    tokens_per_min: int = 0


@dataclass
class TenantConfig:
    id: str
    quotas: QuotaConfig = field(default_factory=QuotaConfig)


@dataclass
class CircuitBreakerConfig:
    max_failures: int = 5
    cooldown_s: float = 30.0
    threshold: float = 0.5


@dataclass
class UpstreamConfig:
    id: str
    type: str = "openai"
    base_url: str = ""
    api_key_env: str = ""
    timeout_s: float = DEFAULT_REQUEST_TIMEOUT_S
    weight: int = 1
    verify_tls: bool = True
    circuit_breaker: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)


@dataclass
class RouteConfig:
    path: str
    upstreams: List[str] = field(default_factory=list)
    policy: str = "default"
    methods: List[str] = field(default_factory=lambda: ["POST"])


@dataclass
class DecisionConfig:
    id: str
    action: str
    detector: str
    on: str = "request"
    min_confidence: float = 0.5
    max_severity: str = "critical"
    replace_with: str = "[REDACTED]"
    tenants: List[str] = field(default_factory=lambda: ["*"])
    reason: str = ""


@dataclass
class PolicyConfig:
    id: str
    decisions: List[DecisionConfig] = field(default_factory=list)


@dataclass
class DetectorConfig:
    id: str
    type: str
    endpoint: str = ""
    api_key_env: str = ""
    model: str = ""
    threshold: float = 0.8
    timeout_s: float = 10.0


@dataclass
class SigningConfig:
    private_key_file: str = ""
    public_key_file: str = ""


@dataclass
class RotationConfig:
    max_bytes: int = 100 * 1024 * 1024
    max_files: int = 10
    fallback_dir: str = ""


@dataclass
class SinkConfig:
    type: str = "stdout"
    url: str = ""
    path: str = ""
    bucket: str = ""
    region: str = ""
    auth_token_env: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    max_bytes: int = 0
    max_files: int = 10


@dataclass
class AuditConfig:
    enabled: bool = True
    path: str = "zerollm_audit.jsonl"
    signing: SigningConfig = field(default_factory=SigningConfig)
    rotation: RotationConfig = field(default_factory=RotationConfig)
    sinks: List[SinkConfig] = field(default_factory=lambda: [SinkConfig(type="stdout")])


@dataclass
class OTelConfig:
    enabled: bool = False
    service_name: str = "zerollm"
    endpoint: str = ""


@dataclass
class RedisConfig:
    enabled: bool = False
    url: str = "redis://localhost:6379/0"


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "json"


@dataclass
class Config:
    schema: str = ""
    mode: str = "fail-closed"
    server: ServerConfig = field(default_factory=ServerConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    tenants: List[TenantConfig] = field(default_factory=list)
    upstreams: List[UpstreamConfig] = field(default_factory=list)
    routes: List[RouteConfig] = field(default_factory=list)
    policies: Dict[str, PolicyConfig] = field(default_factory=lambda: {"default": PolicyConfig(id="default")})
    detectors: List[DetectorConfig] = field(default_factory=list)
    audit: AuditConfig = field(default_factory=AuditConfig)
    otel: OTelConfig = field(default_factory=OTelConfig)
    redis: RedisConfig = field(default_factory=RedisConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    def policy(self, policy_id: str = "default") -> PolicyConfig:
        return self.policies.get(policy_id, self.policies["default"])


def load_config(path: str) -> Config:
    """Load, validate and build a :class:`Config` from a YAML file."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw: Any = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as error:
        raise ConfigError(f"could not read config {path!r}: {error}") from error

    if not isinstance(raw, dict):
        raise ConfigError(f"config {path!r} must be a YAML object")

    raw = expand_env_vars(raw)
    return build_config(raw, source=path)


def load_config_dict(data: Dict[str, Any]) -> Config:
    return build_config(expand_env_vars(data), source="<dict>")


def expand_env_vars(value: Any) -> Any:
    """Recursively expand ``${ENV_VAR}`` references in all string values."""
    if isinstance(value, str):
        return _ENV_REF.sub(lambda m: os.environ.get(m.group(1), m.group(0)), value)
    if isinstance(value, list):
        return [expand_env_vars(item) for item in value]
    if isinstance(value, dict):
        return {key: expand_env_vars(item) for key, item in value.items()}
    return value


def validate_config(data: Dict[str, Any]) -> List[str]:
    """Validate raw config dict against the bundled JSON Schema.

    Returns a list of human-readable error messages; empty when valid.
    """
    schema = _resources.load_schema("config.schema.json")
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    return ["%s: %s" % (".".join(str(p) for p in e.absolute_path) or "/", e.message) for e in errors]


def build_config(raw: Dict[str, Any], source: str = "<config>") -> Config:
    errors = validate_config(raw)
    if errors:
        raise ConfigError("invalid config %s:\n  - %s" % (source, "\n  - ".join(errors[:25])))

    cfg = Config(schema=raw.get("schema", ""), mode=raw.get("mode", "fail-closed"))

    server = raw.get("server", {})
    tls = server.get("tls", {})
    limits = server.get("limits", {})
    cfg.server = ServerConfig(
        host=server.get("host", "0.0.0.0"),
        port=int(server.get("port", 8080)),
        tls=TLSConfig(cert_file=tls.get("cert_file", ""), key_file=tls.get("key_file", "")),
        limits=LimitsConfig(
            max_body_bytes=int(limits.get("max_body_bytes", DEFAULT_MAX_BODY_BYTES)),
            request_timeout_s=float(limits.get("request_timeout_s", DEFAULT_REQUEST_TIMEOUT_S)),
            max_sse_buffered_bytes=int(limits.get("max_sse_buffered_bytes", DEFAULT_SSE_BUFFER_BYTES)),
            graceful_shutdown_timeout_s=float(
                limits.get("graceful_shutdown_timeout_s", DEFAULT_GRACEFUL_SHUTDOWN_S)
            ),
        ),
    )

    auth = raw.get("auth", {})
    api_keys = []
    for key in auth.get("api_keys", []):
        key_hash = key.get("key_hash", "")
        if key.get("key"):
            key_hash = _hash_secret(key["key"])
        api_keys.append(
            ApiKeyConfig(
                name=key["name"],
                tenant=key["tenant"],
                key_hash=key_hash,
                scopes=list(key.get("scopes", [])),
                _raw=key.get("key"),
            )
        )
    oidc = auth.get("oidc", {})
    mtls = auth.get("mtls", {})
    cfg.auth = AuthConfig(
        mode=auth.get("mode", "none"),
        header=auth.get("header", "Authorization"),
        api_keys=api_keys,
        oidc=OIDCConfig(
            issuer=oidc.get("issuer", ""),
            audience=oidc.get("audience", ""),
            jwks_url=oidc.get("jwks_url", ""),
            roles_claim=oidc.get("roles_claim", "roles"),
            tenant_claim=oidc.get("tenant_claim", "tenant"),
        ),
        mtls=MTLSConfig(ca_cert_file=mtls.get("ca_cert_file", "")),
    )

    for tenant in raw.get("tenants", []):
        quotas = tenant.get("quotas", {})
        cfg.tenants.append(
            TenantConfig(
                id=tenant["id"],
                quotas=QuotaConfig(
                    rpm=int(quotas.get("rpm", 0)),
                    rpd=int(quotas.get("rpd", 0)),
                    tokens_per_min=int(quotas.get("tokens_per_min", 0)),
                ),
            )
        )

    for upstream in raw.get("upstreams", []):
        cb = upstream.get("circuit_breaker", {})
        cfg.upstreams.append(
            UpstreamConfig(
                id=upstream["id"],
                type=upstream.get("type", "openai"),
                base_url=upstream["base_url"].rstrip("/"),
                api_key_env=upstream.get("api_key_env", ""),
                timeout_s=float(upstream.get("timeout_s", DEFAULT_REQUEST_TIMEOUT_S)),
                weight=int(upstream.get("weight", 1)),
                verify_tls=bool(upstream.get("verify_tls", True)),
                circuit_breaker=CircuitBreakerConfig(
                    max_failures=int(cb.get("max_failures", 5)),
                    cooldown_s=float(cb.get("cooldown_s", 30.0)),
                    threshold=float(cb.get("threshold", 0.5)),
                ),
            )
        )

    for route in raw.get("routes", []):
        cfg.routes.append(
            RouteConfig(
                path=route["path"],
                upstreams=list(route["upstreams"]),
                policy=route.get("policy", "default"),
                methods=list(route.get("methods", ["POST"])),
            )
        )

    for policy_id, policy in raw.get("policies", {"default": {}}).items():
        decisions = [
            DecisionConfig(
                id=d.get("id", f"{policy_id}-d{i}"),
                action=d["action"],
                detector=d["detector"],
                on=d.get("on", "request"),
                min_confidence=float(d.get("min_confidence", 0.5)),
                max_severity=d.get("max_severity", "critical"),
                replace_with=d.get("replace_with", "[REDACTED]"),
                tenants=list(d.get("tenants", ["*"])),
                reason=d.get("reason", ""),
            )
            for i, d in enumerate(policy.get("decisions", []))
        ]
        cfg.policies[policy_id] = PolicyConfig(id=policy_id, decisions=decisions)

    for detector in raw.get("detectors", []):
        cfg.detectors.append(
            DetectorConfig(
                id=detector["id"],
                type=detector["type"],
                endpoint=detector.get("endpoint", ""),
                api_key_env=detector.get("api_key_env", ""),
                model=detector.get("model", ""),
                threshold=float(detector.get("threshold", 0.8)),
                timeout_s=float(detector.get("timeout_s", 10.0)),
            )
        )

    audit = raw.get("audit", {})
    signing = audit.get("signing", {})
    rotation = audit.get("rotation", {})
    sinks = [
        SinkConfig(
            type=s.get("type", "stdout"),
            url=s.get("url", ""),
            path=s.get("path", ""),
            bucket=s.get("bucket", ""),
            region=s.get("region", ""),
            auth_token_env=s.get("auth_token_env", ""),
            headers=dict(s.get("headers", {})),
            max_bytes=int(s.get("max_bytes", 0)),
            max_files=int(s.get("max_files", 10)),
        )
        for s in audit.get("sinks", [{"type": "stdout"}])
    ]
    cfg.audit = AuditConfig(
        enabled=bool(audit.get("enabled", True)),
        path=audit.get("path", "zerollm_audit.jsonl"),
        signing=SigningConfig(
            private_key_file=signing.get("private_key_file", ""),
            public_key_file=signing.get("public_key_file", ""),
        ),
        rotation=RotationConfig(
            max_bytes=int(rotation.get("max_bytes", 100 * 1024 * 1024)),
            max_files=int(rotation.get("max_files", 10)),
            fallback_dir=rotation.get("fallback_dir", ""),
        ),
        sinks=sinks,
    )

    otel = raw.get("otel", {})
    cfg.otel = OTelConfig(
        enabled=bool(otel.get("enabled", False)),
        service_name=otel.get("service_name", "zerollm"),
        endpoint=otel.get("endpoint", ""),
    )

    redis = raw.get("redis", {})
    cfg.redis = RedisConfig(
        enabled=bool(redis.get("enabled", False)), url=redis.get("url", "redis://localhost:6379/0")
    )

    logging = raw.get("logging", {})
    cfg.logging = LoggingConfig(level=logging.get("level", "INFO"), format=logging.get("format", "json"))

    _semantic_check(cfg)
    return cfg


def _semantic_check(cfg: Config) -> None:
    upstream_ids = {u.id for u in cfg.upstreams}
    tenant_ids = {t.id for t in cfg.tenants}
    policy_ids = set(cfg.policies)

    for route in cfg.routes:
        missing = [u for u in route.upstreams if u not in upstream_ids]
        if missing:
            raise ConfigError("route %r references unknown upstreams: %s" % (route.path, missing))
        if route.policy not in policy_ids:
            raise ConfigError("route %r references unknown policy %r" % (route.path, route.policy))

    if cfg.auth.mode == "api-key" and not cfg.auth.api_keys:
        raise ConfigError("auth.mode=api-key requires at least one api_keys entry")

    if cfg.auth.mode == "api-key":
        for key in cfg.auth.api_keys:
            if not key.key_hash and not key._raw:
                raise ConfigError("api key %r must define key or key_hash" % key.name)
            if key.tenant not in tenant_ids:
                raise ConfigError("api key %r references unknown tenant %r" % (key.name, key.tenant))

    if cfg.auth.mode == "oidc" and (not cfg.auth.oidc.issuer or not cfg.auth.oidc.audience):
        raise ConfigError("auth.mode=oidc requires oidc.issuer and oidc.audience")

    if cfg.mode not in ("fail-open", "fail-closed"):
        raise ConfigError("mode must be 'fail-open' or 'fail-closed'")


def _hash_secret(secret: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(secret.encode("utf-8")).hexdigest()
