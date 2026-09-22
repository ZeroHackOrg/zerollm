"""Authentication: hashed API keys, OIDC/JWT, and mTLS peer mapping.

The configured mode is enforced by the gateway before any route decision:
every authenticated request resolves to a tenant identity and a set of scopes
used by RBAC checks.
"""

from __future__ import annotations

import hmac
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import jwt as pyjwt

from .config import AuthConfig, OIDCConfig, UpstreamConfig

__all__ = [
    "AuthContext",
    "Authenticator",
    "ScopedClient",
    "UnauthorizedError",
]

VALID_MATCH_ATTRS = ("subjectAltName", "subject")


class UnauthorizedError(Exception):
    def __init__(self, message: str, status: int = 401, headers: Optional[dict] = None) -> None:
        super().__init__(message)
        self.status = status
        self.headers = headers or {}


@dataclass
class AuthContext:
    tenant: str = ""
    subject: str = ""
    scopes: List[str] = field(default_factory=list)
    authenticated: bool = False

    @property
    def is_anonymous(self) -> bool:
        return not self.authenticated


class ScopedClient:
    """API-key identity backed by a config entry."""

    def __init__(self, name: str, tenant: str, scopes: List[str]) -> None:
        self.name = name
        self.tenant = tenant
        self.scopes = scopes


def header_token(request) -> str:
    """Extract the bearer/API token from Authorization or ``X-API-Key`` header."""
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    if auth.lower().startswith("apikey "):
        return auth[7:].strip()
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        return api_key.strip()
    return auth.strip()


class Authenticator:
    def __init__(self, config: AuthConfig, tenant_ids: List[str]) -> None:
        self.config = config
        self.mode = config.mode
        self._tenant_ids = set(tenant_ids)
        self._keys: Dict[str, ScopedClient] = {}
        for key in config.api_keys:
            self._keys[key.key_hash] = ScopedClient(key.name, key.tenant, key.scopes)
        self._jwks_client = None
        if config.mode == "oidc" and config.oidc.jwks_url:
            from jwt import PyJWKClient

            self._jwks_client = PyJWKClient(config.oidc.jwks_url)

        self._mtls_context: Optional[ssl.SSLContext] = None
        if config.mode == "mtls" and config.mtls.ca_cert_file:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_verify_locations(cafile=config.mtls.ca_cert_file)
            context.verify_mode = ssl.CERT_REQUIRED
            self._mtls_context = context

    def authenticate(self, request) -> AuthContext:
        if self.mode == "none":
            return AuthContext(tenant=self._tenant_for_request(request, fallback=""), authenticated=False)
        if self.mode == "mtls":
            return self._authenticate_mtls(request)
        token = header_token(request)
        if not token:
            raise UnauthorizedError("missing credentials")
        if self.mode == "api-key":
            return self._authenticate_api_key(token)
        if self.mode == "oidc":
            return self._authenticate_oidc(token)
        raise UnauthorizedError("unknown auth mode")

    async def authenticate_async(self, request) -> AuthContext:
        if self.mode == "oidc" and self._jwks_client is not None:
            return self._authenticate_oidc(header_token(request))
        return self.authenticate(request)

    def _tenant_for_request(self, request, fallback: str) -> str:
        tenant = request.headers.get("X-ZeroLLM-Tenant", "")
        return tenant if tenant and tenant in self._tenant_ids else fallback

    def _authenticate_api_key(self, token: str) -> AuthContext:
        import hashlib

        digest = "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()
        for stored, client in self._keys.items():
            if hmac.compare_digest(digest, stored):
                return AuthContext(
                    tenant=client.tenant, subject=client.name, scopes=client.scopes, authenticated=True
                )
        raise UnauthorizedError("invalid API key")

    def _authenticate_oidc(self, token: str) -> AuthContext:
        from typing import Any

        oidc: OIDCConfig = self.config.oidc
        key: Any = None
        try:
            if self._jwks_client is not None:
                key = self._jwks_client.get_signing_key_from_jwt(token).key
            if key is None:
                raise UnauthorizedError("no signing key available")
        except UnauthorizedError:
            raise
        except Exception as error:
            raise UnauthorizedError("could not resolve signing key") from error
        try:
            claims = pyjwt.decode(
                token, key, algorithms=["RS256"], audience=oidc.audience, issuer=oidc.issuer
            )
        except pyjwt.ExpiredSignatureError as error:
            raise UnauthorizedError("token expired") from error
        except pyjwt.InvalidTokenError as error:
            raise UnauthorizedError("invalid token") from error
        tenant = str(claims.get(oidc.tenant_claim, "") or claims.get("tenant", ""))
        if tenant not in self._tenant_ids and tenant:
            raise UnauthorizedError("tenant not permitted")
        return AuthContext(
            tenant=tenant,
            subject=str(claims.get("sub", "")),
            scopes=[str(s) for s in claims.get(oidc.roles_claim, [])],
            authenticated=True,
        )

    def _authenticate_mtls(self, request) -> AuthContext:
        transport = request.transport
        peercert = None
        if transport is not None:
            peercert = transport.get_extra_info("peercert")
        if not peercert:
            raise UnauthorizedError("client certificate required")
        for attr in VALID_MATCH_ATTRS:
            entries = peercert.get(attr)
            if not entries:
                continue
            if isinstance(entries, (list, tuple)):
                names = []
                for entry in entries:
                    if isinstance(entry, tuple):
                        _, value = entry
                        names.append(value)
                    else:
                        names.append(entry)
                # first DNS/SAN name maps to tenant id
                for name in names:
                    if name in self._tenant_ids:
                        return AuthContext(tenant=name, subject=name, authenticated=True)
            else:
                if entries in self._tenant_ids:
                    return AuthContext(tenant=entries, subject=entries, authenticated=True)
        raise UnauthorizedError("client certificate not mapped to a tenant")


def upstream_auth_headers(upstream: UpstreamConfig) -> dict:
    """Build the Authorization header for an upstream using its api_key_env."""
    import os

    key = os.environ.get(upstream.api_key_env, "") if upstream.api_key_env else ""
    if not key:
        return {}
    if upstream.type == "anthropic":
        return {"x-api-key": key, "anthropic-version": "2023-06-01"}
    return {"Authorization": f"Bearer {key}"}
