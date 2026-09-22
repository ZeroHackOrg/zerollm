"""Tamper-evident audit logging.

Each record is chained to the previous via SHA-256 and, when configured, signed
with an Ed25519/ECDSA private key so a public key can later verify the whole
log. Records fan out to pluggable sinks: JSONL file (with size rotation),
stdout, HTTP (SIEM) and S3 (optional boto3).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, List, Optional

from .config import AuditConfig, SinkConfig

__all__ = [
    "AuditSigner",
    "FileSink",
    "HttpSink",
    "S3Sink",
    "StdoutSink",
    "ZeroLLMAuditLogger",
    "build_sink",
]

_external = ThreadPoolExecutor(max_workers=4, thread_name_prefix="zerollm-audit")


class AuditSigner:
    """Signs audit payload digests with a private Ed25519/ECDSA key (PEM)."""

    def __init__(self, private_key_file: str) -> None:
        if not private_key_file:
            raise ValueError("private_key_file is required")
        from cryptography.hazmat.primitives import serialization

        with open(private_key_file, "rb") as handle:
            self._key = serialization.load_pem_private_key(handle.read(), password=None)
        self._public_pem = (
            self._key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )

    def signature_for(self, blob: str) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519

        if isinstance(self._key, ed25519.Ed25519PrivateKey):
            sig = self._key.sign(blob.encode("utf-8"))
        elif isinstance(self._key, ec.EllipticCurvePrivateKey):
            sig = self._key.sign(blob.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        else:
            raise TypeError("unsupported key type; use Ed25519 or ECDSA")
        import base64

        return base64.b64encode(sig).decode("utf-8")

    @property
    def public_pem(self) -> str:
        return self._public_pem

    @staticmethod
    def verify(public_key_pem: str, blob: str, signature_b64: str) -> bool:
        import base64

        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519

        try:
            key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
            sig = base64.b64decode(signature_b64)
            if isinstance(key, ed25519.Ed25519PublicKey):
                key.verify(sig, blob.encode("utf-8"))
            elif isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(sig, blob.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
            else:
                return False
            return True
        except Exception:
            return False


class StdoutSink:
    def __init__(self, config: SinkConfig) -> None:
        self.config = config

    def emit(self, record: dict) -> None:
        print(json.dumps(record, default=str))


class FileSink:
    """Append-only JSONL writer with size-based rotation."""

    def __init__(self, config: SinkConfig) -> None:
        self.path = Path(config.path or config.url or "zerollm_audit.jsonl")
        self.max_bytes = int(config.max_bytes or 0)
        self.max_files = int(config.max_files or 10)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, record: dict) -> None:
        with self._lock:
            if self.max_bytes and self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                self._rotate()
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, default=str) + "\n")

    def _rotate(self) -> None:
        for i in range(self.max_files - 1, 0, -1):
            src = Path(f"{self.path}.{i - 1}")
            dst = Path(f"{self.path}.{i}")
            if src.exists():
                if dst.exists():
                    dst.unlink()
                src.rename(dst)
        Path(f"{self.path}.0").unlink(missing_ok=True)
        self.path.rename(f"{self.path}.0")


class HttpSink:
    """Delivers records to a SIEM / log endpoint (Splunk HEC, Loki, etc.)."""

    def __init__(self, config: SinkConfig) -> None:
        self.config = config
        self._token = os.environ.get(config.auth_token_env, "") if config.auth_token_env else ""

    def emit(self, record: dict) -> None:
        headers = dict(self.config.headers)
        headers.setdefault("Content-Type", "application/json")
        if self._token:
            headers.setdefault("Authorization", f"Bearer {self._token}")
        body = json.dumps(record, default=str).encode("utf-8")
        request = urllib.request.Request(self.config.url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status >= 300:
                raise RuntimeError(f"audit sink HTTP {response.status}")


class S3Sink:
    """Streams records to S3 (requires the ``s3`` extra)."""

    def __init__(self, config: SinkConfig) -> None:
        self.config = config
        from zerollm._compat import boto3_available

        if not boto3_available():
            raise RuntimeError("S3 audit sink requires boto3 (install zerollm[s3])")
        import boto3

        self._client = boto3.client("s3", region_name=config.region or None)

    def emit(self, record: dict) -> None:
        import uuid

        key = f"zerollm/{time.strftime('%Y/%m/%d')}/{uuid.uuid4().hex}.jsonl"
        self._client.put_object(
            Bucket=self.config.bucket,
            Key=key,
            Body=(json.dumps(record, default=str) + "\n").encode("utf-8"),
        )


def build_sink(config: SinkConfig):
    mapping = {"stdout": StdoutSink, "file": FileSink, "http": HttpSink, "s3": S3Sink}
    sink = mapping[config.type](config)
    if isinstance(sink, FileSink):
        return sink
    return sink


class ZeroLLMAuditLogger:
    """Append-only, hash-chained, optionally signed audit log."""

    def __init__(
        self,
        path: str = "zerollm_audit.jsonl",
        signer: Optional[AuditSigner] = None,
        rotation: Optional[dict] = None,
        sinks: Optional[List[Any]] = None,
        config: Optional[AuditConfig] = None,
    ) -> None:
        self._lock = threading.Lock()
        self._bonsai: List[dict] = []

        if config is not None:
            path = config.path
            if config.signing.private_key_file:
                signer = AuditSigner(config.signing.private_key_file)
            rotation = {"max_bytes": config.rotation.max_bytes, "max_files": config.rotation.max_files}
            if sinks is None:
                sinks = [build_sink(s) for s in config.sinks]

        self.path = Path(path)
        self.signer = signer
        self.sinks: List[Any] = list(sinks or [])
        rotation = rotation or {}
        if not self.sinks:
            self.sinks.append(
                FileSink(
                    SinkConfig(
                        type="file",
                        path=str(self.path),
                        max_bytes=int(rotation.get("max_bytes", 0)),
                        max_files=int(rotation.get("max_files", 10)),
                    )
                )
            )
        self._tail_hash = self._load_existing()

    def _load_existing(self) -> Optional[str]:
        if not self.path.exists():
            return None
        last = None
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            last = json.loads(line)
        if last is None:
            return None
        self._bonsai.append(last)
        return last["record_hash"]

    def log(self, event: str, details: dict, severity: str = "warning") -> dict:
        record = self._make_record(event, details, severity)
        with self._lock:
            self._tail_hash = record["record_hash"]
            self._bonsai.append(record)
            self._emit(record)
        return record

    async def alog(self, event: str, details: dict, severity: str = "warning") -> dict:
        record = self._make_record(event, details, severity)
        with self._lock:
            self._tail_hash = record["record_hash"]
            self._bonsai.append(record)
        await asyncio.get_running_loop().run_in_executor(_external, self._emit, record)
        return record

    def _make_record(self, event: str, details: dict, severity: str) -> dict:
        previous = self._tail_hash
        payload = {"event": event, "severity": severity, "details": details, "ts": time.time()}
        record = {
            "payload": payload,
            "previous_hash": previous,
            "record_hash": self._hash_record(payload, previous),
        }
        if self.signer is not None:
            blob = self._blob(payload, previous)
            record["signature"] = self.signer.signature_for(blob)
            record["signing_key"] = self.signer.public_pem
        return record

    def _emit(self, record: dict) -> None:
        for sink in self.sinks:
            try:
                sink.emit(record)
            except Exception:
                continue

    @staticmethod
    def _blob(payload: dict, previous: Optional[str]) -> str:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")) + (
            f"|{previous}" if previous else ""
        )

    @staticmethod
    def _hash_record(payload: dict, previous: Optional[str]) -> str:
        chain = ZeroLLMAuditLogger._blob(payload, previous)
        return hashlib.sha256(chain.encode()).hexdigest()

    def incidents(self) -> List[dict]:
        return list(self._bonsai)

    def verify_chain(self, public_key_pem: Optional[str] = None) -> bool:
        """Verify hash chain integrity including rotated backups, and, if requested, signatures."""
        previous: Optional[str] = None
        backups: List[Path] = []
        for backup in self.path.parent.glob(self.path.name + ".*"):
            if backup.is_file() and backup.suffix.lstrip(".").isdigit() and str(backup) != str(self.path):
                backups.append(backup)
        backups.sort(key=lambda p: -int(p.suffix.lstrip(".")))
        for path in [*backups, self.path]:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                expected = ZeroLLMAuditLogger._hash_record(record["payload"], previous)
                if record["record_hash"] != expected:
                    return False
                if public_key_pem:
                    if "signature" not in record:
                        return False
                    if not AuditSigner.verify(
                        public_key_pem,
                        ZeroLLMAuditLogger._blob(record["payload"], previous),
                        record["signature"],
                    ):
                        return False
                previous = record["record_hash"]
        return True
