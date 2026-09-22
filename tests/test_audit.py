# tests/test_audit.py
import json

import pytest

from zerollm.audit import AuditSigner, ZeroLLMAuditLogger


def test_chain_verifies(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = ZeroLLMAuditLogger(str(path))
    logger.log("request_blocked", {"detector": "prompt_injection"}, severity="critical")
    logger.log("response_redacted", {"detector": "pii_credit_card"})
    logger.log("request_allowed", {}, severity="info")
    assert logger.verify_chain() is True


def test_tamper_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = ZeroLLMAuditLogger(str(path))
    logger.log("request_blocked", {"detector": "prompt_injection"})
    logger.log("response_redacted", {"detector": "pii_credit_card"})
    lines = path.read_text().splitlines()
    altered = json.loads(lines[0])
    altered["payload"]["detector"] = "something_else"
    path.write_text(json.dumps(altered) + "\n" + "\n".join(lines[1:]) + "\n")
    reloaded = ZeroLLMAuditLogger(str(path))
    assert reloaded.verify_chain() is False


def test_chain_reload_continues(tmp_path):
    path = tmp_path / "audit.jsonl"
    a = ZeroLLMAuditLogger(str(path))
    a.log("one", {"i": 1})
    b = ZeroLLMAuditLogger(str(path))
    b.log("two", {"i": 2})
    assert a.verify_chain() is True
    assert b.verify_chain() is True


def test_incidents_reloaded(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = ZeroLLMAuditLogger(str(path))
    logger.log("one", {})
    logger.log("two", {})
    assert len(logger.incidents()) == 2


def test_signing_roundtrip(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private = ed25519.Ed25519PrivateKey.generate()
    key_file = tmp_path / "key.pem"
    key_file.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path = tmp_path / "signed.jsonl"
    signer = AuditSigner(str(key_file))
    logger = ZeroLLMAuditLogger(str(path), signer=signer)
    logger.log("sensitive_event", {"secret": "x"})
    logger.log("second", {})
    assert logger.verify_chain(public_key_pem=signer.public_pem) is True


def test_signature_detected_after_tamper(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private = ed25519.Ed25519PrivateKey.generate()
    key_file = tmp_path / "key.pem"
    key_file.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    signer = AuditSigner(str(key_file))
    path = tmp_path / "signed.jsonl"
    logger = ZeroLLMAuditLogger(str(path), signer=signer)
    logger.log("one", {})
    lines = path.read_text().splitlines()
    bad = json.loads(lines[0])
    bad["payload"]["event"] = "hacked"
    path.write_text(json.dumps(bad) + "\n" + "\n".join(lines[1:]) + "\n")
    reloaded = ZeroLLMAuditLogger(str(path))
    assert reloaded.verify_chain(public_key_pem=signer.public_pem) is False


def test_file_rotation(tmp_path):
    path = tmp_path / "audit.jsonl"
    # many backups so the chain's genesis record is never evicted;
    # rotation still produces multiple linked files that verify as one chain
    tiny = {"max_bytes": 80, "max_files": 64}
    logger = ZeroLLMAuditLogger(str(path), rotation=tiny)
    for i in range(25):
        logger.log(f"event_{i}", {"i": i})
    assert logger.verify_chain() is True
    backups = [p for p in tmp_path.iterdir() if p.name.startswith("audit.jsonl.")]
    assert len(backups) >= 2


@pytest.mark.asyncio
async def test_alog_writes(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = ZeroLLMAuditLogger(str(path))
    for i in range(5):
        await logger.alog("async_event", {"i": i})
    assert logger.verify_chain() is True
    assert len(path.read_text().splitlines()) == 5
