"""Unit tests for Ed25519 instruction signing."""
import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.agents.signing import sign_message, verify_message, SENSITIVE_TYPES


@pytest.fixture
def keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    pub_bytes = private_key.public_key().public_bytes_raw()
    public_key_hex = pub_bytes.hex()
    return private_key, public_key_hex


class TestSigning:
    def test_sign_adds_signature_to_sensitive_types(self):
        for msg_type in SENSITIVE_TYPES:
            msg = {"v": 1, "type": msg_type, "ts": "2026-01-01T00:00:00Z", "payload": {"key": "value"}}
            signed = sign_message(msg)
            assert "sig" in signed, f"Missing sig for {msg_type}"
            sig = signed["sig"]
            try:
                base64.b64decode(sig)
            except Exception:
                pytest.fail(f"sig is not valid base64 for {msg_type}")

    def test_non_sensitive_types_not_signed(self):
        msg = {"v": 1, "type": "heartbeat", "ts": "2026-01-01T00:00:00Z", "payload": {}}
        signed = sign_message(msg)
        assert "sig" not in signed

    def test_verify_valid_signature(self, keypair):
        private_key, pubkey_hex = keypair
        msg_type = "scan_command"
        msg = {"v": 1, "type": msg_type, "ts": "2026-01-01T00:00:00Z", "payload": {"task_id": "t-1"}}
        ts = msg["ts"]
        payload = json.dumps(msg["payload"], sort_keys=True)
        sign_payload = f"{msg_type}|{ts}|{payload}"
        sig = private_key.sign(sign_payload.encode())
        msg["sig"] = base64.b64encode(sig).decode()
        assert verify_message(msg, pubkey_hex)

    def test_verify_rejects_tampered_payload(self, keypair):
        private_key, pubkey_hex = keypair
        msg = {"v": 1, "type": "scan_command", "ts": "2026-01-01T00:00:00Z", "payload": {"task_id": "t-1"}}
        ts = msg["ts"]
        payload = json.dumps(msg["payload"], sort_keys=True)
        sign_payload = f"scan_command|{ts}|{payload}"
        sig = private_key.sign(sign_payload.encode())
        msg["sig"] = base64.b64encode(sig).decode()
        msg["payload"]["task_id"] = "evil-task"
        assert not verify_message(msg, pubkey_hex)

    def test_verify_rejects_wrong_key(self):
        wrong_priv = ed25519.Ed25519PrivateKey.generate()
        wrong_pub = wrong_priv.public_key().public_bytes_raw().hex()
        priv = ed25519.Ed25519PrivateKey.generate()
        msg = {"v": 1, "type": "scan_command", "ts": "2026-01-01T00:00:00Z", "payload": {"task_id": "t-1"}}
        msg_type = "scan_command"
        ts = msg["ts"]
        payload = json.dumps(msg["payload"], sort_keys=True)
        sign_payload = f"{msg_type}|{ts}|{payload}"
        sig = priv.sign(sign_payload.encode())
        msg["sig"] = base64.b64encode(sig).decode()
        assert not verify_message(msg, wrong_pub)

    def test_verify_requires_signature_for_sensitive(self):
        msg = {"v": 1, "type": "scan_command", "ts": "2026-01-01T00:00:00Z", "payload": {}}
        assert not verify_message(msg, "00" * 32)
