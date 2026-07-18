""""Ed25519 instruction signing -- sign outgoing commands, verify on Agent side."""
import base64
import json
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric import ed25519

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

# Commands that MUST be signed (Agent rejects unsigned sensitive commands)
SENSITIVE_TYPES = {"scan_command", "rule_update", "agent_upgrade", "scan_cancel", "config_update"}


def _get_private_key() -> ed25519.Ed25519PrivateKey | None:
    """Load Ed25519 private key from settings or environment.

    NOTE: an empty key no longer triggers a random one. Random keys are
    process-local, so the public key the Agent downloads via /ca/enroll
    would never match -- every signed command fails verification and the
    Agent either panics (ed25519.Verify with nil key) or silently drops
    traffic (P1-VS-5). If the operator forgets to set the key, we log a
    loud warning and refuse to sign so the misconfiguration is visible.
    """
    key_hex = get_settings().agent_signing_key
    if not key_hex:
        logger.error("agent_signing_key_not_set_refusing_to_sign")
        return None
    try:
        key_bytes = bytes.fromhex(key_hex)
        return ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
    except Exception as exc:
        logger.error("invalid_agent_signing_key_hex", error=str(exc))
        return None
def sign_bytes(data: bytes) -> str:
    """Sign arbitrary bytes with Ed25519. Returns base64-encoded signature.
    Used for agent_upgrade binary hash verification."""
    pk = _get_private_key()
    if pk is None:
        return ""
    sig = pk.sign(data)
    return base64.b64encode(sig).decode()


def get_public_key_hex() -> str:
    """Return the public key hex for Agent verification."""
    pk = _get_private_key()
    if pk is None:
        return ""
    return pk.public_key().public_bytes_raw().hex()


def sign_message(msg: dict) -> dict:
    """Sign an outgoing message if it is a sensitive command type.

    Adds 'sig' field: base64-encoded Ed25519 signature of type+ts+payload concatenation.
    """
    msg_type = msg.get("type", "")
    if msg_type not in SENSITIVE_TYPES:
        return msg

    pk = _get_private_key()
    if pk is None:
        logger.warning("cannot_sign_no_key", type=msg_type)
        return msg

    # Canonical signing payload: type + ts + json(payload)
    ts = msg.get("ts", datetime.now(UTC).isoformat())
    payload = msg.get("payload", {})
    sign_payload = f"{msg_type}|{ts}|{json.dumps(payload, sort_keys=True, ensure_ascii=False)}"

    signature = pk.sign(sign_payload.encode())
    msg["sig"] = base64.b64encode(signature).decode()
    if "ts" not in msg:
        msg["ts"] = ts

    logger.debug("instruction_signed", type=msg_type)
    return msg


def verify_message(msg: dict, public_key_hex: str) -> bool:
    """Verify an Ed25519 signature on an incoming message.

    Used by the server to verify Agent responses (if Agent also signs).
    Returns True if signature is valid or not required.
    """
    msg_type = msg.get("type", "")
    if msg_type not in SENSITIVE_TYPES:
        return True

    sig_b64 = msg.get("sig", "")
    if not sig_b64:
        logger.warning("missing_signature", type=msg_type)
        return False

    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        signature = base64.b64decode(sig_b64)
        ts = msg.get("ts", "")
        payload = msg.get("payload", {})
        verify_payload = f"{msg_type}|{ts}|{json.dumps(payload, sort_keys=True, ensure_ascii=False)}"
        public_key.verify(signature, verify_payload.encode())
        return True
    except Exception as exc:
        logger.warning("signature_verification_failed", type=msg_type, error=str(exc))
        return False
