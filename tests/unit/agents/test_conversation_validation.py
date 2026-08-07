"""V13 P2-9: conversation id validation (no PG needed)."""

import uuid

import pytest

from src.agents.conversation import InvalidConversationIdError, validate_conv_id


def test_valid_uuid_passes():
    cid = str(uuid.uuid4())
    assert str(validate_conv_id(cid)) == cid


def test_invalid_uuid_raises_invalid_conversation_id():
    with pytest.raises(InvalidConversationIdError):
        validate_conv_id("not-a-uuid")


def test_empty_string_raises():
    with pytest.raises(InvalidConversationIdError):
        validate_conv_id("")


def test_none_raises():
    with pytest.raises(InvalidConversationIdError):
        validate_conv_id(None)  # type: ignore[arg-type]
