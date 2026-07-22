"""Tests for runner._status_from_result (P1-CORE-NEW-1 status derivation).

Covers the regression where every L3+ event was mis-stored as "pending_approval"
because status was derived from approval_id presence instead of the terminal
approval_status.
"""

from src.orchestration.runner import _status_from_result


class TestStatusFromResult:
    def test_l1_l2_auto_approve_completed(self):
        # L1/L2: approval_id is None, status approved -> completed
        pending = {"approval_id": None, "approval_status": "approved"}
        assert _status_from_result(pending, None) == "completed"

    def test_l3_approved_completed(self):
        # L3+ approved after quorum -> completed (was wrongly pending_approval)
        pending = {"approval_id": "aprv-1", "approval_status": "approved"}
        assert _status_from_result(pending, None) == "completed"

    def test_l3_rejected(self):
        pending = {"approval_id": "aprv-1", "approval_status": "rejected"}
        assert _status_from_result(pending, None) == "rejected"

    def test_l3_timeout_is_error(self):
        pending = {"approval_id": "aprv-1", "approval_status": "timeout"}
        assert _status_from_result(pending, None) == "error"

    def test_responder_error(self):
        # respond_node returned {"error": "responder_timeout"} -- no pending_action
        pending = {}
        assert _status_from_result(pending, "responder_timeout") == "error"

    def test_responder_error_wins_over_pending(self):
        # If both error and pending are present, error takes precedence.
        pending = {"approval_id": "aprv-1", "approval_status": "approved"}
        assert _status_from_result(pending, "responder_error: x") == "error"

    def test_defensive_approval_id_without_status(self):
        # approval_id set but no terminal status recorded -> pending (defensive)
        pending = {"approval_id": "aprv-1"}
        assert _status_from_result(pending, None) == "pending_approval"

    def test_no_pending_no_error_completed(self):
        assert _status_from_result({}, None) == "completed"
