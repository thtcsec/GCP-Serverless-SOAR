"""Firestore transitions run the read and update in one transaction."""

from unittest.mock import MagicMock, patch

import pytest

from src.core.approval_store import FirestoreApprovalStore


@pytest.mark.parametrize(
    "current,exists,expected",
    [
        ("pending", True, True),
        ("executing", True, False),
        ("pending", False, False),
    ],
)
def test_firestore_transition_checks_state_inside_transaction(current, exists, expected):
    store = FirestoreApprovalStore.__new__(FirestoreApprovalStore)
    store._client = MagicMock()
    store._col = MagicMock()
    ref = store._col.document.return_value
    snapshot = ref.get.return_value
    snapshot.exists = exists
    snapshot.to_dict.return_value = {"status": current}
    transaction = store._client.transaction.return_value
    with patch("google.cloud.firestore.transactional", side_effect=lambda callback: callback):
        assert store.transition("incident", "pending", "executing", actor="analyst") is expected
    ref.get.assert_called_once_with(transaction=transaction)
    if expected:
        transaction.update.assert_called_once()
        assert transaction.update.call_args[0][1]["status"] == "executing"
    else:
        transaction.update.assert_not_called()
