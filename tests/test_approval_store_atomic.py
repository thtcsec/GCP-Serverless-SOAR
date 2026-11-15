"""Firestore transitions run the read and update in one transaction."""

from unittest.mock import MagicMock, patch

import pytest

from src.core.approval_store import FirestoreApprovalStore


def test_firestore_create_does_not_overwrite_existing_record():
    from google.api_core.exceptions import AlreadyExists

    store = FirestoreApprovalStore.__new__(FirestoreApprovalStore)
    store._col = MagicMock()
    record = {"incident_id": "event:one", "status": "processing"}
    assert store.create_once(record)
    store._col.document.return_value.create.side_effect = AlreadyExists("duplicate")
    assert not store.create_once(record)
    store._col.document.return_value.set.assert_not_called()


def test_firestore_checks_deadline_in_transaction():
    store = FirestoreApprovalStore.__new__(FirestoreApprovalStore)
    store._client = MagicMock()
    store._col = MagicMock()
    snapshot = store._col.document.return_value.get.return_value
    snapshot.exists = True
    snapshot.to_dict.return_value = {"status": "pending", "expires_at": 1}
    with patch("google.cloud.firestore.transactional", side_effect=lambda callback: callback):
        assert not store.transition("old", "pending", "executing", require_unexpired=True)
    store._client.transaction.return_value.update.assert_not_called()


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
