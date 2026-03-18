"""Tests for GCP Audit Logger."""

from unittest.mock import MagicMock

import pytest

from src.core.audit_logger import AuditAction, AuditEntry, AuditLogger


class TestAuditEntry:
    def test_entry_creation(self):
        entry = AuditEntry(
            action=AuditAction.ISOLATE_NETWORK,
            resource_id="vm-1",
            actor="admin@corp.com",
            details={"reason": "crypto miner"},
        )
        assert entry.action == AuditAction.ISOLATE_NETWORK
        assert entry.resource_id == "vm-1"
        assert entry.success is True

    def test_entry_to_dict(self):
        entry = AuditEntry(
            action=AuditAction.KILL_PROCESS,
            resource_id="vm-1",
        )
        d = entry.to_dict()
        assert d["action"] == "KILL_PROCESS"
        assert "timestamp" in d
        assert d["success"] is True


class TestAuditLogger:
    @pytest.fixture
    def audit_logger(self):
        return AuditLogger()

    def test_log_action(self, audit_logger):
        entry = audit_logger.log(
            AuditAction.PLAYBOOK_STARTED,
            resource_id="vm-1",
        )
        assert entry.action == AuditAction.PLAYBOOK_STARTED
        assert len(audit_logger._entries) == 1

    def test_log_multiple_actions(self, audit_logger):
        audit_logger.log(AuditAction.PLAYBOOK_STARTED, "vm-1")
        audit_logger.log(AuditAction.ISOLATE_NETWORK, "vm-1")
        audit_logger.log(AuditAction.KILL_PROCESS, "vm-1", success=False)
        audit_logger.log(AuditAction.PLAYBOOK_COMPLETED, "vm-1")
        assert len(audit_logger._entries) == 4

    def test_get_entries_filter_by_resource(self, audit_logger):
        audit_logger.log(AuditAction.KILL_PROCESS, "vm-1")
        audit_logger.log(AuditAction.KILL_PROCESS, "vm-2")
        entries = audit_logger.get_entries(resource_id="vm-1")
        assert len(entries) == 1

    def test_get_entries_filter_by_action(self, audit_logger):
        audit_logger.log(AuditAction.KILL_PROCESS, "vm-1")
        audit_logger.log(AuditAction.ISOLATE_NETWORK, "vm-1")
        entries = audit_logger.get_entries(action=AuditAction.KILL_PROCESS)
        assert len(entries) == 1

    def test_get_summary(self, audit_logger):
        audit_logger.log(AuditAction.PLAYBOOK_STARTED, "vm-1")
        audit_logger.log(AuditAction.KILL_PROCESS, "vm-1", success=False)
        summary = audit_logger.get_summary()
        assert summary["total_entries"] == 2
        assert summary["success_count"] == 1
        assert summary["failure_count"] == 1

    def test_export_to_gcs(self, audit_logger):
        storage_mock = MagicMock()
        audit_logger._storage = storage_mock
        audit_logger.log(AuditAction.PLAYBOOK_STARTED, "vm-1")
        result = audit_logger.export_to_gcs("my-bucket")
        assert result is True

    def test_export_to_gcs_no_client(self, audit_logger):
        result = audit_logger.export_to_gcs("my-bucket")
        assert result is False

    def test_cloud_logging_integration(self):
        logging_mock = MagicMock()
        audit_logger = AuditLogger(logging_client=logging_mock)
        audit_logger.log(AuditAction.SCORING_DECISION, "vm-1")
        logging_mock.logger.assert_called_once()
