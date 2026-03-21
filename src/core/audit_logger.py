"""
GCP SOAR — Audit Logger
Logs all SOAR actions to a structured, immutable audit trail.
Every containment, investigation, and decision action is recorded
with timestamp, actor, action type, target resource, and result.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

logger = logging.getLogger("gcp-soar.audit")


class AuditAction(StrEnum):
    """Enumeration of auditable SOAR actions."""

    ISOLATE_NETWORK = "ISOLATE_NETWORK"
    KILL_PROCESS = "KILL_PROCESS"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    REVOKE_SA_KEYS = "REVOKE_SA_KEYS"
    DISABLE_SA = "DISABLE_SA"
    REMOVE_IAM_BINDINGS = "REMOVE_IAM_BINDINGS"
    SNAPSHOT_DISK = "SNAPSHOT_DISK"
    STOP_INSTANCE = "STOP_INSTANCE"
    THREAT_INTEL_LOOKUP = "THREAT_INTEL_LOOKUP"
    SCORING_DECISION = "SCORING_DECISION"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    PLAYBOOK_STARTED = "PLAYBOOK_STARTED"
    PLAYBOOK_COMPLETED = "PLAYBOOK_COMPLETED"
    PLAYBOOK_FAILED = "PLAYBOOK_FAILED"
    # Nhóm 1: Cloud SQL
    SNAPSHOT_CLOUDSQL = "SNAPSHOT_CLOUDSQL"
    RESTRICT_CLOUDSQL_NETWORK = "RESTRICT_CLOUDSQL_NETWORK"
    STOP_CLOUDSQL_INSTANCE = "STOP_CLOUDSQL_INSTANCE"
    # Nhóm 2: GKE
    EVICT_POD = "EVICT_POD"
    APPLY_NETWORK_POLICY = "APPLY_NETWORK_POLICY"
    COLLECT_POD_LOGS = "COLLECT_POD_LOGS"
    # Nhóm 3: CI/CD
    CANCEL_BUILD = "CANCEL_BUILD"
    DISABLE_BUILD_TRIGGER = "DISABLE_BUILD_TRIGGER"
    QUARANTINE_ARTIFACT = "QUARANTINE_ARTIFACT"


class AuditEntry:
    """A single audit log entry."""

    def __init__(
        self,
        action: AuditAction,
        resource_id: str,
        actor: str = "SOAR_SYSTEM",
        details: dict[str, Any] | None = None,
        success: bool = True,
    ) -> None:
        self.timestamp = datetime.now(UTC).isoformat()
        self.action = action
        self.resource_id = resource_id
        self.actor = actor
        self.details = details or {}
        self.success = success

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "action": self.action.value,
            "resource_id": self.resource_id,
            "actor": self.actor,
            "success": self.success,
            "details": self.details,
        }


class AuditLogger:
    """
    Structured audit logger for all SOAR operations.
    Supports local in-memory log, Cloud Logging, and GCS archival.
    """

    def __init__(self, logging_client: Any = None, storage_client: Any = None) -> None:
        self._entries: list[AuditEntry] = []
        self._logging = logging_client
        self._storage = storage_client
        self._log_name = "soar-audit-trail"

    def log(
        self,
        action: AuditAction,
        resource_id: str,
        actor: str = "SOAR_SYSTEM",
        details: dict[str, Any] | None = None,
        success: bool = True,
    ) -> AuditEntry:
        """Record a SOAR action to the audit trail."""
        entry = AuditEntry(
            action=action,
            resource_id=resource_id,
            actor=actor,
            details=details,
            success=success,
        )
        self._entries.append(entry)
        logger.info(f"AUDIT | {entry.action.value} | {resource_id} | {'OK' if success else 'FAIL'} | {actor}")

        if self._logging:
            self._write_to_cloud_logging(entry)

        return entry

    def get_entries(
        self,
        resource_id: str | None = None,
        action: AuditAction | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Retrieve audit entries with optional filtering."""
        filtered = self._entries
        if resource_id:
            filtered = [e for e in filtered if e.resource_id == resource_id]
        if action:
            filtered = [e for e in filtered if e.action == action]
        return [e.to_dict() for e in filtered[-limit:]]

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of all audit activity."""
        total = len(self._entries)
        success_count = sum(1 for e in self._entries if e.success)
        actions: dict[str, int] = {}
        for entry in self._entries:
            key = entry.action.value
            actions[key] = actions.get(key, 0) + 1

        return {
            "total_entries": total,
            "success_count": success_count,
            "failure_count": total - success_count,
            "actions_breakdown": actions,
        }

    def export_to_gcs(self, bucket_name: str, prefix: str = "audit/") -> bool:
        """Archive audit entries to GCS for long-term retention."""
        if not self._storage or not self._entries:
            return False

        try:
            ts = datetime.now(UTC).strftime("%Y/%m/%d/%H%M%S")
            blob_name = f"{prefix}{ts}-audit.json"
            body = json.dumps([e.to_dict() for e in self._entries], indent=2)
            bucket = self._storage.bucket(bucket_name)
            blob = bucket.blob(blob_name)
            blob.upload_from_string(body, content_type="application/json")
            logger.info(f"Exported {len(self._entries)} audit entries to gs://{bucket_name}/{blob_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to export audit to GCS: {e}")
            return False

    def _write_to_cloud_logging(self, entry: AuditEntry) -> None:
        """Write a single audit entry to Cloud Logging."""
        try:
            gcp_logger = self._logging.logger(self._log_name)
            gcp_logger.log_struct(
                entry.to_dict(),
                severity="INFO" if entry.success else "WARNING",
            )
        except Exception as e:
            logger.warning(f"Cloud Logging write failed (non-fatal): {e}")
