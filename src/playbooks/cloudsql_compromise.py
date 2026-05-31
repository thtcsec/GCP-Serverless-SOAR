"""
GCP SOAR — Cloud SQL Compromise Playbook
Handles Cloud SQL database compromise events from Security Command Center / Audit Logs.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from src.core.audit_logger import AuditAction, AuditLogger
from src.core.event_normalizer import UnifiedIncident
from src.core.metrics import PlaybookTimer, emit_metric
from src.models.events import IAMAuditEvent, SCCFinding
from src.playbooks._helpers import coerce_incident, is_dry_run
from src.playbooks.base import Playbook

logger = logging.getLogger("gcp-soar.playbook.cloudsql")


class CloudSQLCompromisePlaybook(Playbook):
    """Playbook to respond to Cloud SQL compromise events."""

    def __init__(self) -> None:
        self.audit = AuditLogger()

    def can_handle(self, incident: UnifiedIncident | dict[str, Any]) -> bool:
        incident = coerce_incident(incident)
        try:
            event_data = incident.raw_event
            if "category" in event_data:
                finding = SCCFinding(**event_data)
                is_sql = (
                    "cloudsql.googleapis.com" in finding.resource.type
                    or "cloudsql.googleapis.com" in finding.resource_name
                )
                return is_sql and (finding.severity in ("HIGH", "CRITICAL", "MEDIUM"))

            if "protoPayload" in event_data:
                audit = IAMAuditEvent(**event_data)
                return "cloudsql" in audit.proto_payload.service_name.lower() and audit.is_risky

            return False
        except Exception:
            return False

    def execute(self, incident: UnifiedIncident | dict[str, Any]) -> bool | dict[str, Any]:
        incident = coerce_incident(incident)
        with PlaybookTimer("CloudSQLCompromise"):
            try:
                event_data = incident.raw_event
                db_id = "unknown"
                project_id = "unknown"
                event_name = "CloudSQL_SuspiciousActivity"
                severity = incident.severity or "HIGH"

                if "category" in event_data:
                    finding = SCCFinding(**event_data)
                    project_id, db_id = self._parse_resource(finding.resource_name)
                    event_name = finding.category
                    severity = finding.severity
                elif "protoPayload" in event_data:
                    audit = IAMAuditEvent(**event_data)
                    db_id = audit.proto_payload.resource_name.split("/")[-1]
                    event_name = audit.proto_payload.method_name

                if is_dry_run(incident):
                    return self._build_preview(project_id, db_id, event_name, severity)

                logger.info(f"Executing Cloud SQL Compromise playbook for {db_id} (action={event_name})")
                self.audit.log(AuditAction.PLAYBOOK_STARTED, db_id, actor="GCP_SOAR", details={"event": event_name})
                emit_metric("findings_processed", 1.0, {"playbook": "CloudSQLCompromise"})

                decision = incident.decision or self._severity_decision(severity)
                self.audit.log(AuditAction.SCORING_DECISION, db_id, actor="GCP_SOAR", details={"decision": decision})

                if decision == "IGNORE":
                    logger.info(f"Cloud SQL event for {db_id} scored low. Ignoring.")
                    self.audit.log(AuditAction.PLAYBOOK_COMPLETED, db_id, actor="GCP_SOAR")
                    return True

                if decision in ("AUTO_ISOLATE", "REQUIRE_APPROVAL", "EVALUATE"):
                    self._create_db_backup(project_id, db_id)

                self.audit.log(AuditAction.PLAYBOOK_COMPLETED, db_id, actor="GCP_SOAR")
                return True

            except Exception as e:
                logger.error(f"Cloud SQL Compromise playbook failed: {e}", exc_info=True)
                with contextlib.suppress(Exception):
                    self.audit.log(AuditAction.PLAYBOOK_FAILED, "cloudsql_compromise", actor="GCP_SOAR", success=False)
                return False

    @staticmethod
    def _parse_resource(resource_name: str) -> tuple[str, str]:
        """Extract project_id and instance_id from SCC resource_name."""
        parts = resource_name.split("/")
        project_id = ""
        db_id = resource_name
        if "projects" in parts:
            try:
                p_idx = parts.index("projects")
                project_id = parts[p_idx + 1]
                db_id = parts[parts.index("instances") + 1] if "instances" in parts else parts[-1]
            except (ValueError, IndexError):
                pass
        return project_id, db_id

    @staticmethod
    def _severity_decision(severity: str) -> str:
        if severity in ("CRITICAL", "HIGH"):
            return "AUTO_ISOLATE"
        elif severity == "MEDIUM":
            return "REQUIRE_APPROVAL"
        return "IGNORE"

    @staticmethod
    def _build_preview(project_id: str, db_id: str, event_name: str, severity: str) -> dict[str, Any]:
        decision = CloudSQLCompromisePlaybook._severity_decision(severity)
        return {
            "mode": "dry_run",
            "playbook": "CloudSQLCompromise",
            "target_resource": db_id,
            "project_id": project_id,
            "decision": decision,
            "summary": "Preview only. No Cloud SQL backups or network settings were changed.",
            "planned_actions": [
                {
                    "step": 1,
                    "action": "severity_decision",
                    "target": db_id,
                    "details": f"Map severity '{severity}' to decision '{decision}' for event '{event_name}'.",
                },
                {
                    "step": 2,
                    "action": "backupRuns.insert",
                    "target": db_id,
                    "details": f"Create on-demand forensic backup in project {project_id or 'unknown'}.",
                },
            ],
        }

    def _create_db_backup(self, project_id: str, db_id: str) -> None:
        """Create an on-demand SQL backup."""
        try:
            from datetime import UTC, datetime

            from google.auth import default  # type: ignore
            from googleapiclient import discovery

            credentials, project = default()
            if not project_id or project_id == "unknown":
                project_id = project

            service = discovery.build("sqladmin", "v1", credentials=credentials)

            ts = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
            description = f"SOAR forensic backup - {ts}"

            request = service.backupRuns().insert(project=project_id, instance=db_id, body={"description": description})
            response = request.execute()

            logger.info(f"Initiated forensic backup run {response.get('id')} for instance {db_id}")
            self.audit.log(AuditAction.SNAPSHOT_DB, db_id, actor="GCP_SOAR", details={"backup_id": response.get("id")})
        except Exception as e:
            logger.warning(f"Failed to create DB backup for {db_id}: {e}")
            self.audit.log(AuditAction.SNAPSHOT_DB, db_id, actor="GCP_SOAR", success=False, details={"error": str(e)})
