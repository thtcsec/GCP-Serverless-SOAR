"""
GCP SOAR — Service Account Compromise Playbook
Handles risky IAM audit-log events related to GCP service accounts.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from ..clients.gcp import get_iam_client, get_publisher, get_resource_manager_client
from ..core.audit_logger import AuditAction, get_audit_logger
from ..core.config import config
from ..core.event_normalizer import UnifiedIncident
from ..core.metrics import PlaybookTimer, emit_metric, get_tracer
from ..integrations.slack_notifier import SlackNotifier
from ..models.events import IAMAuditEvent
from ._helpers import coerce_incident, is_dry_run

logger = logging.getLogger("gcp-soar.playbook.sa")
tracer = get_tracer("gcp-soar.playbook.sa")

HIGH_RISK_METHODS = [
    "CreateServiceAccountKey",
    "SetIamPolicy",
    "UndeleteServiceAccountKey",
    "CreateServiceAccount",
    "UploadServiceAccountKey",
]

CRITICAL_ROLES = [
    "roles/editor",
    "roles/owner",
    "roles/admin",
    "roles/storage.admin",
    "roles/compute.admin",
]


class SACompromise:
    """Detect, disable, and alert on service-account compromise."""

    def can_handle(self, incident: UnifiedIncident | dict[str, Any]) -> bool:
        incident = coerce_incident(incident)
        try:
            evt = IAMAuditEvent(**incident.raw_event)
            return evt.is_risky
        except Exception:
            return False

    def execute(self, incident: UnifiedIncident | dict[str, Any]) -> bool | dict[str, Any]:
        incident = coerce_incident(incident)
        with PlaybookTimer("SACompromise"):
            evt = IAMAuditEvent(**incident.raw_event)
            payload = evt.proto_payload
            audit = get_audit_logger()

            sa_email = self._extract_sa_email(payload.resource_name)
            if not sa_email:
                logger.warning("Cannot extract SA email from resource name")
                return False

            caller_ip = payload.request.get("callerIp", "")
            action = payload.method_name

            if is_dry_run(incident):
                return self._build_preview(sa_email, action, caller_ip)

            score = incident.risk_score
            decision = incident.decision
            intel_report = incident.intel_summary

            if decision == "IGNORE":
                logger.info(f"Ignored SA Compromise for {sa_email} (score={score}).")
                return True

            if decision == "REQUIRE_APPROVAL":
                logger.info(f"SA Compromise for {sa_email} requires human approval. Score: {score}")
                self._notify_slack(sa_email, action, caller_ip, score, decision, intel_report)
                audit.log(AuditAction.APPROVAL_REQUESTED, sa_email, details={"score": score})
                return True

            if decision == "AUTO_ISOLATE":
                logger.critical(f"SA Auto-Isolation triggered for {sa_email} on {action} (Score: {score})")
                emit_metric("findings_processed", 1.0, {"playbook": "SACompromise"})

                try:
                    with tracer.start_as_current_span("sa_compromise") as span:
                        span.set_attribute("service_account", sa_email)
                        span.set_attribute("risk_score", score)
                        self._disable_keys(sa_email)
                        audit.log(AuditAction.REVOKE_SA_KEYS, sa_email)
                        self._remove_critical_roles(sa_email)
                        audit.log(AuditAction.REMOVE_IAM_BINDINGS, sa_email)
                        self._send_alert(sa_email, payload.authentication_info.principal_email, int(score))
                        self._notify_slack(sa_email, action, caller_ip, score, decision, intel_report)
                    return True
                except Exception as exc:
                    logger.error(f"SA response failed for {sa_email}: {exc}")
                    audit.log(AuditAction.PLAYBOOK_FAILED, sa_email, details={"error": str(exc)}, success=False)
                    return False

            return False

    @staticmethod
    def _build_preview(sa_email: str, action: str, caller_ip: str) -> dict[str, Any]:
        return {
            "mode": "dry_run",
            "playbook": "SACompromise",
            "target_resource": sa_email,
            "summary": "Preview only. No service account keys, IAM bindings, or alerts were changed.",
            "planned_actions": [
                {
                    "step": 1,
                    "action": "risk_assessment",
                    "target": sa_email,
                    "details": f"Evaluate risky IAM method '{action}' from caller IP '{caller_ip or 'unknown'}'.",
                },
                {
                    "step": 2,
                    "action": "disable_service_account_keys",
                    "target": sa_email,
                    "details": "Disable user-managed service account keys if decision reaches AUTO_ISOLATE.",
                },
                {
                    "step": 3,
                    "action": "remove_critical_roles",
                    "target": sa_email,
                    "details": "Remove critical project-level IAM roles bound to the service account.",
                },
                {
                    "step": 4,
                    "action": "publish_alert",
                    "target": sa_email,
                    "details": "Publish incident alert and notify Slack for operator review.",
                },
            ],
        }

    @staticmethod
    def _extract_sa_email(resource_name: str) -> str | None:
        if "serviceAccounts/" in resource_name:
            return resource_name.split("serviceAccounts/")[1]
        return None

    @staticmethod
    def _disable_keys(sa_email: str) -> None:
        client = get_iam_client()
        sa_resource = f"projects/{config.project_id}/serviceAccounts/{sa_email}"
        keys = client.list_service_account_keys(name=sa_resource)
        from google.cloud import iam_admin_v1

        for key in keys.keys:
            if key.key_type == iam_admin_v1.ServiceAccountKey.KeyType.USER_MANAGED:
                client.disable_service_account_key(name=key.name)
                logger.info(f"Disabled SA key: {key.name}")

    @staticmethod
    def _remove_critical_roles(sa_email: str) -> None:
        rm_client = get_resource_manager_client()
        project_name = f"projects/{config.project_id}"
        policy = rm_client.get_iam_policy(request={"resource": project_name})

        member = f"serviceAccount:{sa_email}"
        changed = False
        for binding in policy.bindings:
            if binding.role in CRITICAL_ROLES and member in binding.members:
                binding.members.remove(member)
                changed = True

        if changed:
            rm_client.set_iam_policy(request={"resource": project_name, "policy": policy})
            logger.info(f"Removed critical roles for {sa_email}")

    @staticmethod
    def _send_alert(sa_email: str, principal_email: str, risk_score: int) -> None:
        if not config.alert_topic:
            logger.warning("ALERT_TOPIC not configured — skipping alert")
            return

        import json

        publisher = get_publisher()
        topic_path = publisher.topic_path(config.project_id, config.alert_topic)
        alert = {
            "type": "SA_COMPROMISE",
            "service_account": sa_email,
            "triggered_by": principal_email,
            "risk_score": risk_score,
            "timestamp": datetime.now(UTC).isoformat(),
            "actions_taken": ["keys_disabled", "critical_roles_removed"],
        }
        publisher.publish(topic_path, json.dumps(alert).encode("utf-8"))
        logger.info(f"Published SA compromise alert for {sa_email}")

    @staticmethod
    def _notify_slack(
        sa_email: str,
        action: str,
        ip: str,
        score: float,
        decision: str,
        intel_report: dict[str, Any],
    ) -> None:
        """Sends an alert to Slack."""
        try:
            notifier = SlackNotifier()
            incident_data = {
                "id": f"SA-{sa_email}-{action}",
                "severity": "CRITICAL" if decision == "AUTO_ISOLATE" else "HIGH",
                "title": f"Service Account Compromise Deteced: {action}",
                "description": f"Suspicious Action: {action}\nService Account: {sa_email}\nSource IP: {ip}\nRisk Score: {score}",  # noqa: E501
                "decision": decision,
                "intel_summary": intel_report,
            }
            notifier.send_incident_alert(incident_data)
        except Exception as e:
            logger.error(f"Failed to notify Slack: {str(e)}")
