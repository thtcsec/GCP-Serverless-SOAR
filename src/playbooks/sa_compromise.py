"""
GCP SOAR — Service Account Compromise Playbook
Handles risky IAM audit-log events related to GCP service accounts.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict

from ..clients.gcp import get_iam_client, get_publisher, get_resource_manager_client
from ..core.config import config
from ..core.metrics import emit_metric, PlaybookTimer, get_tracer
from ..models.events import IAMAuditEvent

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

    def can_handle(self, event_data: Dict[str, Any]) -> bool:
        try:
            evt = IAMAuditEvent(**event_data)
            return evt.is_risky
        except Exception:
            return False

    def execute(self, event_data: Dict[str, Any]) -> bool:
        with PlaybookTimer("SACompromise"):
            evt = IAMAuditEvent(**event_data)
            payload = evt.proto_payload

            sa_email = self._extract_sa_email(payload.resource_name)
            if not sa_email:
                logger.warning("Cannot extract SA email from resource name")
                return False

            risk_score = self._calculate_risk(payload)
            if risk_score < 7:
                logger.info(f"Risk score {risk_score} below threshold for {sa_email}")
                return True  # handled but no action needed

            logger.warning(f"SA compromise detected: {sa_email} (score={risk_score})")
            emit_metric("findings_processed", 1.0, {"playbook": "SACompromise"})

            try:
                with tracer.start_as_current_span("sa_compromise") as span:
                    span.set_attribute("service_account", sa_email)
                    span.set_attribute("risk_score", risk_score)
                    self._disable_keys(sa_email)
                    self._remove_critical_roles(sa_email)
                    self._send_alert(sa_email, payload.authentication_info.principal_email, risk_score)
                return True
            except Exception as exc:
                logger.error(f"SA response failed for {sa_email}: {exc}")
                return False

    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_sa_email(resource_name: str) -> str | None:
        if "serviceAccounts/" in resource_name:
            return resource_name.split("serviceAccounts/")[1]
        return None

    @staticmethod
    def _calculate_risk(payload) -> int:
        score = 0
        if any(m in payload.method_name for m in HIGH_RISK_METHODS):
            score += 5
        caller_ip = payload.request.get("callerIp", "")
        if not caller_ip.startswith(("compute.google", "container.google")):
            score += 3
        hour = datetime.now(timezone.utc).hour
        if hour >= 23 or hour <= 5:
            score += 2
        return min(score, 10)

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
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actions_taken": ["keys_disabled", "critical_roles_removed"],
        }
        publisher.publish(topic_path, json.dumps(alert).encode("utf-8"))
        logger.info(f"Published SA compromise alert for {sa_email}")
