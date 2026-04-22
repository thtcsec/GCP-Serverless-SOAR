"""
GCP SOAR — Service Account Compromise Playbook
Handles risky IAM audit-log events related to GCP service accounts.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from ..clients.gcp import get_iam_client, get_publisher, get_resource_manager_client
from ..core.config import config
from ..core.metrics import PlaybookTimer, emit_metric, get_tracer
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

    def can_handle(self, event_data: dict[str, Any]) -> bool:
        try:
            evt = IAMAuditEvent(**event_data)
            return evt.is_risky
        except Exception:
            return False

    def execute(self, event_data: dict[str, Any]) -> bool | dict[str, Any]:
        with PlaybookTimer("SACompromise"):
            evt = IAMAuditEvent(**event_data)
            payload = evt.proto_payload

            sa_email = self._extract_sa_email(payload.resource_name)
            if not sa_email:
                logger.warning("Cannot extract SA email from resource name")
                return False

            caller_ip = payload.request.get("callerIp", "")
            action = payload.method_name

            if self._is_dry_run(event_data):
                return self._build_preview(sa_email, action, caller_ip)

            intel_report = {}
            risk_data = {"decision": "IGNORE", "risk_score": 0.0}

            # 1. Threat Intel & Scoring
            if caller_ip and not caller_ip.startswith(("compute.google", "container.google")):
                try:
                    from ..integrations.intel import ThreatIntelService
                    from ..integrations.scoring import ScoringEngine

                    intel_service = ThreatIntelService()
                    scoring_engine = ScoringEngine()

                    intel_report = intel_service.get_ip_report(caller_ip)
                    base_risk = self._calculate_base_risk(payload, caller_ip)

                    risk_data = scoring_engine.calculate_risk_score(intel_report, initial_severity=base_risk)
                except Exception as e:
                    logger.error(f"Failed to calculate risk score: {e}")
            else:
                # Local fallback if IP is internal or missing
                base_risk = self._calculate_base_risk(payload, caller_ip)
                from ..integrations.scoring import ScoringEngine

                scoring_engine = ScoringEngine()
                risk_data = scoring_engine.calculate_risk_score(intel_report, initial_severity=base_risk)

            decision = str(risk_data.get("decision", "IGNORE"))
            raw_score = risk_data.get("risk_score", 0.0)
            score = float(str(raw_score))

            # 2. Decision Routing
            if decision == "IGNORE":
                logger.info(f"Ignored SA Compromise for {sa_email} due to low risk score ({score}).")
                return True

            elif decision == "REQUIRE_APPROVAL":
                logger.info(f"SA Compromise for {sa_email} requires human approval. Score: {score}")
                self._notify_slack(sa_email, action, caller_ip, score, decision, intel_report)
                return True

            elif decision == "AUTO_ISOLATE":
                logger.critical(f"SA Auto-Isolation triggered for {sa_email} on {action} (Score: {score})")
                emit_metric("findings_processed", 1.0, {"playbook": "SACompromise"})

                try:
                    with tracer.start_as_current_span("sa_compromise") as span:
                        span.set_attribute("service_account", sa_email)
                        span.set_attribute("risk_score", score)
                        self._disable_keys(sa_email)
                        self._remove_critical_roles(sa_email)
                        self._send_alert(sa_email, payload.authentication_info.principal_email, int(score))
                        self._notify_slack(sa_email, action, caller_ip, score, decision, intel_report)
                    return True
                except Exception as exc:
                    logger.error(f"SA response failed for {sa_email}: {exc}")
                    return False

            return False

    @staticmethod
    def _is_dry_run(event_data: dict[str, Any]) -> bool:
        return bool(
            event_data.get("dry_run") or event_data.get("preview_only") or event_data.get("execution_mode") == "dry_run"
        )

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

    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_sa_email(resource_name: str) -> str | None:
        if "serviceAccounts/" in resource_name:
            return resource_name.split("serviceAccounts/")[1]
        return None

    @staticmethod
    def _calculate_base_risk(payload, caller_ip: str) -> float:
        score = 0
        if any(m in payload.method_name for m in HIGH_RISK_METHODS):
            score += 5
        if caller_ip and not caller_ip.startswith(("compute.google", "container.google")):
            score += 3
        hour = datetime.now(UTC).hour
        if hour >= 23 or hour <= 5:
            score += 2
        return float(min(score, 10))

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
            from ..integrations.slack_notifier import SlackNotifier

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
