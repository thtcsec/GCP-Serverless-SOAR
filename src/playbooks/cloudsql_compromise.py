"""
GCP SOAR — Cloud SQL Compromise Playbook
Handles Cloud SQL compromise events from Cloud Audit Logs.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from ..core.audit_logger import AuditAction, AuditLogger
from ..core.metrics import PlaybookTimer, emit_metric, get_tracer
from ..models.events import CloudSQLAuditEvent

logger = logging.getLogger("gcp-soar.playbook.cloudsql")
tracer = get_tracer("gcp-soar.playbook.cloudsql")


class CloudSQLCompromisePlaybook:
    """Isolate and backup a compromised Cloud SQL instance."""

    def __init__(self) -> None:
        self.audit = AuditLogger()

    def can_handle(self, event_data: dict[str, Any]) -> bool:
        try:
            proto = event_data.get("protoPayload", {})
            service = proto.get("serviceName", "")
            if service != "sqladmin.googleapis.com":
                return False
            event = CloudSQLAuditEvent.model_validate(event_data)
            return event.is_risky
        except Exception:
            return False

    def execute(self, event_data: dict[str, Any]) -> bool:
        with PlaybookTimer("CloudSQLCompromise"):
            try:
                event = CloudSQLAuditEvent.model_validate(event_data)
                resource_name = event.resource_name
                method_name = event.method_name
                caller_ip = event.caller_ip

                logger.info(f"Executing Cloud SQL Compromise playbook for {resource_name} (method={method_name})")
                self.audit.log(AuditAction.PLAYBOOK_STARTED, resource_name, details={"method": method_name})
                emit_metric("findings_processed", 1.0, {"playbook": "CloudSQLCompromise"})

                # Step 1: Threat intel + scoring
                intel_report: dict[str, Any] = {}
                risk_data: dict[str, Any] = {"decision": "IGNORE", "risk_score": 0.0}

                is_external_ip = (
                    caller_ip
                    and not caller_ip.startswith("10.")
                    and not caller_ip.startswith("172.")
                    and not caller_ip.startswith("192.168.")
                    and ".google" not in caller_ip
                )

                if is_external_ip:
                    try:
                        from ..integrations.intel import ThreatIntelService
                        from ..integrations.scoring import ScoringEngine

                        intel_service = ThreatIntelService()
                        intel_report = intel_service.get_ip_report(caller_ip)
                        self.audit.log(AuditAction.THREAT_INTEL_LOOKUP, caller_ip, details=intel_report)
                        risk_data = ScoringEngine.calculate_risk_score(intel_report, initial_severity=7.0)
                    except Exception as e:
                        logger.warning(f"Threat intel / scoring failed (non-fatal): {e}")
                        risk_data = {"decision": "REQUIRE_APPROVAL", "risk_score": 50.0}

                decision = str(risk_data.get("decision", "IGNORE"))
                score = float(str(risk_data.get("risk_score", 0.0)))
                self.audit.log(
                    AuditAction.SCORING_DECISION,
                    resource_name,
                    details={"decision": decision, "score": score},
                )

                with tracer.start_as_current_span("cloudsql_compromise") as span:
                    span.set_attribute("resource", resource_name)
                    span.set_attribute("method", method_name)
                    span.set_attribute("decision", decision)

                    if decision == "IGNORE":
                        logger.info(f"Cloud SQL event for {resource_name} scored low ({score}). Ignoring.")
                        self.audit.log(AuditAction.PLAYBOOK_COMPLETED, resource_name)
                        return True

                    elif decision == "REQUIRE_APPROVAL":
                        logger.info(f"Cloud SQL event for {resource_name} requires approval. Score={score}")
                        self._notify_slack(resource_name, method_name, caller_ip, score, decision, intel_report)
                        self._publish_alert(resource_name, method_name, score, decision)
                        self.audit.log(AuditAction.APPROVAL_REQUESTED, resource_name, details={"score": score})
                        self.audit.log(AuditAction.PLAYBOOK_COMPLETED, resource_name)
                        return True

                    elif decision == "AUTO_ISOLATE":
                        logger.critical(f"AUTO_ISOLATE triggered for Cloud SQL {resource_name} (score={score})")

                        # Step 2: Create backup
                        self._create_backup(resource_name)

                        # Step 3: Restrict authorized networks
                        self._restrict_authorized_networks(resource_name)

                        # Step 4: Notify
                        self._notify_slack(resource_name, method_name, caller_ip, score, decision, intel_report)
                        self._publish_alert(resource_name, method_name, score, decision)

                        self.audit.log(AuditAction.PLAYBOOK_COMPLETED, resource_name)
                        return True

            except Exception as e:
                logger.error(f"Cloud SQL Compromise playbook failed: {e}", exc_info=True)
                with contextlib.suppress(Exception):
                    resource_id = event_data.get("protoPayload", {}).get("resourceName", "unknown")
                    self.audit.log(AuditAction.PLAYBOOK_FAILED, resource_id, success=False)
                return False

        return False

    def _create_backup(self, resource_name: str) -> None:
        """Create a Cloud SQL backup."""
        try:
            # resource_name format: //sqladmin.googleapis.com/projects/{project}/instances/{instance}
            parts = resource_name.split("/")
            project_id = parts[4] if len(parts) > 4 else "unknown"
            instance_id = parts[6] if len(parts) > 6 else resource_name

            from googleapiclient import discovery  # type: ignore

            service = discovery.build("sqladmin", "v1")
            service.backupRuns().insert(project=project_id, instance=instance_id).execute()
            logger.info(f"Initiated Cloud SQL backup for {instance_id}")
            self.audit.log(AuditAction.SNAPSHOT_CLOUDSQL, resource_name, details={"instance": instance_id})
        except Exception as e:
            logger.warning(f"Failed to create Cloud SQL backup for {resource_name}: {e}")

    def _restrict_authorized_networks(self, resource_name: str) -> None:
        """Restrict authorized networks to empty list (deny all)."""
        try:
            parts = resource_name.split("/")
            project_id = parts[4] if len(parts) > 4 else "unknown"
            instance_id = parts[6] if len(parts) > 6 else resource_name

            from googleapiclient import discovery  # type: ignore

            service = discovery.build("sqladmin", "v1")
            service.instances().patch(
                project=project_id,
                instance=instance_id,
                body={"settings": {"ipConfiguration": {"authorizedNetworks": []}}},
            ).execute()
            logger.info(f"Restricted authorized networks for Cloud SQL {instance_id}")
            self.audit.log(
                AuditAction.RESTRICT_CLOUDSQL_NETWORK,
                resource_name,
                details={"authorized_networks": []},
            )
        except Exception as e:
            logger.warning(f"Failed to restrict authorized networks for {resource_name}: {e}")

    def _notify_slack(
        self,
        resource_name: str,
        method_name: str,
        caller_ip: str,
        score: float,
        decision: str,
        intel_report: dict[str, Any],
    ) -> None:
        try:
            from ..integrations.slack_notifier import SlackNotifier

            notifier = SlackNotifier()
            incident_data = {
                "id": f"CLOUDSQL-{resource_name}-{method_name}",
                "severity": "CRITICAL" if decision == "AUTO_ISOLATE" else "HIGH",
                "title": f"Cloud SQL Compromise Detected: {method_name}",
                "description": (
                    f"Suspicious Cloud SQL action: {method_name}\n"
                    f"Resource: {resource_name}\n"
                    f"Caller IP: {caller_ip}\n"
                    f"Risk Score: {score}\n"
                    f"Decision: {decision}"
                ),
                "decision": decision,
                "intel_summary": intel_report,
            }
            notifier.send_incident_alert(incident_data)
        except Exception as e:
            logger.warning(f"Failed to send Slack notification: {e}")

    def _publish_alert(self, resource_name: str, method_name: str, score: float, decision: str) -> None:
        try:
            import json

            from google.cloud import pubsub_v1  # type: ignore

            from ..core.config import config

            publisher = pubsub_v1.PublisherClient()
            topic_path = publisher.topic_path(config.project_id, "soar-alerts")
            message_data = json.dumps(
                {
                    "playbook": "CloudSQLCompromise",
                    "resource": resource_name,
                    "method": method_name,
                    "score": score,
                    "decision": decision,
                }
            ).encode("utf-8")
            publisher.publish(topic_path, message_data)
        except Exception as e:
            logger.warning(f"Failed to publish Pub/Sub alert: {e}")
