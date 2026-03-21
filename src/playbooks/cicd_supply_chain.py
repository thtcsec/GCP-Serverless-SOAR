"""
GCP SOAR — CI/CD Supply Chain Attack Detection Playbook
Handles Cloud Build audit events for supply chain compromise detection.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from ..core.audit_logger import AuditAction, AuditLogger
from ..core.metrics import PlaybookTimer, emit_metric, get_tracer
from ..models.events import CloudBuildAuditEvent

logger = logging.getLogger("gcp-soar.playbook.cicd")
tracer = get_tracer("gcp-soar.playbook.cicd")


class CICDSupplyChainPlaybook:
    """Detect and respond to CI/CD supply chain attacks in Cloud Build."""

    def __init__(self) -> None:
        self.audit = AuditLogger()

    def can_handle(self, event_data: dict[str, Any]) -> bool:
        try:
            proto = event_data.get("protoPayload", {})
            service = proto.get("serviceName", "")
            if service != "cloudbuild.googleapis.com":
                return False
            event = CloudBuildAuditEvent.model_validate(event_data)
            return event.is_risky
        except Exception:
            return False

    def execute(self, event_data: dict[str, Any]) -> bool:
        with PlaybookTimer("CICDSupplyChain"):
            try:
                event = CloudBuildAuditEvent.model_validate(event_data)
                method_name = event.method_name
                resource_name = event.proto_payload.resource_name
                actor = event.proto_payload.authentication_info.principal_email
                request = event.proto_payload.request

                # Extract build ID / trigger name
                build_id = request.get("id", "")
                trigger_id = request.get("triggerId", request.get("id", ""))
                resource_id = build_id or trigger_id or resource_name

                logger.info(f"Executing CI/CD Supply Chain playbook: method={method_name}")
                self.audit.log(
                    AuditAction.PLAYBOOK_STARTED,
                    resource_id,
                    details={"method": method_name, "actor": actor},
                )
                emit_metric("findings_processed", 1.0, {"playbook": "CICDSupplyChain"})

                # Behavior-based scoring
                risk_score = self._behavior_score(actor, method_name, request)
                decision = "AUTO_ISOLATE" if risk_score >= 70 else "REQUIRE_APPROVAL" if risk_score >= 40 else "IGNORE"
                self.audit.log(
                    AuditAction.SCORING_DECISION,
                    resource_id,
                    details={"decision": decision, "risk_score": risk_score},
                )

                with tracer.start_as_current_span("cicd_supply_chain") as span:
                    span.set_attribute("method", method_name)
                    span.set_attribute("resource", resource_id)
                    span.set_attribute("decision", decision)

                    if decision == "IGNORE":
                        logger.info(f"Cloud Build event {method_name} scored low. Ignoring.")
                        self.audit.log(AuditAction.PLAYBOOK_COMPLETED, resource_id)
                        return True

                    elif decision == "REQUIRE_APPROVAL":
                        logger.info(f"Cloud Build event {method_name} requires approval. Score={risk_score}")
                        self._notify_slack(resource_id, method_name, actor, risk_score, decision)
                        self._publish_alert(resource_id, method_name, risk_score, decision)
                        self.audit.log(AuditAction.APPROVAL_REQUESTED, resource_id)
                        self.audit.log(AuditAction.PLAYBOOK_COMPLETED, resource_id)
                        return True

                    elif decision == "AUTO_ISOLATE":
                        logger.critical(f"AUTO_ISOLATE for Cloud Build resource {resource_id}")

                        # Cancel running build
                        if build_id:
                            self._cancel_build(resource_name, build_id)

                        # Disable build trigger
                        if trigger_id and "CreateBuild" not in method_name:
                            self._disable_trigger(resource_name, trigger_id)

                        # Quarantine output GCS bucket
                        output_bucket = request.get("artifacts", {}).get("objects", {}).get("location", "")
                        if output_bucket:
                            self._quarantine_gcs_bucket(output_bucket, resource_id)

                        self._notify_slack(resource_id, method_name, actor, risk_score, decision)
                        self._publish_alert(resource_id, method_name, risk_score, decision)
                        self.audit.log(AuditAction.PLAYBOOK_COMPLETED, resource_id)
                        return True

            except Exception as e:
                logger.error(f"CI/CD Supply Chain playbook failed: {e}", exc_info=True)
                with contextlib.suppress(Exception):
                    self.audit.log(AuditAction.PLAYBOOK_FAILED, "cloudbuild_resource", success=False)
                return False

        return False

    @staticmethod
    def _behavior_score(actor: str, method_name: str, request: dict[str, Any]) -> float:
        """Behavior-based risk scoring for Cloud Build events."""
        score = 0.0

        # Highly sensitive CI/CD methods
        if "CreateBuild" in method_name:
            # Suspicious substitutions in build
            substitutions = request.get("build", {}).get("substitutions", {})
            if any("secret" in k.lower() or "token" in k.lower() or "key" in k.lower() for k in substitutions):
                score += 40.0
            else:
                score += 15.0
        elif "UpdateBuildTrigger" in method_name or "CreateBuildTrigger" in method_name:
            score += 35.0
        elif "DeleteBuildTrigger" in method_name:
            score += 25.0

        # External service account
        if actor and not actor.endswith(".gserviceaccount.com"):
            score += 20.0

        return min(score, 100.0)

    def _cancel_build(self, resource_name: str, build_id: str) -> None:
        try:
            parts = resource_name.split("/")
            project_id = parts[1] if len(parts) > 1 else "unknown"

            from googleapiclient import discovery  # type: ignore

            service = discovery.build("cloudbuild", "v1")
            service.projects().builds().cancel(projectId=project_id, id=build_id, body={}).execute()
            logger.info(f"Cancelled Cloud Build {build_id}")
            self.audit.log(AuditAction.CANCEL_BUILD, build_id, details={"project": project_id})
        except Exception as e:
            logger.warning(f"Failed to cancel build {build_id}: {e}")

    def _disable_trigger(self, resource_name: str, trigger_id: str) -> None:
        try:
            parts = resource_name.split("/")
            project_id = parts[1] if len(parts) > 1 else "unknown"

            from googleapiclient import discovery  # type: ignore

            service = discovery.build("cloudbuild", "v1")
            # Get trigger and patch disabled=True
            trigger = service.projects().triggers().get(projectId=project_id, triggerId=trigger_id).execute()
            trigger["disabled"] = True
            service.projects().triggers().patch(projectId=project_id, triggerId=trigger_id, body=trigger).execute()
            logger.info(f"Disabled Cloud Build trigger {trigger_id}")
            self.audit.log(AuditAction.DISABLE_BUILD_TRIGGER, trigger_id, details={"project": project_id})
        except Exception as e:
            logger.warning(f"Failed to disable trigger {trigger_id}: {e}")

    def _quarantine_gcs_bucket(self, bucket_path: str, resource_id: str) -> None:
        try:
            # Strip gs:// prefix if present
            bucket_name = bucket_path.replace("gs://", "").split("/")[0]

            from google.cloud import storage  # type: ignore

            storage_client = storage.Client()
            bucket = storage_client.bucket(bucket_name)
            # Remove all IAM bindings by setting uniform bucket-level access
            bucket.patch(iam_configuration={"uniformBucketLevelAccess": {"enabled": True}})
            logger.info(f"Quarantined GCS artifact bucket {bucket_name}")
            self.audit.log(
                AuditAction.QUARANTINE_ARTIFACT,
                bucket_name,
                details={"build_resource": resource_id},
            )
        except Exception as e:
            logger.warning(f"Failed to quarantine GCS bucket {bucket_path}: {e}")

    def _notify_slack(self, resource_id: str, method_name: str, actor: str, score: float, decision: str) -> None:
        try:
            from ..integrations.slack_notifier import SlackNotifier

            notifier = SlackNotifier()
            incident_data = {
                "id": f"CICD-{resource_id}-{method_name}",
                "severity": "CRITICAL" if decision == "AUTO_ISOLATE" else "HIGH",
                "title": f"CI/CD Supply Chain Attack Detected: {method_name}",
                "description": (
                    f"Suspicious Cloud Build action: {method_name}\n"
                    f"Resource: {resource_id}\n"
                    f"Actor: {actor}\n"
                    f"Risk Score: {score}\n"
                    f"Decision: {decision}"
                ),
                "decision": decision,
                "intel_summary": {},
            }
            notifier.send_incident_alert(incident_data)
        except Exception as e:
            logger.warning(f"Failed to send Slack notification: {e}")

    def _publish_alert(self, resource_id: str, method_name: str, score: float, decision: str) -> None:
        try:
            import json

            from google.cloud import pubsub_v1  # type: ignore

            from ..core.config import config

            publisher = pubsub_v1.PublisherClient()
            topic_path = publisher.topic_path(config.project_id, "soar-alerts")
            message_data = json.dumps(
                {
                    "playbook": "CICDSupplyChain",
                    "resource": resource_id,
                    "method": method_name,
                    "score": score,
                    "decision": decision,
                }
            ).encode("utf-8")
            publisher.publish(topic_path, message_data)
        except Exception as e:
            logger.warning(f"Failed to publish Pub/Sub alert: {e}")
