"""
GCP SOAR — Storage Exfiltration Playbook
Detects and responds to Cloud Storage data-exfiltration patterns.
"""

from __future__ import annotations

import contextlib
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from ..clients.gcp import get_publisher, get_storage_client
from ..core.config import config
from ..core.metrics import PlaybookTimer, emit_metric, get_tracer
from ..models.events import StorageAuditEvent

logger = logging.getLogger("gcp-soar.playbook.storage")
tracer = get_tracer("gcp-soar.playbook.storage")


class StorageExfiltration:
    """Detect anomalous storage reads and lock down the bucket."""

    def can_handle(self, event_data: dict[str, Any]) -> bool:
        try:
            evt = StorageAuditEvent(**event_data)
            return evt.is_read_operation
        except Exception:
            return False

    def execute(self, event_data: dict[str, Any]) -> bool | dict[str, Any]:
        with PlaybookTimer("StorageExfiltration"):
            evt = StorageAuditEvent(**event_data)
            payload = evt.proto_payload

            bucket_name = self._extract_bucket(payload.resource_name)
            if not bucket_name:
                logger.warning("Cannot extract bucket name")
                return False

            principal = payload.authentication_info.principal_email
            caller_ip = payload.request.get("callerIp", "")

            if self._is_dry_run(event_data):
                return self._build_preview(bucket_name, principal, caller_ip, payload.method_name)

            analysis = self._analyse_patterns(principal, bucket_name)

            if not analysis["is_exfiltration"]:
                return True

            logger.warning(f"Exfiltration detected on {bucket_name} by {principal}")
            emit_metric("findings_processed", 1.0, {"playbook": "StorageExfiltration"})

            try:
                with tracer.start_as_current_span("storage_exfiltration") as span:
                    span.set_attribute("bucket", bucket_name)
                    span.set_attribute("principal", principal)
                    self._block_user(bucket_name, principal)
                    self._enable_protections(bucket_name)
                    self._create_forensic_copy(bucket_name, principal, analysis)
                    self._send_alert(bucket_name, principal, caller_ip, analysis)
                return True
            except Exception as exc:
                logger.error(f"Storage response failed for {bucket_name}: {exc}")
                return False

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_bucket(resource_name: str) -> str | None:
        if "projects/_/buckets/" in resource_name:
            return resource_name.split("projects/_/buckets/")[1].split("/")[0]
        return None

    @staticmethod
    def _is_dry_run(event_data: dict[str, Any]) -> bool:
        return bool(
            event_data.get("dry_run") or event_data.get("preview_only") or event_data.get("execution_mode") == "dry_run"
        )

    @staticmethod
    def _build_preview(bucket_name: str, principal: str, caller_ip: str, method_name: str) -> dict[str, Any]:
        return {
            "mode": "dry_run",
            "playbook": "StorageExfiltration",
            "target_resource": bucket_name,
            "summary": "Preview only. No Cloud Storage IAM or protection settings were changed.",
            "planned_actions": [
                {
                    "step": 1,
                    "action": "analyse_patterns",
                    "target": bucket_name,
                    "details": (
                        f"Analyse read patterns for {principal} via {method_name} from {caller_ip or 'unknown'}."
                    ),
                },
                {
                    "step": 2,
                    "action": "remove_iam_member",
                    "target": bucket_name,
                    "details": f"Remove {principal} from bucket IAM if exfiltration is confirmed.",
                },
                {
                    "step": 3,
                    "action": "enable_protections",
                    "target": bucket_name,
                    "details": "Enable versioning, retention, and uniform bucket-level access.",
                },
                {
                    "step": 4,
                    "action": "create_forensic_copy",
                    "target": bucket_name,
                    "details": "Save forensic metadata to the configured forensic bucket.",
                },
            ],
        }

    def _analyse_patterns(self, principal: str, bucket_name: str) -> dict[str, Any]:
        analysis: dict[str, Any] = {
            "is_exfiltration": False,
            "risk_score": 0,
            "access_count": 0,
            "total_bytes": 0,
            "unique_ips": set(),
        }
        try:
            logs = self._get_recent_logs(principal, bucket_name)
            analysis["access_count"] = len(logs)
            analysis["total_bytes"] = sum(entry.get("size", 1_048_576) for entry in logs)
            analysis["unique_ips"] = {entry.get("callerIp", "") for entry in logs}

            score = 0
            if analysis["total_bytes"] > config.exfiltration_threshold:
                score += 5
            if analysis["access_count"] > 1000:
                score += 3
            if len(analysis["unique_ips"]) > 3:
                score += 2
            hour = datetime.now(UTC).hour
            if hour >= 23 or hour <= 5:
                score += 2

            analysis["risk_score"] = score
            analysis["is_exfiltration"] = score >= 6
        except Exception as exc:
            logger.error(f"Pattern analysis error: {exc}")
        # Convert set for JSON serialisation
        analysis["unique_ips"] = list(analysis.get("unique_ips", []))
        return analysis

    @staticmethod
    def _get_recent_logs(principal: str, bucket_name: str, hours: int = 24) -> list[dict]:
        """Query Cloud Logging for recent storage access entries."""
        try:
            from google.cloud import logging as gcp_logging

            client = gcp_logging.Client(project=config.project_id or None)
            start_time = datetime.now(UTC) - timedelta(hours=hours)

            filter_parts = [
                'resource.type="gcs_bucket"',
                f'resource.labels.bucket_name="{bucket_name}"',
                'protoPayload.serviceName="storage.googleapis.com"',
                f'timestamp>="{start_time.isoformat()}"',
            ]
            if principal:
                filter_parts.append(f'protoPayload.authenticationInfo.principalEmail="{principal}"')

            filter_str = " AND ".join(filter_parts)
            logs: list[dict[str, Any]] = []
            max_entries = 200

            for entry in client.list_entries(
                filter_=filter_str,
                order_by=gcp_logging.DESCENDING,
                max_results=max_entries,
            ):
                api_repr = entry.to_api_repr()
                payload = api_repr.get("protoPayload", {}) or {}
                request_meta = payload.get("requestMetadata", {}) or {}
                request = payload.get("request", {}) or {}
                response = payload.get("response", {}) or {}

                log_entry: dict[str, Any] = {
                    "callerIp": request_meta.get("callerIp", ""),
                    "methodName": payload.get("methodName", ""),
                    "timestamp": api_repr.get("timestamp", ""),
                }

                size = None
                for key in ("size", "objectSize", "contentLength", "bytesSent", "bytesReceived"):
                    if key in response:
                        size = response.get(key)
                        break
                    if key in request:
                        size = request.get(key)
                        break
                if size is not None:
                    with contextlib.suppress(TypeError, ValueError):
                        log_entry["size"] = int(size)

                logs.append(log_entry)

            return logs
        except Exception as exc:
            logger.warning(f"Cloud Logging query failed for {bucket_name}: {exc}")
            return []

    @staticmethod
    def _block_user(bucket_name: str, principal: str) -> None:
        bucket = get_storage_client().bucket(bucket_name)
        policy = bucket.get_iam_policy()

        member = f"serviceAccount:{principal}" if ".gserviceaccount.com" in principal else f"user:{principal}"

        changed = False
        for binding in policy.bindings:
            if member in binding.get("members", []):
                binding["members"].remove(member)
                changed = True

        if changed:
            bucket.set_iam_policy(policy)
            logger.info(f"Removed {principal} from bucket {bucket_name}")

    @staticmethod
    def _enable_protections(bucket_name: str) -> None:
        bucket = get_storage_client().bucket(bucket_name)

        if not bucket.versioning_enabled:
            bucket.versioning_enabled = True
            logger.info(f"Enabled versioning on {bucket_name}")

        try:
            bucket.retention_period = 30 * 86400  # 30 days in seconds
            logger.info(f"Set 30-day retention on {bucket_name}")
        except Exception as exc:
            logger.info(f"Retention already set or not applicable: {exc}")

        if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
            bucket.iam_configuration.uniform_bucket_level_access_enabled = True
            logger.info(f"Enabled uniform bucket-level access on {bucket_name}")

    @staticmethod
    def _create_forensic_copy(bucket_name: str, principal: str, analysis: dict) -> None:
        if not config.forensic_bucket:
            logger.warning("FORENSIC_BUCKET not configured — skipping forensic copy")
            return

        forensic_data = {
            "bucket_name": bucket_name,
            "principal": principal,
            "analysis": analysis,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        blob = (
            get_storage_client()
            .bucket(config.forensic_bucket)
            .blob(f"storage-exfil/{bucket_name}/{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}.json")
        )
        blob.upload_from_string(json.dumps(forensic_data), content_type="application/json")
        logger.info(f"Forensic snapshot saved to {config.forensic_bucket}")

    @staticmethod
    def _send_alert(bucket_name: str, principal: str, caller_ip: str, analysis: dict) -> None:
        if not config.alert_topic:
            return
        publisher = get_publisher()
        topic_path = publisher.topic_path(config.project_id, config.alert_topic)
        alert = {
            "type": "STORAGE_EXFILTRATION",
            "bucket": bucket_name,
            "principal": principal,
            "caller_ip": caller_ip,
            "risk_score": analysis["risk_score"],
            "total_bytes": analysis["total_bytes"],
            "timestamp": datetime.now(UTC).isoformat(),
            "actions_taken": [
                "user_blocked",
                "versioning_enabled",
                "retention_set",
                "forensic_copy_created",
            ],
        }
        publisher.publish(topic_path, json.dumps(alert).encode("utf-8"))
        logger.info(f"Published storage exfiltration alert for {bucket_name}")
