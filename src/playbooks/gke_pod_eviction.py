"""
GCP SOAR — GKE Pod Eviction Playbook
Handles GKE container threat findings and risky Kubernetes audit events.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from ..core.audit_logger import AuditAction, AuditLogger
from ..core.metrics import PlaybookTimer, emit_metric, get_tracer
from ..models.events import GKEAuditEvent, SCCFinding

logger = logging.getLogger("gcp-soar.playbook.gke")
tracer = get_tracer("gcp-soar.playbook.gke")


class GKEPodEvictionPlaybook:
    """Quarantine and evict compromised pods in GKE clusters."""

    def __init__(self) -> None:
        self.audit = AuditLogger()

    def can_handle(self, event_data: dict[str, Any]) -> bool:
        try:
            # Check SCC CONTAINER_THREAT category
            category = event_data.get("category", "")
            if "CONTAINER_THREAT" in category or "container_threat" in category.lower():
                finding = SCCFinding.model_validate(event_data)
                return finding.is_high_severity

            # Check GKE audit log with risky method
            proto = event_data.get("protoPayload", {})
            service = proto.get("serviceName", "")
            if "container.googleapis.com" in service or "k8s.io" in service:
                event = GKEAuditEvent.model_validate(event_data)
                return event.is_risky

            return False
        except Exception:
            return False

    def execute(self, event_data: dict[str, Any]) -> bool:
        with PlaybookTimer("GKEPodEviction"):
            try:
                # Parse event details
                resource_name = ""
                method_name = ""
                cluster_name = ""
                namespace = "default"
                pod_name = ""
                severity_str = "MEDIUM"

                proto = event_data.get("protoPayload", {})
                if proto:
                    method_name = proto.get("methodName", "")
                    resource_name = proto.get("resourceName", "")
                    # Extract cluster, namespace, pod from resource name
                    cluster_name, namespace, pod_name = self._parse_k8s_resource(resource_name)
                    severity_str = event_data.get("severity", "MEDIUM")
                else:
                    # SCC finding
                    resource_name = event_data.get("resourceName", "")
                    severity_str = event_data.get("severity", "MEDIUM")
                    cluster_name = resource_name.split("/")[-1] if resource_name else "unknown"

                if not cluster_name:
                    logger.error("Could not extract cluster name from GKE event")
                    return False

                logger.info(f"Executing GKE Pod Eviction for cluster={cluster_name}, pod={pod_name}")
                self.audit.log(
                    AuditAction.PLAYBOOK_STARTED,
                    f"{cluster_name}/{namespace}/{pod_name}",
                    details={"method": method_name, "severity": severity_str},
                )
                emit_metric("findings_processed", 1.0, {"playbook": "GKEPodEviction"})

                severity_map = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 5.0, "LOW": 2.0}
                sev_score = severity_map.get(severity_str.upper(), 5.0)
                decision = "AUTO_ISOLATE" if sev_score >= 7.0 else "REQUIRE_APPROVAL" if sev_score >= 4.0 else "IGNORE"
                self.audit.log(AuditAction.SCORING_DECISION, cluster_name, details={"decision": decision})

                with tracer.start_as_current_span("gke_pod_eviction") as span:
                    span.set_attribute("cluster", cluster_name)
                    span.set_attribute("pod", pod_name)
                    span.set_attribute("decision", decision)

                    if decision == "IGNORE":
                        logger.info("GKE event low severity. Ignoring.")
                        self.audit.log(AuditAction.PLAYBOOK_COMPLETED, cluster_name)
                        return True

                    # Collect logs to GCS
                    if pod_name:
                        self._collect_pod_logs_to_gcs(cluster_name, namespace, pod_name)

                    if decision in ("AUTO_ISOLATE", "REQUIRE_APPROVAL") and pod_name:
                        self._apply_quarantine_label(cluster_name, namespace, pod_name)

                    self.audit.log(AuditAction.PLAYBOOK_COMPLETED, cluster_name)
                    return True

            except Exception as e:
                logger.error(f"GKE Pod Eviction playbook failed: {e}", exc_info=True)
                with contextlib.suppress(Exception):
                    self.audit.log(AuditAction.PLAYBOOK_FAILED, "gke_pod", success=False)
                return False

        return False

    @staticmethod
    def _parse_k8s_resource(resource_name: str) -> tuple[str, str, str]:
        """Extract (cluster, namespace, pod) from Kubernetes resource name."""
        # Format: //container.googleapis.com/projects/.../clusters/{cluster}/namespaces/{ns}/pods/{pod}
        try:
            parts = resource_name.split("/")
            cluster = ""
            namespace = "default"
            pod = ""
            for i, part in enumerate(parts):
                if part == "clusters" and i + 1 < len(parts):
                    cluster = parts[i + 1]
                elif part == "namespaces" and i + 1 < len(parts):
                    namespace = parts[i + 1]
                elif part == "pods" and i + 1 < len(parts):
                    pod = parts[i + 1]
            return cluster, namespace, pod
        except Exception:
            return resource_name, "default", ""

    def _apply_quarantine_label(self, cluster_name: str, namespace: str, pod_name: str) -> None:
        """Label pod as quarantined via GKE API."""
        try:
            import subprocess

            label_cmd = [
                "kubectl",
                f"--context=gke_{cluster_name}",
                "--namespace",
                namespace,
                "label",
                "pod",
                pod_name,
                "soar-quarantine=true",
                "--overwrite",
            ]
            result = subprocess.run(label_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                logger.info(f"Applied soar-quarantine label to pod {pod_name}")
                self.audit.log(
                    AuditAction.APPLY_NETWORK_POLICY,
                    f"{cluster_name}/{namespace}/{pod_name}",
                    details={"label": "soar-quarantine=true"},
                )
            else:
                logger.warning(f"kubectl label failed: {result.stderr}")
                self.audit.log(
                    AuditAction.APPLY_NETWORK_POLICY,
                    f"{cluster_name}/{namespace}/{pod_name}",
                    success=False,
                )
        except Exception as e:
            logger.warning(f"Failed to apply quarantine label: {e}")

    def _collect_pod_logs_to_gcs(self, cluster_name: str, namespace: str, pod_name: str) -> None:
        """Upload pod evidence metadata to GCS."""
        try:
            import json
            from datetime import UTC, datetime

            from google.cloud import storage  # type: ignore

            from ..core.config import config

            evidence = {
                "cluster_name": cluster_name,
                "namespace": namespace,
                "pod_name": pod_name,
                "collected_at": datetime.now(UTC).isoformat(),
                "note": "GKE pod log collection placeholder",
            }
            storage_client = storage.Client()
            bucket = storage_client.bucket(config.forensic_bucket or "soar-evidence")
            blob_name = f"evidence/gke/{cluster_name}/{namespace}/{pod_name}.json"
            blob = bucket.blob(blob_name)
            blob.upload_from_string(json.dumps(evidence), content_type="application/json")
            logger.info(f"Uploaded GKE pod evidence to gs://{config.forensic_bucket}/{blob_name}")
            self.audit.log(
                AuditAction.COLLECT_POD_LOGS,
                f"{cluster_name}/{namespace}/{pod_name}",
                details={"gcs_blob": blob_name},
            )
        except Exception as e:
            logger.warning(f"Failed to collect GKE pod logs: {e}")
