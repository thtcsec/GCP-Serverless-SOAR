"""
GCP SOAR — GKE Pod Isolation Playbook
Handles GKE runtime threat findings from Security Command Center (Container Threat Detection).
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from src.core.audit_logger import AuditAction, AuditLogger
from src.core.metrics import PlaybookTimer, emit_metric
from src.models.events import SCCFinding
from src.playbooks.base import Playbook

logger = logging.getLogger("gcp-soar.playbook.gke_pod")

# Container Threat Detection categories
_GKE_THREAT_CATEGORIES: list[str] = [
    "Execution: Malicious binary",
    "Execution: Kubernetes attack tool",
    "Privilege Escalation",
    "Defense Evasion",
    "Command and Control",
    "Container Escape",
]


class GKEPodIsolationPlaybook(Playbook):
    """Playbook to isolate/evict compromised pods in GKE clusters."""

    def __init__(self) -> None:
        self.audit = AuditLogger()

    def can_handle(self, event_data: dict[str, Any]) -> bool:
        try:
            finding = SCCFinding(**event_data)
            # Must be a GKE cluster or Node resource, and match one of our categories
            is_gke = "gke.googleapis.com" in finding.resource.type or "gke.googleapis.com" in finding.resource_name
            return is_gke and any(cat.lower() in finding.category.lower() for cat in _GKE_THREAT_CATEGORIES)
        except Exception:
            return False

    def execute(self, event_data: dict[str, Any]) -> bool:
        with PlaybookTimer("GKEPodIsolation"):
            try:
                finding = SCCFinding(**event_data)

                # Extract resource components
                # GKE findings usually have properties inside sourceProperties
                props = finding.source_properties
                cluster_name = props.get("cluster_name") or finding.resource.name.split("/")[-1]
                namespace_name = props.get("namespace") or "default"
                pod_name = props.get("pod")

                if not cluster_name:
                    logger.error("No GKE cluster name found in SCC finding")
                    return False

                if not pod_name:
                    logger.warning("No pod name found in finding; cannot isolate specific pod.")
                    return False

                logger.info(f"Executing GKE Pod Isolation for cluster={cluster_name}, pod={pod_name}")
                self.audit.log(
                    AuditAction.PLAYBOOK_STARTED,
                    f"{cluster_name}/{namespace_name}/{pod_name}",
                    actor="GCP_SOAR",
                    details={"finding_type": finding.category, "severity": finding.severity},
                )
                emit_metric("findings_processed", 1.0, {"playbook": "GKEPodIsolation"})

                # Severity-based decision
                decision = self._severity_decision(finding.severity)
                self.audit.log(
                    AuditAction.SCORING_DECISION,
                    cluster_name,
                    actor="GCP_SOAR",
                    details={"decision": decision, "severity": finding.severity},
                )

                if decision == "IGNORE":
                    logger.info(f"GKE finding for {cluster_name} severity too low. Ignoring.")
                    self.audit.log(AuditAction.PLAYBOOK_COMPLETED, cluster_name, actor="GCP_SOAR")
                    return True

                if decision in ("AUTO_ISOLATE", "REQUIRE_APPROVAL"):
                    self._apply_quarantine_label(cluster_name, namespace_name, pod_name)
                    if decision == "AUTO_ISOLATE":
                        self._evict_pod(cluster_name, namespace_name, pod_name)

                self.audit.log(AuditAction.PLAYBOOK_COMPLETED, cluster_name, actor="GCP_SOAR")
                return True

            except Exception as e:
                logger.error(f"GKE Pod Isolation playbook failed: {e}", exc_info=True)
                with contextlib.suppress(Exception):
                    self.audit.log(
                        AuditAction.PLAYBOOK_FAILED,
                        "gke_pod",
                        actor="GCP_SOAR",
                        success=False,
                    )
                return False

    @staticmethod
    def _severity_decision(severity: str) -> str:
        """Map SCC severity to SOAR decision."""
        if severity in ("CRITICAL", "HIGH"):
            return "AUTO_ISOLATE"
        elif severity == "MEDIUM":
            return "REQUIRE_APPROVAL"
        return "IGNORE"

    def _get_k8s_client(self):
        """Load internal k8s client config."""
        from kubernetes import client, config

        try:
            # Try in-cluster first (if running on GKE)
            config.load_incluster_config()
        except config.config_exception.ConfigException:
            # Fallback to kubeconfig (useful for local testing with simulator)
            config.load_kube_config()
        return client

    def _apply_quarantine_label(self, cluster_name: str, namespace: str, pod_name: str) -> None:
        """Label pod with soar-quarantine=true to isolate it from services."""
        try:
            client = self._get_k8s_client()
            v1 = client.CoreV1Api()

            body = {"metadata": {"labels": {"soar-quarantine": "true"}}}
            v1.patch_namespaced_pod(name=pod_name, namespace=namespace, body=body)

            logger.info(f"Applied soar-quarantine label to pod {pod_name} in {cluster_name}")
            # Note: For strict typing, we might need a custom AuditAction for kubernetes,
            # but usually KILL_PROCESS or ISOLATE_NETWORK is conceptually enough.
            # EKS in AWS uses APPLY_NETWORK_POLICY. We'll use ISOLATE_NETWORK.
            self.audit.log(
                AuditAction.ISOLATE_NETWORK,
                f"{cluster_name}/{namespace}/{pod_name}",
                actor="GCP_SOAR",
                details={"label": "soar-quarantine=true"},
            )
        except Exception as e:
            logger.warning(f"Failed to apply quarantine label to {pod_name}: {e}")
            self.audit.log(
                AuditAction.ISOLATE_NETWORK,
                f"{cluster_name}/{namespace}/{pod_name}",
                actor="GCP_SOAR",
                success=False,
                details={"error": str(e)},
            )

    def _evict_pod(self, cluster_name: str, namespace: str, pod_name: str) -> None:
        """Gracefully evict the pod using the Eviction API."""
        try:
            client = self._get_k8s_client()
            v1 = client.CoreV1Api()

            body = client.V1Eviction(metadata=client.V1ObjectMeta(name=pod_name, namespace=namespace))
            v1.create_namespaced_pod_eviction(name=pod_name, namespace=namespace, body=body)

            logger.info(f"Successfully sent eviction request for pod {pod_name}")
            self.audit.log(
                AuditAction.KILL_PROCESS,
                f"{cluster_name}/{namespace}/{pod_name}",
                actor="GCP_SOAR",
                details={"action": "eviction"},
            )
        except Exception as e:
            logger.warning(f"Failed to evict pod {pod_name}: {e}")
            self.audit.log(
                AuditAction.KILL_PROCESS,
                f"{cluster_name}/{namespace}/{pod_name}",
                actor="GCP_SOAR",
                success=False,
                details={"error": str(e)},
            )
