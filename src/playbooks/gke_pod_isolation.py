"""
GCP SOAR — GKE Pod Isolation Playbook
Handles GKE runtime threat findings from Security Command Center (Container Threat Detection).
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

from src.clients.gcp import get_storage_client
from src.core.audit_logger import AuditAction, AuditLogger
from src.core.config import config
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

    def execute(self, event_data: dict[str, Any]) -> bool | dict[str, Any]:
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

                if self._is_dry_run(event_data):
                    return self._build_preview(
                        cluster_name, namespace_name, pod_name, finding.category, finding.severity
                    )

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
                    self._collect_pod_evidence(cluster_name, namespace_name, pod_name, finding.name)
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

    @staticmethod
    def _is_dry_run(event_data: dict[str, Any]) -> bool:
        return bool(
            event_data.get("dry_run") or event_data.get("preview_only") or event_data.get("execution_mode") == "dry_run"
        )

    @staticmethod
    def _build_preview(
        cluster_name: str,
        namespace: str,
        pod_name: str,
        category: str,
        severity: str,
    ) -> dict[str, Any]:
        decision = GKEPodIsolationPlaybook._severity_decision(severity)
        planned_actions = [
            {
                "step": 1,
                "action": "severity_decision",
                "target": cluster_name,
                "details": f"Map severity '{severity}' to decision '{decision}' for category '{category}'.",
            },
            {
                "step": 2,
                "action": "patch_namespaced_pod",
                "target": f"{cluster_name}/{namespace}/{pod_name}",
                "details": "Apply soar-quarantine=true label to isolate the pod.",
            },
        ]
        if decision == "AUTO_ISOLATE":
            planned_actions.append(
                {
                    "step": 3,
                    "action": "create_namespaced_pod_eviction",
                    "target": f"{cluster_name}/{namespace}/{pod_name}",
                    "details": "Evict the compromised pod from the cluster.",
                }
            )

        return {
            "mode": "dry_run",
            "playbook": "GKEPodIsolation",
            "target_resource": f"{cluster_name}/{namespace}/{pod_name}",
            "decision": decision,
            "planned_actions": planned_actions,
            "summary": "Preview only. No Kubernetes remediation APIs were executed.",
        }

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

    @staticmethod
    def _safe_key_component(value: str) -> str:
        return value.replace("/", "_").replace(":", "_")

    def _collect_pod_evidence(self, cluster_name: str, namespace: str, pod_name: str, finding_name: str) -> None:
        if not config.forensic_bucket:
            logger.warning("FORENSIC_BUCKET not configured — skipping pod evidence collection")
            return

        try:
            client = self._get_k8s_client()
            v1 = client.CoreV1Api()

            log_tail = int(os.environ.get("GKE_POD_LOG_TAIL", "2000"))
            log_since = int(os.environ.get("GKE_POD_LOG_SINCE_SECONDS", "3600"))
            log_timeout = int(os.environ.get("GKE_POD_LOG_TIMEOUT", "60"))
            include_previous = os.environ.get("GKE_POD_LOG_PREVIOUS", "false").lower() in ("1", "true", "yes")

            artifacts: dict[str, str] = {}
            errors: dict[str, str] = {}
            evidence: dict[str, Any] = {
                "cluster_name": cluster_name,
                "namespace": namespace,
                "pod_name": pod_name,
                "finding_name": finding_name,
                "collected_at": datetime.now(UTC).isoformat(),
                "log_tail": log_tail,
                "log_since_seconds": log_since,
                "include_previous": include_previous,
                "artifacts": artifacts,
                "errors": errors,
            }

            safe_finding = self._safe_key_component(finding_name) or datetime.now(UTC).strftime("%Y%m%d%H%M%S")
            key_prefix = f"evidence/gke/{cluster_name}/{namespace}/{pod_name}/{safe_finding}"
            bucket = get_storage_client().bucket(config.forensic_bucket)

            def upload_text(key: str, payload: str, content_type: str) -> None:
                blob = bucket.blob(key)
                blob.upload_from_string(payload, content_type=content_type)

            try:
                logs_output = v1.read_namespaced_pod_log(
                    name=pod_name,
                    namespace=namespace,
                    tail_lines=log_tail,
                    since_seconds=log_since if log_since > 0 else None,
                    _request_timeout=log_timeout,
                )
                if logs_output:
                    log_key = f"{key_prefix}.log"
                    upload_text(log_key, logs_output, "text/plain")
                    artifacts["logs"] = log_key
            except Exception as exc:
                errors["logs"] = str(exc)

            if include_previous:
                try:
                    prev_output = v1.read_namespaced_pod_log(
                        name=pod_name,
                        namespace=namespace,
                        tail_lines=log_tail,
                        since_seconds=log_since if log_since > 0 else None,
                        previous=True,
                        _request_timeout=log_timeout,
                    )
                    if prev_output:
                        prev_key = f"{key_prefix}.previous.log"
                        upload_text(prev_key, prev_output, "text/plain")
                        artifacts["previous_logs"] = prev_key
                except Exception as exc:
                    errors["previous_logs"] = str(exc)

            try:
                pod_obj = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
                describe_key = f"{key_prefix}.describe.json"
                upload_text(describe_key, json.dumps(pod_obj.to_dict(), indent=2), "application/json")
                artifacts["describe"] = describe_key
            except Exception as exc:
                errors["describe"] = str(exc)

            try:
                events = v1.list_namespaced_event(
                    namespace=namespace,
                    field_selector=f"involvedObject.name={pod_name},involvedObject.kind=Pod",
                )
                events_key = f"{key_prefix}.events.json"
                payload = json.dumps([event.to_dict() for event in events.items], indent=2)
                upload_text(events_key, payload, "application/json")
                artifacts["events"] = events_key
            except Exception as exc:
                errors["events"] = str(exc)

            meta_key = f"{key_prefix}.json"
            upload_text(meta_key, json.dumps(evidence), "application/json")

            self.audit.log(
                AuditAction.COLLECT_POD_LOGS,
                f"{cluster_name}/{namespace}/{pod_name}",
                actor="GCP_SOAR",
                details={"gcs_key": meta_key, "artifacts": evidence.get("artifacts", {})},
            )
        except Exception as exc:
            logger.warning(f"Failed to collect GKE pod evidence for {pod_name}: {exc}")

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
