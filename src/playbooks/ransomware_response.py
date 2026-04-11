"""
GCP SOAR — Ransomware Response Playbook
Handles ransomware / malware events detected by Security Command Center.

Actions:
1. Snapshot all disks attached to the compromised Compute Engine instance.
2. Isolate the instance by replacing its network tags (firewall isolation).
3. Enable Cloud Storage Object Versioning (if a bucket is involved).
4. Remove public/allUsers IAM bindings on the bucket.
5. Stop the instance to prevent lateral movement.
"""

from __future__ import annotations

import contextlib
import logging
from datetime import UTC, datetime
from typing import Any

from google.cloud import compute_v1

from src.clients import gcp
from src.core.audit_logger import AuditAction, AuditLogger
from src.core.config import config
from src.models.events import SCCFinding
from src.playbooks.base import Playbook

logger = logging.getLogger("gcp-soar.playbook.ransomware")

# SCC categories that signal ransomware-like behaviour
_RANSOMWARE_CATEGORIES: list[str] = [
    "Ransomware",
    "Malware",
    "Cryptocurrency mining",
    "Backdoor",
    "Cryptomining",
]


class RansomwareResponsePlaybook(Playbook):
    """Auto-contain ransomware threats across GCE and Cloud Storage."""

    def can_handle(self, event_data: dict[str, Any]) -> bool:
        try:
            finding = SCCFinding(**event_data)
            return (
                finding.is_high_severity
                and any(cat.lower() in finding.category.lower() for cat in _RANSOMWARE_CATEGORIES)
            )
        except Exception:
            return False

    def execute(self, event_data: dict[str, Any]) -> bool:
        try:
            finding = SCCFinding(**event_data)
            audit = AuditLogger()

            logger.info(
                f"Executing Ransomware Response for category={finding.category}",
                extra={"json_fields": {"category": finding.category}},
            )
            audit.log(AuditAction.PLAYBOOK_STARTED, finding.name, actor="GCP_SOAR")

            # --- Compute Engine branch --------------------------------------
            if finding.is_compute_resource:
                project, zone, instance = self._parse_resource(finding.resource_name)
                if instance:
                    self._snapshot_disks(project, zone, instance, finding.category)
                    self._isolate_instance(project, zone, instance)
                    self._stop_instance(project, zone, instance)

            # --- Cloud Storage branch ----------------------------------------
            bucket_name = self._extract_bucket_name(finding)
            if bucket_name:
                self._enable_versioning(bucket_name)
                self._remove_public_access(bucket_name)

            audit.log(AuditAction.PLAYBOOK_COMPLETED, finding.name, actor="GCP_SOAR")
            return True

        except Exception as exc:
            logger.error(f"Ransomware Response failed: {exc}", exc_info=True)
            with contextlib.suppress(Exception):
                AuditLogger().log(
                    AuditAction.PLAYBOOK_FAILED,
                    "ransomware_response",
                    actor="GCP_SOAR",
                    success=False,
                )
            return False

    # ------------------------------------------------------------------ #
    # Resource helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_resource(resource_name: str) -> tuple[str, str, str]:
        """Extract (project, zone, instance) from SCC resource name."""
        parts = resource_name.split("/")
        try:
            return parts[4], parts[6], parts[8]
        except IndexError:
            return "", "", ""

    @staticmethod
    def _extract_bucket_name(finding: SCCFinding) -> str | None:
        """Extract bucket name from SCC finding if present."""
        rn = finding.resource_name
        if "/buckets/" in rn:
            parts = rn.split("/")
            idx = parts.index("buckets")
            if idx + 1 < len(parts):
                return parts[idx + 1]
        return None

    # ------------------------------------------------------------------ #
    # Compute Engine actions
    # ------------------------------------------------------------------ #

    @staticmethod
    def _snapshot_disks(project: str, zone: str, instance_name: str, category: str) -> None:
        """Snapshot every disk attached to the instance."""
        instances_client = gcp.get_instances_client()
        instance = instances_client.get(project=project, zone=zone, instance=instance_name)

        for disk in instance.disks:
            disk_name = disk.source.split("/")[-1]
            ts = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
            snapshot_name = f"ransomware-{instance_name}-{disk_name}-{ts}"

            snapshot_resource = compute_v1.Snapshot(
                name=snapshot_name,
                description=f"SOAR ransomware quarantine – threat: {category}",
                labels={
                    "purpose": "ransomware-quarantine",
                    "threat": category.lower().replace(" ", "-"),
                    "source-instance": instance_name,
                },
            )
            gcp.get_disks_client().create_snapshot(
                project=project,
                zone=zone,
                disk=disk_name,
                snapshot_resource=snapshot_resource,
            )
            logger.info(f"Initiated snapshot {snapshot_name} for disk {disk_name}")

    @staticmethod
    def _isolate_instance(project: str, zone: str, instance_name: str) -> None:
        """Replace instance tags so deny-all firewall rules apply."""
        client = gcp.get_instances_client()
        instance = client.get(project=project, zone=zone, instance=instance_name)
        tags = instance.tags
        tags.items = [config.isolation_tag]
        op = client.set_tags(project=project, zone=zone, instance=instance_name, tags_resource=tags)
        op.result()
        logger.info(f"Applied isolation tag '{config.isolation_tag}' to {instance_name}")

    @staticmethod
    def _stop_instance(project: str, zone: str, instance_name: str) -> None:
        gcp.get_instances_client().stop(project=project, zone=zone, instance=instance_name)
        logger.info(f"Stopped instance {instance_name}")

    # ------------------------------------------------------------------ #
    # Cloud Storage actions
    # ------------------------------------------------------------------ #

    @staticmethod
    def _enable_versioning(bucket_name: str) -> None:
        """Enable Object Versioning on the bucket."""
        client = gcp.get_storage_client()
        bucket = client.get_bucket(bucket_name)
        bucket.versioning_enabled = True
        bucket.patch()
        logger.info(f"Enabled Object Versioning on bucket {bucket_name}")

    @staticmethod
    def _remove_public_access(bucket_name: str) -> None:
        """Remove allUsers / allAuthenticatedUsers IAM bindings."""
        client = gcp.get_storage_client()
        bucket = client.get_bucket(bucket_name)
        policy = bucket.get_iam_policy(requested_policy_version=3)

        dangerous_members = {"allUsers", "allAuthenticatedUsers"}
        modified = False
        for binding in policy.bindings:
            before = set(binding["members"])
            binding["members"] = [m for m in binding["members"] if m not in dangerous_members]
            if set(binding["members"]) != before:
                modified = True

        if modified:
            bucket.set_iam_policy(policy)
            logger.info(f"Removed public IAM bindings from bucket {bucket_name}")
        else:
            logger.info(f"No public IAM bindings found on bucket {bucket_name}")
