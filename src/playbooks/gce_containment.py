"""
GCP SOAR — GCE Containment Playbook
Handles Compute Engine VM compromise events from Security Command Center.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from google.cloud import compute_v1

from ..clients.gcp import get_disks_client, get_instances_client
from ..core.config import config
from ..core.metrics import PlaybookTimer, emit_metric, get_tracer
from ..models.events import SCCFinding

logger = logging.getLogger("gcp-soar.playbook.gce")
tracer = get_tracer("gcp-soar.playbook.gce")

ALLOWED_CATEGORIES = ["Cryptocurrency mining", "Backdoor", "Malware"]


class GCEContainment:
    """Isolate, snapshot, and stop a compromised GCE instance."""

    # ------------------------------------------------------------------ #
    # Protocol methods
    # ------------------------------------------------------------------ #

    def can_handle(self, event_data: dict[str, Any]) -> bool:
        try:
            finding = SCCFinding(**event_data)
            return (
                finding.is_compute_resource
                and finding.is_high_severity
                and any(cat in finding.category for cat in ALLOWED_CATEGORIES)
            )
        except Exception:
            return False

    def execute(self, event_data: dict[str, Any]) -> bool | dict[str, Any]:
        with PlaybookTimer("GCEContainment"):
            finding = SCCFinding(**event_data)
            project_id, zone, instance_name = self._parse_resource(finding.resource_name)

            if not instance_name:
                logger.error("Cannot extract instance details from resource name")
                return False

            if self._is_dry_run(event_data):
                return self._build_preview(project_id, zone, instance_name, finding.category)

            logger.info(
                f"Executing GCE containment for {instance_name}",
                extra={"json_fields": {"action": "GCE_CONTAINMENT", "instance": instance_name}},
            )
            emit_metric("findings_processed", 1.0, {"playbook": "GCEContainment"})

            try:
                with tracer.start_as_current_span("gce_containment") as span:
                    span.set_attribute("instance", instance_name)
                    self._isolate_instance(project_id, zone, instance_name)
                    self._detach_service_account(project_id, zone, instance_name)
                    self._block_ssh_keys(project_id, zone, instance_name)
                    self._take_snapshot(project_id, zone, instance_name, finding.category)
                    self._stop_instance(project_id, zone, instance_name)
                logger.info(f"GCE containment completed for {instance_name}")
                return True
            except Exception as exc:
                logger.error(f"GCE containment failed for {instance_name}: {exc}")
                return False

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_resource(resource_name: str):
        """Extract (project_id, zone, instance_name) from SCC resource name."""
        parts = resource_name.split("/")
        try:
            return parts[4], parts[6], parts[8]
        except IndexError:
            return None, None, None

    @staticmethod
    def _is_dry_run(event_data: dict[str, Any]) -> bool:
        return bool(
            event_data.get("dry_run") or event_data.get("preview_only") or event_data.get("execution_mode") == "dry_run"
        )

    @staticmethod
    def _build_preview(project_id: str, zone: str, instance_name: str, category: str) -> dict[str, Any]:
        planned_actions = [
            {
                "step": 1,
                "action": "set_tags",
                "target": instance_name,
                "details": f"Apply isolation tag '{config.isolation_tag}' in project {project_id}.",
            },
            {
                "step": 2,
                "action": "set_service_account",
                "target": instance_name,
                "details": "Detach the active service account from the VM.",
            },
            {
                "step": 3,
                "action": "set_metadata",
                "target": instance_name,
                "details": "Set block-project-ssh-keys=TRUE on instance metadata.",
            },
            {
                "step": 4,
                "action": "create_snapshot",
                "target": instance_name,
                "details": f"Create a forensic boot disk snapshot for category '{category}'.",
            },
            {
                "step": 5,
                "action": "stop",
                "target": instance_name,
                "details": f"Stop instance {instance_name} in zone {zone}.",
            },
        ]
        logger.info(f"Dry-run preview generated for GCE containment on {instance_name}")
        return {
            "mode": "dry_run",
            "playbook": "GCEContainment",
            "target_resource": instance_name,
            "project_id": project_id,
            "zone": zone,
            "planned_actions": planned_actions,
            "summary": "Preview only. No GCP remediation APIs were executed.",
        }

    @staticmethod
    def _isolate_instance(project_id: str, zone: str, instance_name: str) -> None:
        client = get_instances_client()
        instance = client.get(project=project_id, zone=zone, instance=instance_name)
        tags = instance.tags
        tags.items = [config.isolation_tag]
        op = client.set_tags(project=project_id, zone=zone, instance=instance_name, tags_resource=tags)
        op.result()
        logger.info(f"Applied isolation tag '{config.isolation_tag}' to {instance_name}")

    @staticmethod
    def _detach_service_account(project_id: str, zone: str, instance_name: str) -> None:
        client = get_instances_client()
        op = client.set_service_account(
            project=project_id,
            zone=zone,
            instance=instance_name,
            instances_set_service_account_request_resource=compute_v1.InstancesSetServiceAccountRequest(
                email="", scopes=[]
            ),
        )
        op.result()
        logger.info(f"Detached service account from {instance_name}")

    @staticmethod
    def _block_ssh_keys(project_id: str, zone: str, instance_name: str) -> None:
        client = get_instances_client()
        instance = client.get(project=project_id, zone=zone, instance=instance_name)
        metadata = instance.metadata
        items = list(metadata.items) if metadata.items else []

        found = False
        for item in items:
            if item.key == "block-project-ssh-keys":
                item.value = "TRUE"
                found = True
                break
        if not found:
            items.append(compute_v1.Items(key="block-project-ssh-keys", value="TRUE"))

        metadata.items = items
        op = client.set_metadata(project=project_id, zone=zone, instance=instance_name, metadata_resource=metadata)
        op.result()
        logger.info(f"Blocked project SSH keys for {instance_name}")

    @staticmethod
    def _take_snapshot(project_id: str, zone: str, instance_name: str, category: str) -> None:
        client = get_instances_client()
        instance = client.get(project=project_id, zone=zone, instance=instance_name)

        boot_disk_url = next((d.source for d in instance.disks if d.boot), None)
        if not boot_disk_url:
            logger.warning(f"No boot disk found for {instance_name}")
            return

        disk_name = boot_disk_url.split("/")[-1]
        ts = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
        snapshot_name = f"forensic-{instance_name}-{ts}"

        snapshot_resource = compute_v1.Snapshot(
            name=snapshot_name,
            description=f"SOAR forensic snapshot – threat: {category}",
            labels={
                "purpose": "incident-response",
                "threat": category.lower().replace(" ", "-"),
                "source-instance": instance_name,
            },
        )
        get_disks_client().create_snapshot(
            project=project_id, zone=zone, disk=disk_name, snapshot_resource=snapshot_resource
        )
        logger.info(f"Initiated snapshot {snapshot_name}")

    @staticmethod
    def _stop_instance(project_id: str, zone: str, instance_name: str) -> None:
        get_instances_client().stop(project=project_id, zone=zone, instance=instance_name)
        logger.info(f"Stopped instance {instance_name}")
