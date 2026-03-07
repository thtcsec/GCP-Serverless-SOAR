"""
GCP SOAR — Cross-Project Responder
Performs incident-response actions in remote GCP projects using
service-account impersonation (the GCP equivalent of AWS STS AssumeRole).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from google.auth import impersonated_credentials, default as auth_default
from google.cloud import compute_v1, storage  # type: ignore[attr-defined]

logger = logging.getLogger("gcp-soar.cross_project")

# Map of environment → target SA for impersonation
ACCOUNT_MAP: Dict[str, Dict[str, str]] = {
    "dev": {
        "project_id": "",           # Set via env or config
        "target_sa": "",            # e.g. soar-responder@dev-project.iam.gserviceaccount.com
    },
    "staging": {
        "project_id": "",
        "target_sa": "",
    },
    "prod": {
        "project_id": "",
        "target_sa": "",
    },
}

SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/compute",
]


class CrossProjectResponder:
    """Execute SOAR actions in a remote GCP project via SA impersonation."""

    def __init__(self, environment: str = "dev") -> None:
        self.environment = environment
        self.account = ACCOUNT_MAP.get(environment, {})
        self._credentials = None

    # ------------------------------------------------------------------ #
    # Credential management
    # ------------------------------------------------------------------ #

    def _get_credentials(self):
        if self._credentials is not None:
            return self._credentials

        source_credentials, _ = auth_default()
        target_sa = self.account.get("target_sa", "")
        if not target_sa:
            raise ValueError(f"No target SA configured for environment '{self.environment}'")

        self._credentials = impersonated_credentials.Credentials(
            source_credentials=source_credentials,
            target_principal=target_sa,
            target_scopes=SCOPES,
        )
        logger.info(f"Impersonating {target_sa} for {self.environment}")
        return self._credentials

    def _compute_client(self) -> compute_v1.InstancesClient:
        return compute_v1.InstancesClient(credentials=self._get_credentials())

    def _storage_client(self) -> storage.Client:
        return storage.Client(credentials=self._get_credentials(), project=self.account["project_id"])

    # ------------------------------------------------------------------ #
    # Response actions
    # ------------------------------------------------------------------ #

    def isolate_instance(self, zone: str, instance_name: str, isolation_tag: str = "isolated-vm") -> Dict[str, Any]:
        """Isolate a VM in the target project by overwriting network tags."""
        project_id = self.account["project_id"]
        client = self._compute_client()

        instance = client.get(project=project_id, zone=zone, instance=instance_name)
        original_tags = list(instance.tags.items) if instance.tags.items else []

        tags = instance.tags
        tags.items = [isolation_tag]
        op = client.set_tags(project=project_id, zone=zone, instance=instance_name, tags_resource=tags)
        op.result()

        logger.info(f"[{self.environment}] Isolated {instance_name}")
        return {"instance": instance_name, "original_tags": original_tags, "status": "isolated"}

    def create_snapshot(self, zone: str, instance_name: str, category: str = "unknown") -> Dict[str, Any]:
        """Create a forensic disk snapshot in the target project."""
        project_id = self.account["project_id"]
        client = self._compute_client()

        instance = client.get(project=project_id, zone=zone, instance=instance_name)
        boot_disk_url = next((d.source for d in instance.disks if d.boot), None)

        if not boot_disk_url:
            return {"error": "No boot disk found"}

        disk_name = boot_disk_url.split("/")[-1]
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        snap_name = f"forensic-xp-{instance_name}-{ts}"

        snap = compute_v1.Snapshot(
            name=snap_name,
            description=f"Cross-project forensic snapshot – {category}",
            labels={"purpose": "incident-response", "source-project": project_id, "source-instance": instance_name},
        )

        disks_client = compute_v1.DisksClient(credentials=self._get_credentials())
        disks_client.create_snapshot(project=project_id, zone=zone, disk=disk_name, snapshot_resource=snap)

        logger.info(f"[{self.environment}] Snapshot {snap_name} initiated")
        return {"snapshot": snap_name, "disk": disk_name}

    def terminate_instance(self, zone: str, instance_name: str) -> Dict[str, Any]:
        project_id = self.account["project_id"]
        client = self._compute_client()
        client.stop(project=project_id, zone=zone, instance=instance_name)
        logger.info(f"[{self.environment}] Stopped {instance_name}")
        return {"instance": instance_name, "status": "stopped"}

    def revoke_sa_credentials(self, sa_email: str) -> Dict[str, Any]:
        """Disable all user-managed keys for a service account in the target project."""
        from google.cloud import iam_admin_v1

        creds = self._get_credentials()
        client = iam_admin_v1.IAMClient(credentials=creds)
        project_id = self.account["project_id"]

        sa_resource = f"projects/{project_id}/serviceAccounts/{sa_email}"
        keys = client.list_service_account_keys(name=sa_resource)

        disabled: list[str] = []
        for key in keys.keys:
            if key.key_type == iam_admin_v1.ServiceAccountKey.KeyType.USER_MANAGED:
                client.disable_service_account_key(name=key.name)
                disabled.append(key.name)

        logger.info(f"[{self.environment}] Disabled {len(disabled)} keys for {sa_email}")
        return {"service_account": sa_email, "disabled_keys": len(disabled)}

    def secure_storage_bucket(self, bucket_name: str) -> Dict[str, Any]:
        """Enable versioning, uniform access, and public-access prevention on a bucket."""
        client = self._storage_client()
        bucket = client.bucket(bucket_name)

        bucket.versioning_enabled = True
        bucket.iam_configuration.uniform_bucket_level_access_enabled = True
        bucket.iam_configuration.public_access_prevention = "enforced"
        bucket.patch()

        logger.info(f"[{self.environment}] Secured bucket {bucket_name}")
        return {"bucket": bucket_name, "versioning": True, "uniform_access": True, "public_access_prevention": True}

    def get_project_security_posture(self) -> Dict[str, Any]:
        """Summarise basic security metrics for the target project."""
        project_id = self.account["project_id"]
        compute = self._compute_client()

        # Count instances by status
        instances = compute.aggregated_list(project=project_id)
        running = stopped = isolated = 0
        for _, scoped in instances:
            for inst in getattr(scoped, "instances", []):
                if "isolated" in (inst.tags.items or []):
                    isolated += 1
                elif inst.status == "RUNNING":
                    running += 1
                else:
                    stopped += 1

        return {
            "project_id": project_id,
            "environment": self.environment,
            "running_instances": running,
            "stopped_instances": stopped,
            "isolated_instances": isolated,
            "assessed_at": datetime.now(timezone.utc).isoformat(),
        }
