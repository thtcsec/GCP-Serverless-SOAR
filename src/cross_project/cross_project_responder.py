"""
GCP SOAR — Cross-Project Responder
Performs incident-response actions in remote GCP projects using
service-account impersonation (the GCP equivalent of AWS STS AssumeRole).
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import UTC, datetime
from typing import Any

from google.auth import default as auth_default
from google.auth import impersonated_credentials
from google.cloud import compute_v1, storage  # type: ignore[attr-defined]

logger = logging.getLogger("gcp-soar.cross_project")

DEFAULT_ENVIRONMENTS = ("dev", "staging", "prod")
PROJECT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,61}[a-z0-9]$")
SERVICE_ACCOUNT_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.iam\.gserviceaccount\.com$")

SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/compute",
]


class CrossProjectResponder:
    """Execute SOAR actions in a remote GCP project via SA impersonation."""

    def __init__(self, environment: str = "dev", strict: bool | None = None) -> None:
        self.environment = environment
        self.strict = (
            strict if strict is not None else os.environ.get("CROSS_PROJECT_STRICT_CONFIG", "false").lower() == "true"
        )
        self.account_map = self._load_account_map()
        self._validate_account_map()
        self.account = self.account_map.get(environment, {})
        self._validate_current_environment()
        self._credentials = None

    def _load_account_map(self) -> dict[str, dict[str, str]]:
        raw = os.environ.get("CROSS_PROJECT_ACCOUNT_MAP", "").strip()
        account_map: dict[str, dict[str, str]] = {
            env: {"project_id": "", "target_sa": ""} for env in DEFAULT_ENVIRONMENTS
        }
        if raw:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("CROSS_PROJECT_ACCOUNT_MAP must be a JSON object")
            for env, cfg in parsed.items():
                if isinstance(cfg, dict):
                    account_map[env] = {
                        "project_id": str(cfg.get("project_id", "")).strip(),
                        "target_sa": str(cfg.get("target_sa", "")).strip(),
                    }
        for env in DEFAULT_ENVIRONMENTS:
            env_prefix = env.upper()
            project_id = os.environ.get(f"{env_prefix}_TARGET_PROJECT_ID", "").strip()
            target_sa = os.environ.get(f"{env_prefix}_TARGET_SERVICE_ACCOUNT", "").strip()
            if project_id:
                account_map.setdefault(env, {})["project_id"] = project_id
            if target_sa:
                account_map.setdefault(env, {})["target_sa"] = target_sa
        return account_map

    def _validate_account_map(self) -> None:
        issues: list[str] = []
        for env, cfg in self.account_map.items():
            project_id = str(cfg.get("project_id", "")).strip()
            target_sa = str(cfg.get("target_sa", "")).strip()
            if not project_id and not target_sa:
                continue
            if not project_id:
                issues.append(f"{env}: missing project_id")
            elif not PROJECT_ID_PATTERN.match(project_id):
                issues.append(f"{env}: invalid project_id format")
            if not target_sa:
                issues.append(f"{env}: missing target_sa")
            elif not SERVICE_ACCOUNT_PATTERN.match(target_sa):
                issues.append(f"{env}: invalid target_sa format")
        if issues:
            message = "Cross-project account mapping validation failed: " + "; ".join(issues)
            if self.strict:
                raise ValueError(message)
            logger.warning(message)

    def _validate_current_environment(self) -> None:
        project_id = str(self.account.get("project_id", "")).strip()
        target_sa = str(self.account.get("target_sa", "")).strip()
        if project_id and target_sa:
            return
        message = f"Environment '{self.environment}' is not fully configured for cross-project response"
        if self.strict:
            raise ValueError(message)
        logger.warning(message)

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

    def isolate_instance(self, zone: str, instance_name: str, isolation_tag: str = "isolated-vm") -> dict[str, Any]:
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

    def create_snapshot(self, zone: str, instance_name: str, category: str = "unknown") -> dict[str, Any]:
        """Create a forensic disk snapshot in the target project."""
        project_id = self.account["project_id"]
        client = self._compute_client()

        instance = client.get(project=project_id, zone=zone, instance=instance_name)
        boot_disk_url = next((d.source for d in instance.disks if d.boot), None)

        if not boot_disk_url:
            return {"error": "No boot disk found"}

        disk_name = boot_disk_url.split("/")[-1]
        ts = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
        snap_name = f"forensic-xp-{instance_name}-{ts}"

        snap = compute_v1.Snapshot(
            name=snap_name,
            description=f"Cross-project forensic snapshot – {category}",
            labels={
                "purpose": "incident-response",
                "source-project": project_id,
                "source-instance": instance_name,
            },
        )

        disks_client = compute_v1.DisksClient(credentials=self._get_credentials())
        disks_client.create_snapshot(project=project_id, zone=zone, disk=disk_name, snapshot_resource=snap)

        logger.info(f"[{self.environment}] Snapshot {snap_name} initiated")
        return {"snapshot": snap_name, "disk": disk_name}

    def terminate_instance(self, zone: str, instance_name: str) -> dict[str, Any]:
        project_id = self.account["project_id"]
        client = self._compute_client()
        client.stop(project=project_id, zone=zone, instance=instance_name)
        logger.info(f"[{self.environment}] Stopped {instance_name}")
        return {"instance": instance_name, "status": "stopped"}

    def revoke_sa_credentials(self, sa_email: str) -> dict[str, Any]:
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

    def secure_storage_bucket(self, bucket_name: str) -> dict[str, Any]:
        """Enable versioning, uniform access, and public-access prevention on a bucket."""
        client = self._storage_client()
        bucket = client.bucket(bucket_name)

        bucket.versioning_enabled = True
        bucket.iam_configuration.uniform_bucket_level_access_enabled = True
        bucket.iam_configuration.public_access_prevention = "enforced"
        bucket.patch()

        logger.info(f"[{self.environment}] Secured bucket {bucket_name}")
        return {
            "bucket": bucket_name,
            "versioning": True,
            "uniform_access": True,
            "public_access_prevention": True,
        }

    def get_project_security_posture(self) -> dict[str, Any]:
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
            "assessed_at": datetime.now(UTC).isoformat(),
        }
