"""
GCP SOAR — Secret Rotation Manager
Manages automatic rotation of API keys used by the SOAR platform,
including Threat Intelligence keys (VirusTotal, AbuseIPDB)
and integration secrets (Slack webhooks, Jira tokens).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("gcp-soar.secret_rotation")


class SecretRotationManager:
    """
    Manages API key rotation via GCP Secret Manager.
    """

    # Maximum age in days before a key should be rotated
    DEFAULT_MAX_AGE_DAYS = 90

    def __init__(self, secret_client: Any = None) -> None:
        self._client = secret_client

    def check_key_age(self, project_id: str, secret_id: str) -> dict[str, Any]:
        """Check the age of the latest version of a secret."""
        if not self._client:
            return {"error": "Secret Manager client not configured"}

        try:
            name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
            _ = self._client.access_secret_version(request={"name": name})

            # Get secret metadata for create time
            secret_name = f"projects/{project_id}/secrets/{secret_id}"
            secret = self._client.get_secret(request={"name": secret_name})

            create_time = secret.create_time
            age_days = (datetime.now(UTC) - create_time.replace(tzinfo=UTC)).days if create_time else -1

            return {
                "secret_id": secret_id,
                "project_id": project_id,
                "age_days": age_days,
                "needs_rotation": age_days > self.DEFAULT_MAX_AGE_DAYS,
            }
        except Exception as e:
            logger.error(f"Failed to check key age for {secret_id}: {e}")
            return {"secret_id": secret_id, "error": str(e)}

    def rotate_secret(self, project_id: str, secret_id: str, new_value: str) -> bool:
        """Add a new version of the secret (effectively rotating it)."""
        if not self._client:
            return False

        try:
            parent = f"projects/{project_id}/secrets/{secret_id}"
            self._client.add_secret_version(
                request={
                    "parent": parent,
                    "payload": {"data": new_value.encode("UTF-8")},
                }
            )
            logger.info(f"Rotated secret: {secret_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to rotate {secret_id}: {e}")
            return False

    def get_rotation_report(self, project_id: str, secret_ids: list[str]) -> dict[str, Any]:
        """Generate a rotation status report for all monitored secrets."""
        results: list[dict[str, Any]] = []
        needs_rotation_count = 0

        for sid in secret_ids:
            status = self.check_key_age(project_id, sid)
            results.append(status)
            if status.get("needs_rotation", False):
                needs_rotation_count += 1

        return {
            "total_secrets": len(secret_ids),
            "needs_rotation": needs_rotation_count,
            "max_age_policy_days": self.DEFAULT_MAX_AGE_DAYS,
            "secrets": results,
        }

    @staticmethod
    def get_monitored_secrets() -> list[str]:
        """Return the list of SOAR secret IDs that should be monitored."""
        return [
            "virustotal-api-key",
            "abuseipdb-api-key",
            "slack-webhook-url",
            "jira-api-token",
            "siem-api-key",
        ]
