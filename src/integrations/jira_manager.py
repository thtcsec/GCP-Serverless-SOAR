"""
GCP SOAR — Jira Ticket Manager
Creates and manages Jira tickets for security incidents.
Credentials stored in GCP Secret Manager.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from base64 import b64encode
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("gcp-soar.integrations.jira")

PRIORITY_MAP = {
    "CRITICAL": "Highest",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}


class JiraManager:
    """Lightweight Jira REST API client (no external library required)."""

    def __init__(self) -> None:
        self.base_url = ""
        self.auth_header = ""
        self._load_config()

    def _load_config(self) -> None:
        """Load Jira credentials from env vars or Secret Manager."""
        self.base_url = os.environ.get("JIRA_URL", "")
        username = os.environ.get("JIRA_USERNAME", "")
        token = os.environ.get("JIRA_API_TOKEN", "")

        if not self.base_url:
            self.base_url, username, token = self._from_secret_manager()

        if username and token:
            creds = b64encode(f"{username}:{token}".encode()).decode()
            self.auth_header = f"Basic {creds}"

    @staticmethod
    def _from_secret_manager():
        try:
            from google.cloud import secretmanager

            client = secretmanager.SecretManagerServiceClient()
            project_id = os.environ.get("PROJECT_ID", "")

            def _secret(name: str) -> str:
                resp = client.access_secret_version(
                    name=f"projects/{project_id}/secrets/{name}/versions/latest"
                )
                return resp.payload.data.decode("utf-8")

            return _secret("jira-url"), _secret("jira-username"), _secret("jira-api-token")
        except Exception as exc:
            logger.error(f"Cannot load Jira secrets: {exc}")
            return "", "", ""

    # ------------------------------------------------------------------ #

    def create_incident_ticket(
        self,
        project_key: str,
        summary: str,
        severity: str,
        description: str,
        labels: list[str] | None = None,
    ) -> Optional[str]:
        """Create a Jira issue and return the issue key."""
        if not self.base_url or not self.auth_header:
            logger.error("Jira not configured")
            return None

        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "issuetype": {"name": "Bug"},
                "priority": {"name": PRIORITY_MAP.get(severity, "Medium")},
                "description": description,
                "labels": labels or ["security-incident", "soar-auto"],
            }
        }

        data = self._request("POST", "/rest/api/2/issue", payload)
        if data:
            key = data.get("key", "")
            logger.info(f"Created Jira ticket: {key}")
            return key
        return None

    def update_ticket_status(self, issue_key: str, transition_name: str) -> bool:
        transitions = self._request("GET", f"/rest/api/2/issue/{issue_key}/transitions")
        if not transitions:
            return False

        tid = next(
            (t["id"] for t in transitions.get("transitions", []) if t["name"].lower() == transition_name.lower()),
            None,
        )
        if tid is None:
            logger.warning(f"Transition '{transition_name}' not found for {issue_key}")
            return False

        return self._request("POST", f"/rest/api/2/issue/{issue_key}/transitions", {"transition": {"id": tid}}) is not None

    def add_comment(self, issue_key: str, body: str) -> bool:
        return self._request("POST", f"/rest/api/2/issue/{issue_key}/comment", {"body": body}) is not None

    # ------------------------------------------------------------------ #

    def _request(self, method: str, path: str, body: Optional[Dict] = None):
        url = f"{self.base_url.rstrip('/')}{path}"
        data = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", self.auth_header)
        try:
            with urllib.request.urlopen(req) as resp:  # nosec B310
                if resp.status in (200, 201):
                    return json.loads(resp.read())
                return {}
        except Exception as exc:
            logger.error(f"Jira API {method} {path} failed: {exc}")
            return None
