"""
GCP SOAR — Slack Notifier
Sends rich incident notifications to Slack via webhook (stored in Secret Manager).
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("gcp-soar.integrations.slack")

SEVERITY_COLORS = {
    "CRITICAL": "#FF0000",
    "HIGH": "#FF6600",
    "MEDIUM": "#FFCC00",
    "LOW": "#36A64F",
}


def _get_webhook_url() -> str:
    """Retrieve webhook URL from environment or Secret Manager."""
    url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if url:
        return url

    # Fallback: fetch from Secret Manager
    try:
        from google.cloud import secretmanager  # type: ignore[attr-defined]

        client = secretmanager.SecretManagerServiceClient()
        project_id = os.environ.get("PROJECT_ID", "")
        secret_name = f"projects/{project_id}/secrets/slack-webhook-url/versions/latest"
        response = client.access_secret_version(name=secret_name)
        return response.payload.data.decode("utf-8")
    except Exception as exc:
        logger.error(f"Cannot retrieve Slack webhook: {exc}")
        return ""


def _post(webhook_url: str, payload: Dict) -> bool:
    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req)  # nosec B310
        return True
    except Exception as exc:
        logger.error(f"Slack POST failed: {exc}")
        return False


def send_incident_alert(
    project_id: str,
    zone: str,
    instance_name: str,
    category: str,
    severity: str,
    finding_id: str,
) -> bool:
    """Send a colour-coded incident alert."""
    url = _get_webhook_url()
    if not url:
        logger.error("SLACK_WEBHOOK_URL not configured")
        return False

    colour = SEVERITY_COLORS.get(severity, "#808080")
    payload = {
        "attachments": [
            {
                "color": colour,
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": "🚨 GCP Security Incident"},
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Project:*\n{project_id}"},
                            {"type": "mrkdwn", "text": f"*Zone:*\n{zone}"},
                            {"type": "mrkdwn", "text": f"*Instance:*\n`{instance_name}`"},
                            {"type": "mrkdwn", "text": f"*Threat:*\n{category}"},
                            {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                            {"type": "mrkdwn", "text": f"*Finding:*\n`{finding_id}`"},
                        ],
                    },
                ],
            }
        ]
    }
    return _post(url, payload)


def send_isolation_notification(instance_name: str, zone: str, success: bool) -> bool:
    url = _get_webhook_url()
    if not url:
        return False

    status = "✅ Isolated" if success else "❌ Isolation Failed"
    payload = {
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*VM Isolation — {status}*\nInstance: `{instance_name}` ({zone})"}},
        ]
    }
    return _post(url, payload)


def send_forensics_notification(instance_name: str, snapshot_name: str) -> bool:
    url = _get_webhook_url()
    if not url:
        return False

    payload = {
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"🔬 *Forensic Snapshot Created*\nInstance: `{instance_name}`\nSnapshot: `{snapshot_name}`"}},
        ]
    }
    return _post(url, payload)


def send_approval_request(instance_name: str, action: str, approval_url: str = "") -> bool:
    url = _get_webhook_url()
    if not url:
        return False

    payload = {
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "⚠️ Human Approval Required"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Action:* {action}\n*Instance:* `{instance_name}`"}},
        ]
    }
    if approval_url:
        payload["blocks"].append(
            {"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text", "text": "Approve"}, "url": approval_url}]}  # type: ignore[list-item]
        )
    return _post(url, payload)
