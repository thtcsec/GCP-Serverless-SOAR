"""
Slack Interactivity Request URL handler (Approve / Reject buttons).

Point Slack App Interactivity Request URL at this Cloud Function HTTP endpoint.
Requires SLACK_SIGNING_SECRET in production.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from urllib.parse import parse_qs

import functions_framework

from ..handlers import pipeline

logger = logging.getLogger(__name__)


def _verify_slack_signature(headers: dict[str, str], body: bytes) -> bool:
    secret = os.environ.get("SLACK_SIGNING_SECRET", "")
    if not secret:
        logger.warning("SLACK_SIGNING_SECRET unset — skipping signature verification (lab only)")
        return True

    ts = headers.get("X-Slack-Request-Timestamp") or headers.get("x-slack-request-timestamp") or ""
    sig = headers.get("X-Slack-Signature") or headers.get("x-slack-signature") or ""
    if not ts or not sig:
        return False
    if abs(time.time() - int(ts)) > 60 * 5:
        return False
    basestring = f"v0:{ts}:{body.decode('utf-8')}".encode()
    digest = "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, sig)


@functions_framework.http
def slack_interactions(request):
    """GCP HTTP Cloud Function entry for Slack interactive payloads."""
    body_bytes = request.get_data() or b""
    headers = {k: v for k, v in request.headers.items()}
    if not _verify_slack_signature(headers, body_bytes):
        return ("invalid signature", 401)

    content_type = (request.headers.get("Content-Type") or "").lower()
    if "application/x-www-form-urlencoded" in content_type:
        form = parse_qs(body_bytes.decode("utf-8"))
        payload_list = form.get("payload") or []
        if not payload_list:
            return ("missing payload", 400)
        payload = json.loads(payload_list[0])
    else:
        payload = request.get_json(silent=True) or {}

    if payload.get("type") == "url_verification":
        return (payload.get("challenge", ""), 200)

    actions = payload.get("actions") or []
    if not actions:
        return ("", 200)

    action = actions[0]
    action_id = action.get("action_id", "")
    incident_id = action.get("value", "")
    user = (payload.get("user") or {}).get("username") or (payload.get("user") or {}).get("id") or "slack"

    if action_id == "soar_approve":
        result = pipeline.resume_approval(incident_id=incident_id, action="approve", actor=f"slack:{user}")
        text = f":white_check_mark: Approved `{incident_id}` by {user}"
    elif action_id == "soar_reject":
        result = pipeline.resume_approval(incident_id=incident_id, action="reject", actor=f"slack:{user}")
        text = f":no_entry: Rejected `{incident_id}` by {user}"
    else:
        return ("", 200)

    logger.info("Slack interaction handled: %s", result)
    return (json.dumps({"replace_original": True, "text": text}), 200, {"Content-Type": "application/json"})
