"""
GCP SOAR — Cloud Function / Eventarc Transport Adapters

Thin wrappers that decode transport envelopes and delegate to handlers.handle_event().
These are NOT business entry points — all logic lives in the unified pipeline.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sys
import types

import functions_framework

# Dynamic 'src' package alias for Gen2 deploys that import `from src.xxx`
src_dir = os.path.dirname(__file__)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)
if "src" not in sys.modules:
    src_module = types.ModuleType("src")
    src_module.__path__ = [src_dir]
    sys.modules["src"] = src_module

from .handlers import handle_event, registry  # noqa: E402
from .integrations.scoring import ScoringEngine  # noqa: E402

logger = logging.getLogger("gcp-soar.entrypoint")


@functions_framework.http
def health(request):
    """HTTP liveness / status probe (deploy with entry_point=health if needed)."""
    payload = {
        "status": "ok",
        "service": "soar-incident-responder",
        "pipeline": "IncidentPipeline",
        "playbooks_registered": [p.__class__.__name__ for p in registry._playbooks],
        "scoring": {
            "ignore_threshold": ScoringEngine.IGNORE_THRESHOLD,
            "auto_isolate_threshold": ScoringEngine.AUTO_ISOLATE_THRESHOLD,
            "formula": "(vt_malicious*2) + (abuse_score*0.5) + (severity*3) + anomaly_boost",
        },
        "project": os.environ.get("GCLOUD_PROJECT") or os.environ.get("GCP_PROJECT") or "",
        "region": os.environ.get("FUNCTION_REGION") or os.environ.get("GOOGLE_CLOUD_REGION") or "",
    }
    return (json.dumps(payload), 200, {"Content-Type": "application/json"})


def _decode_pubsub_cloud_event(cloud_event) -> dict:
    if not cloud_event.data or "message" not in cloud_event.data:
        raise ValueError("Invalid Pub/Sub cloud event format")
    message_data = base64.b64decode(cloud_event.data["message"]["data"]).decode("utf-8")
    return json.loads(message_data)


def _decode_audit_cloud_event(cloud_event) -> dict:
    """Audit log events arrive as CloudEvents with the log entry in data."""
    data = cloud_event.data
    if isinstance(data, dict) and "protoPayload" in data:
        return data
    if isinstance(data, bytes):
        data = json.loads(data.decode("utf-8"))
    if isinstance(data, str):
        data = json.loads(data)
    return data


@functions_framework.cloud_event
def soar_responder(cloud_event):
    """Pub/Sub adapter (SCC / security findings)."""
    try:
        event_data = _decode_pubsub_cloud_event(cloud_event)
        handle_event(event_data)
    except Exception as exc:
        logger.error("soar_responder failed: %s", exc)


@functions_framework.cloud_event
def sa_compromise_responder(cloud_event):
    """Eventarc adapter (IAM audit logs)."""
    try:
        event_data = _decode_audit_cloud_event(cloud_event)
        handle_event(event_data)
    except Exception as exc:
        logger.error("sa_compromise_responder failed: %s", exc)


@functions_framework.cloud_event
def storage_exfil_responder(cloud_event):
    """Eventarc adapter (Storage audit logs)."""
    try:
        event_data = _decode_audit_cloud_event(cloud_event)
        handle_event(event_data)
    except Exception as exc:
        logger.error("storage_exfil_responder failed: %s", exc)


@functions_framework.cloud_event
def queue_processor(cloud_event):
    """Pub/Sub queue adapter — routes to unified pipeline (replaces workflow fan-out)."""
    try:
        event_data = _decode_pubsub_cloud_event(cloud_event)
        handle_event(event_data)
    except Exception as exc:
        logger.error("queue_processor failed: %s", exc)
