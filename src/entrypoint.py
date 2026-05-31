"""
GCP SOAR — Cloud Function / Eventarc Transport Adapters

Thin wrappers that decode transport envelopes and delegate to handlers.handle_event().
These are NOT business entry points — all logic lives in the unified pipeline.
"""

from __future__ import annotations

import base64
import json
import logging

import functions_framework

from .handlers import handle_event

logger = logging.getLogger("gcp-soar.entrypoint")


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
        logger.error(f"soar_responder failed: {exc}")


@functions_framework.cloud_event
def sa_compromise_responder(cloud_event):
    """Eventarc adapter (IAM audit logs)."""
    try:
        event_data = _decode_audit_cloud_event(cloud_event)
        handle_event(event_data)
    except Exception as exc:
        logger.error(f"sa_compromise_responder failed: {exc}")


@functions_framework.cloud_event
def storage_exfil_responder(cloud_event):
    """Eventarc adapter (Storage audit logs)."""
    try:
        event_data = _decode_audit_cloud_event(cloud_event)
        handle_event(event_data)
    except Exception as exc:
        logger.error(f"storage_exfil_responder failed: {exc}")


@functions_framework.cloud_event
def queue_processor(cloud_event):
    """Pub/Sub queue adapter — routes to unified pipeline (replaces workflow fan-out)."""
    try:
        event_data = _decode_pubsub_cloud_event(cloud_event)
        handle_event(event_data)
    except Exception as exc:
        logger.error(f"queue_processor failed: {exc}")
