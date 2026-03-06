"""
GCP SOAR — Pub/Sub Message Processor
Processes messages from a Pub/Sub subscription and routes them to the
appropriate Cloud Workflow execution.  Mirrors the AWS queue_processor.py pattern.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any, Dict, List

import functions_framework
from google.cloud import workflows_v1
from google.cloud.workflows import executions_v1

logger = logging.getLogger("gcp-soar.queue_processor")
logger.setLevel(logging.INFO)

WORKFLOW_NAME = os.environ.get("WORKFLOW_NAME", "")
DLQ_TOPIC = os.environ.get("DLQ_TOPIC", "")
PROJECT_ID = os.environ.get("PROJECT_ID", "")
REGION = os.environ.get("GCP_REGION", "us-central1")

# Workflow routing map — maps service names to workflow IDs
WORKFLOW_MAP: Dict[str, str] = {
    "securitycenter.googleapis.com": os.environ.get("GUARDDUTY_WORKFLOW", "soar-incident-response"),
    "iam.googleapis.com": os.environ.get("IAM_WORKFLOW", "soar-sa-response"),
    "storage.googleapis.com": os.environ.get("STORAGE_WORKFLOW", "soar-storage-response"),
}


@functions_framework.cloud_event
def queue_processor(cloud_event):
    """Entry point — triggered by a Pub/Sub push subscription."""
    logger.info(f"Processing message {cloud_event['id']}")

    try:
        raw = base64.b64decode(cloud_event.data["message"]["data"]).decode("utf-8")
        message = json.loads(raw)
    except Exception as exc:
        logger.error(f"Failed to decode Pub/Sub message: {exc}")
        return

    source = _detect_source(message)
    workflow_id = WORKFLOW_MAP.get(source, WORKFLOW_NAME)

    if not workflow_id:
        logger.warning(f"No workflow configured for source '{source}' — sending to DLQ")
        _send_to_dlq(message)
        return

    try:
        execution = _start_workflow(workflow_id, message)
        logger.info(f"Started workflow execution: {execution.name}")
    except Exception as exc:
        logger.error(f"Failed to start workflow {workflow_id}: {exc}")
        _send_to_dlq(message)


def _detect_source(message: Dict[str, Any]) -> str:
    """Infer the event source from message contents."""
    if "finding" in message or "category" in message:
        return "securitycenter.googleapis.com"
    proto = message.get("protoPayload", {})
    return proto.get("serviceName", "unknown")


def _start_workflow(workflow_id: str, payload: Dict[str, Any]):
    """Execute a Cloud Workflow with the given payload."""
    client = executions_v1.ExecutionsClient()
    parent = f"projects/{PROJECT_ID}/locations/{REGION}/workflows/{workflow_id}"

    execution = executions_v1.Execution(argument=json.dumps(payload))
    return client.create_execution(parent=parent, execution=execution)


def _send_to_dlq(message: Dict[str, Any]) -> None:
    """Forward a failed message to the Dead Letter Topic."""
    if not DLQ_TOPIC or not PROJECT_ID:
        logger.error("DLQ_TOPIC or PROJECT_ID not set — dropping message")
        return

    from google.cloud import pubsub_v1

    publisher = pubsub_v1.PublisherClient()
    topic_path = publisher.topic_path(PROJECT_ID, DLQ_TOPIC)
    publisher.publish(topic_path, json.dumps(message).encode("utf-8"))
    logger.info("Message forwarded to DLQ")
