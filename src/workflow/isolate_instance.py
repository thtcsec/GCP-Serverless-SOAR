"""
GCP SOAR Workflow — Isolate Instance
Network-isolates a GCE instance by replacing its tags with the isolation tag.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

import functions_framework
from google.cloud import compute_v1

logger = logging.getLogger("gcp-soar.workflow.isolate")

ISOLATION_TAG = os.environ.get("ISOLATION_TAG", "isolated-vm")


@functions_framework.http
def isolate_instance(request):
    """HTTP Cloud Function invoked by Cloud Workflows."""
    body = request.get_json(silent=True) or {}

    project_id = body.get("project_id", os.environ.get("PROJECT_ID", ""))
    zone = body.get("zone", "")
    instance_name = body.get("instance_name", "")

    if not all([project_id, zone, instance_name]):
        return json.dumps({"error": "Missing project_id, zone, or instance_name"}), 400

    client = compute_v1.InstancesClient()

    try:
        instance = client.get(project=project_id, zone=zone, instance=instance_name)
        original_tags = list(instance.tags.items) if instance.tags.items else []

        tags = instance.tags
        tags.items = [ISOLATION_TAG]
        op = client.set_tags(project=project_id, zone=zone, instance=instance_name, tags_resource=tags)
        op.result()

        result = {
            **body,
            "isolation_status": "success",
            "original_tags": original_tags,
            "applied_tag": ISOLATION_TAG,
            "isolation_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"Isolated {instance_name}")
        return json.dumps(result), 200, {"Content-Type": "application/json"}

    except Exception as exc:
        logger.error(f"Isolation failed for {instance_name}: {exc}")
        return json.dumps({**body, "isolation_status": "failed", "error": str(exc)}), 500
