"""
GCP SOAR Workflow — Terminate Instance
Stops a compromised GCE instance and generates the final incident report.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime

import functions_framework
from google.cloud import compute_v1

logger = logging.getLogger("gcp-soar.workflow.terminate")


@functions_framework.http
def terminate_instance(request):
    """HTTP Cloud Function invoked by Cloud Workflows after human approval."""
    body = request.get_json(silent=True) or {}

    project_id = body.get("project_id", os.environ.get("PROJECT_ID", ""))
    zone = body.get("zone", "")
    instance_name = body.get("instance_name", "")

    if not all([project_id, zone, instance_name]):
        return json.dumps({"error": "Missing required fields"}), 400

    client = compute_v1.InstancesClient()

    try:
        instance = client.get(project=project_id, zone=zone, instance=instance_name)
        state = instance.status.lower()

        if state in ("terminated", "stopped"):
            logger.info(f"Instance {instance_name} is already {state}")
        else:
            client.stop(project=project_id, zone=zone, instance=instance_name)
            logger.info(f"Stopped instance {instance_name}")

    except Exception as exc:
        error_str = str(exc)
        if "notFound" in error_str:
            logger.warning(f"Instance {instance_name} not found — may already be deleted")
        else:
            logger.error(f"Terminate failed: {exc}")
            return json.dumps({**body, "terminate_status": "failed", "error": error_str}), 500

    # Build incident report
    report = {
        "incident_id": body.get("finding_id", "N/A"),
        "instance_name": instance_name,
        "project_id": project_id,
        "zone": zone,
        "category": body.get("category", "unknown"),
        "severity": body.get("severity_classification", body.get("severity", "")),
        "priority": body.get("priority", ""),
        "response_actions": {
            "isolation": body.get("isolation_status", ""),
            "snapshots": body.get("snapshots", []),
            "termination": "success",
        },
        "timeline": {
            "detected_at": body.get("event_time", ""),
            "isolated_at": body.get("isolation_timestamp", ""),
            "snapshot_at": body.get("snapshot_timestamp", ""),
            "terminated_at": datetime.now(UTC).isoformat(),
        },
    }

    result = {**body, "terminate_status": "success", "incident_report": report}
    logger.info(f"Incident report generated for {instance_name}")
    return json.dumps(result), 200, {"Content-Type": "application/json"}
