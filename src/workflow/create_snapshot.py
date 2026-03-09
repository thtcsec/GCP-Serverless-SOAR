"""
GCP SOAR Workflow — Create Snapshot
Creates forensic disk snapshots for all disks attached to a compromised instance.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

import functions_framework
from google.cloud import compute_v1

logger = logging.getLogger("gcp-soar.workflow.snapshot")


@functions_framework.http
def create_snapshot(request):
    """HTTP Cloud Function invoked by Cloud Workflows."""
    body = request.get_json(silent=True) or {}

    project_id = body.get("project_id", os.environ.get("PROJECT_ID", ""))
    zone = body.get("zone", "")
    instance_name = body.get("instance_name", "")
    category = body.get("category", "unknown")

    if not all([project_id, zone, instance_name]):
        return json.dumps({"error": "Missing required fields"}), 400

    instances_client = compute_v1.InstancesClient()
    disks_client = compute_v1.DisksClient()

    try:
        instance = instances_client.get(project=project_id, zone=zone, instance=instance_name)
        snapshots_created = []

        for disk in instance.disks:
            disk_name = disk.source.split("/")[-1]
            ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
            snap_name = f"forensic-{instance_name}-{disk_name}-{ts}"

            snap = compute_v1.Snapshot(
                name=snap_name,
                description=f"SOAR forensic snapshot – {category}",
                labels={
                    "purpose": "incident-response",
                    "threat": category.lower().replace(" ", "-"),
                    "source-instance": instance_name,
                    "device-name": disk.device_name or disk_name,
                    "created-by": "soar-workflow",
                },
            )
            disks_client.create_snapshot(project=project_id, zone=zone, disk=disk_name, snapshot_resource=snap)
            snapshots_created.append({"snapshot_name": snap_name, "disk": disk_name, "device": disk.device_name})

        result = {
            **body,
            "snapshot_status": "success",
            "snapshots": snapshots_created,
            "snapshot_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"Created {len(snapshots_created)} snapshots for {instance_name}")
        return json.dumps(result), 200, {"Content-Type": "application/json"}

    except Exception as exc:
        logger.error(f"Snapshot creation failed: {exc}")
        return json.dumps({**body, "snapshot_status": "failed", "error": str(exc)}), 500
