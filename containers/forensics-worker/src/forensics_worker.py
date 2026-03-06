"""
Enterprise SOAR GCP — Forensics Worker
Long-running Cloud Run container for forensic analysis of compromised instances.
Mounts disk snapshots, scans for indicators of compromise, and stores evidence.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from flask import Flask, request, jsonify
from google.cloud import compute_v1, storage

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO")),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

PROJECT_ID = os.environ.get("PROJECT_ID", "")
FORENSIC_BUCKET = os.environ.get("FORENSIC_BUCKET", "")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "production")


# ---------------------------------------------------------------------------
# Forensic Worker
# ---------------------------------------------------------------------------

class GCPForensicsWorker:
    """Performs forensic evidence collection and analysis."""

    def __init__(self) -> None:
        self.active_jobs: Dict[str, Dict] = {}
        self.job_counter = 0

    def analyze_instance(self, instance_name: str, zone: str, snapshot_names: List[str] | None = None, job_id: str | None = None) -> Dict[str, Any]:
        """
        Run forensic analysis on a compromised instance.

        Steps:
            1. Collect instance metadata
            2. Analyse disk snapshots
            3. Check for known IOCs
            4. Generate forensic report
            5. Store evidence in GCS
        """
        if not job_id:
            self.job_counter += 1
            job_id = f"forensic-{int(datetime.now(timezone.utc).timestamp())}-{self.job_counter}"

        self.active_jobs[job_id] = {
            "instance_name": instance_name,
            "zone": zone,
            "status": "in_progress",
            "start_time": datetime.now(timezone.utc).isoformat(),
            "steps": [],
        }

        try:
            # Step 1 — Instance metadata
            metadata = self._collect_metadata(instance_name, zone, job_id)

            # Step 2 — Snapshot analysis
            snapshot_info = self._analyze_snapshots(snapshot_names or [], job_id)

            # Step 3 — IOC check
            ioc_results = self._check_iocs(instance_name, metadata, job_id)

            # Step 4 — Report
            report = self._build_report(job_id, instance_name, zone, metadata, snapshot_info, ioc_results)

            # Step 5 — Persist evidence
            evidence_path = self._store_evidence(job_id, report)

            self.active_jobs[job_id]["status"] = "completed"
            self.active_jobs[job_id]["end_time"] = datetime.now(timezone.utc).isoformat()

            return {
                "job_id": job_id,
                "instance_name": instance_name,
                "status": "completed",
                "evidence_path": evidence_path,
                "findings_summary": ioc_results.get("summary", {}),
                "report": report,
            }

        except Exception as exc:
            logger.error(f"Forensic job {job_id} failed: {exc}")
            self.active_jobs[job_id]["status"] = "failed"
            self.active_jobs[job_id]["error"] = str(exc)
            return {"job_id": job_id, "status": "failed", "error": str(exc)}

    # ------------------------------------------------------------------ #
    # Internal steps
    # ------------------------------------------------------------------ #

    def _collect_metadata(self, instance_name: str, zone: str, job_id: str) -> Dict[str, Any]:
        """Gather instance metadata for forensic context."""
        try:
            client = compute_v1.InstancesClient()
            instance = client.get(project=PROJECT_ID, zone=zone, instance=instance_name)

            meta = {
                "name": instance.name,
                "machine_type": instance.machine_type.split("/")[-1],
                "status": instance.status,
                "zone": zone,
                "creation_timestamp": instance.creation_timestamp,
                "network_interfaces": [
                    {
                        "network": ni.network.split("/")[-1] if ni.network else "",
                        "internal_ip": ni.network_i_p or "",
                        "external_ip": (ni.access_configs[0].nat_i_p if ni.access_configs else ""),
                    }
                    for ni in instance.network_interfaces
                ],
                "disks": [
                    {"name": d.source.split("/")[-1] if d.source else "", "boot": d.boot, "size_gb": d.disk_size_gb}
                    for d in instance.disks
                ],
                "tags": list(instance.tags.items) if instance.tags and instance.tags.items else [],
                "service_accounts": [sa.email for sa in instance.service_accounts] if instance.service_accounts else [],
                "labels": dict(instance.labels) if instance.labels else {},
            }
            self._log_step(job_id, "collect_metadata", "success")
            return meta
        except Exception as exc:
            self._log_step(job_id, "collect_metadata", "failed", str(exc))
            return {}

    def _analyze_snapshots(self, snapshot_names: List[str], job_id: str) -> List[Dict]:
        """Return metadata about each forensic snapshot."""
        info: List[Dict] = []
        client = compute_v1.SnapshotsClient()

        for name in snapshot_names:
            try:
                snap = client.get(project=PROJECT_ID, snapshot=name)
                info.append({
                    "name": snap.name,
                    "status": snap.status,
                    "disk_size_gb": snap.disk_size_gb,
                    "storage_bytes": snap.storage_bytes,
                    "created": snap.creation_timestamp,
                    "labels": dict(snap.labels) if snap.labels else {},
                })
            except Exception as exc:
                info.append({"name": name, "error": str(exc)})

        self._log_step(job_id, "analyze_snapshots", "success", f"{len(info)} snapshots")
        return info

    def _check_iocs(self, instance_name: str, metadata: Dict, job_id: str) -> Dict[str, Any]:
        """
        Heuristic IOC checks based on available metadata.
        A real implementation would analyse disk images with YARA / ClamAV.
        """
        findings: List[str] = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        # Check for suspicious tags
        tags = metadata.get("tags", [])
        if "isolated-vm" in tags:
            findings.append("Instance was isolated by SOAR")
            severity_counts["high"] += 1

        # Check for no service account (indicator of detachment)
        if not metadata.get("service_accounts"):
            findings.append("No service account attached (may have been detached)")
            severity_counts["medium"] += 1

        # Check for external IP exposure
        for ni in metadata.get("network_interfaces", []):
            if ni.get("external_ip"):
                findings.append(f"External IP detected: {ni['external_ip']}")
                severity_counts["medium"] += 1

        self._log_step(job_id, "check_iocs", "success", f"{len(findings)} findings")
        return {"findings": findings, "summary": severity_counts}

    def _build_report(self, job_id, instance_name, zone, metadata, snapshots, iocs) -> Dict:
        return {
            "job_id": job_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "instance": instance_name,
            "zone": zone,
            "metadata": metadata,
            "snapshots": snapshots,
            "ioc_findings": iocs.get("findings", []),
            "severity_summary": iocs.get("summary", {}),
        }

    def _store_evidence(self, job_id: str, report: Dict) -> str:
        """Upload forensic report to the evidence GCS bucket."""
        if not FORENSIC_BUCKET:
            logger.warning("FORENSIC_BUCKET not set — skipping evidence upload")
            return ""

        client = storage.Client()
        ts = datetime.now(timezone.utc).strftime("%Y%m%d")
        blob_path = f"forensics/{report['instance']}/{ts}/{job_id}.json"

        bucket = client.bucket(FORENSIC_BUCKET)
        blob = bucket.blob(blob_path)
        blob.upload_from_string(json.dumps(report, default=str), content_type="application/json")

        path = f"gs://{FORENSIC_BUCKET}/{blob_path}"
        logger.info(f"Evidence stored at {path}")
        return path

    # ------------------------------------------------------------------ #

    def _log_step(self, job_id: str, step: str, status: str, detail: str = "") -> None:
        entry = {"step": step, "status": status, "detail": detail, "timestamp": datetime.now(timezone.utc).isoformat()}
        if job_id in self.active_jobs:
            self.active_jobs[job_id]["steps"].append(entry)
        logger.info(f"[{job_id}] {step}: {status} {detail}")


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

worker = GCPForensicsWorker()


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "forensics-worker", "environment": ENVIRONMENT})


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    instance_name = data.get("instance_name", "")
    zone = data.get("zone", "")
    snapshots = data.get("snapshot_names", [])

    if not instance_name or not zone:
        return jsonify({"error": "instance_name and zone are required"}), 400

    result = worker.analyze_instance(instance_name, zone, snapshots)
    status_code = 200 if result.get("status") == "completed" else 500
    return jsonify(result), status_code


@app.route("/jobs", methods=["GET"])
def list_jobs():
    return jsonify({"jobs": worker.active_jobs})


@app.route("/jobs/<job_id>", methods=["GET"])
def get_job(job_id: str):
    job = worker.active_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
