"""
Enterprise SOAR GCP — Forensics Worker
Long-running Cloud Run container for forensic analysis of compromised instances.
Mounts disk snapshots, scans for indicators of compromise, and stores evidence.
"""

import hashlib
import json
import logging
import os
import re
import time
from datetime import UTC, datetime
from typing import Any

from flask import Flask, jsonify, request
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
FORENSICS_SCAN_ROOT = os.environ.get("FORENSICS_SCAN_ROOT", "/forensics")
FORENSICS_LOOKBACK_DAYS = int(os.environ.get("FORENSICS_LOOKBACK_DAYS", "7"))
FORENSICS_MAX_FILE_SIZE = int(os.environ.get("FORENSICS_MAX_FILE_SIZE", str(5 * 1024 * 1024)))
FORENSICS_LOG_MAX_LINES = int(os.environ.get("FORENSICS_LOG_MAX_LINES", "2000"))
KNOWN_MALICIOUS_HASHES = {
    h.strip().lower() for h in os.environ.get("FORENSICS_KNOWN_BAD_HASHES", "").split(",") if h.strip()
}
SUSPICIOUS_NAME_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"xmrig",
        r"kdevtmpfsi",
        r"kinsing",
        r"cryptominer",
        r"backdoor",
        r"webshell",
        r"\.ssh/authorized_keys(\.bak)?$",
    ]
]
SUSPICIOUS_COMMAND_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"nc\s+-e",
        r"bash\s+-i",
        r"curl\s+http",
        r"wget\s+http",
        r"/dev/tcp/",
        r"chmod\s+\+x",
        r"base64\s+-d",
        r"python\s+-c",
        r"powershell\s+-enc",
    ]
]
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(r"\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\b")


# ---------------------------------------------------------------------------
# Forensic Worker
# ---------------------------------------------------------------------------


class GCPForensicsWorker:
    """Performs forensic evidence collection and analysis."""

    def __init__(self) -> None:
        self.active_jobs: dict[str, dict] = {}
        self.job_counter = 0

    def analyze_instance(
        self,
        instance_name: str,
        zone: str,
        snapshot_names: list[str] | None = None,
        job_id: str | None = None,
    ) -> dict[str, Any]:
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
            job_id = f"forensic-{int(datetime.now(UTC).timestamp())}-{self.job_counter}"

        self.active_jobs[job_id] = {
            "instance_name": instance_name,
            "zone": zone,
            "status": "in_progress",
            "start_time": datetime.now(UTC).isoformat(),
            "steps": [],
        }

        try:
            # Step 1 — Instance metadata
            metadata = self._collect_metadata(instance_name, zone, job_id)

            # Step 2 — Snapshot analysis
            snapshot_info = self._analyze_snapshots(snapshot_names or [], job_id)

            # Step 3 — IOC check
            ioc_results = self._check_iocs(instance_name, metadata, snapshot_info, job_id)

            # Step 4 — Report
            threat_intel = self._build_threat_intel(snapshot_info, job_id)
            report = self._build_report(job_id, instance_name, zone, metadata, snapshot_info, ioc_results, threat_intel)

            # Step 5 — Persist evidence
            evidence_path = self._store_evidence(job_id, report)

            self.active_jobs[job_id]["status"] = "completed"
            self.active_jobs[job_id]["end_time"] = datetime.now(UTC).isoformat()

            return {
                "job_id": job_id,
                "instance_name": instance_name,
                "status": "completed",
                "evidence_path": evidence_path,
                "findings_summary": ioc_results.get("summary", {}),
                "threat_intel": threat_intel,
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

    def _collect_metadata(self, instance_name: str, zone: str, job_id: str) -> dict[str, Any]:
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

    def _resolve_snapshot_scan_path(self, snapshot_name: str) -> str:
        candidate = os.path.join(FORENSICS_SCAN_ROOT, snapshot_name)
        if os.path.isdir(candidate):
            return candidate
        if os.path.isdir(FORENSICS_SCAN_ROOT):
            return FORENSICS_SCAN_ROOT
        return ""

    def _analyze_filesystem(self, snapshot_path: str) -> dict[str, Any]:
        if not snapshot_path or not os.path.isdir(snapshot_path):
            return {
                "scan_mode": "filesystem",
                "scan_path": snapshot_path,
                "path_exists": False,
                "total_files": 0,
                "suspicious_files": 0,
                "hidden_files": 0,
                "recently_modified_files": 0,
                "file_types_found": {
                    "executables": 0,
                    "scripts": 0,
                    "configuration": 0,
                    "logs": 0,
                    "temp_files": 0,
                },
                "suspicious_file_locations": [],
            }
        now = time.time()
        extension_map = {
            "executables": {".exe", ".dll", ".so", ".bin"},
            "scripts": {".sh", ".py", ".pl", ".ps1", ".bat"},
            "configuration": {".conf", ".ini", ".yaml", ".yml", ".json", ".xml"},
            "logs": {".log"},
            "temp_files": {".tmp", ".swp", ".temp"},
        }
        result = {
            "scan_mode": "filesystem",
            "scan_path": snapshot_path,
            "path_exists": True,
            "total_files": 0,
            "suspicious_files": 0,
            "hidden_files": 0,
            "recently_modified_files": 0,
            "file_types_found": {k: 0 for k in extension_map},
            "suspicious_file_locations": [],
        }
        for root, _, files in os.walk(snapshot_path):
            for file_name in files:
                result["total_files"] += 1
                full_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(full_path, snapshot_path)
                lowered_name = file_name.lower()
                if lowered_name.startswith("."):
                    result["hidden_files"] += 1
                try:
                    stat_result = os.stat(full_path)
                    if now - stat_result.st_mtime <= FORENSICS_LOOKBACK_DAYS * 86400:
                        result["recently_modified_files"] += 1
                except OSError:
                    pass
                ext = os.path.splitext(lowered_name)[1]
                for bucket, ext_set in extension_map.items():
                    if ext in ext_set:
                        result["file_types_found"][bucket] += 1
                if any(pattern.search(rel_path) for pattern in SUSPICIOUS_NAME_PATTERNS):
                    result["suspicious_files"] += 1
                    result["suspicious_file_locations"].append(rel_path)
        return result

    def _scan_malware(self, snapshot_path: str) -> dict[str, Any]:
        start = time.time()
        scan_result = {
            "scan_mode": "hash-signature",
            "scan_path": snapshot_path,
            "path_exists": bool(snapshot_path and os.path.isdir(snapshot_path)),
            "scanned_files": 0,
            "skipped_files": 0,
            "malware_detected": 0,
            "threats_found": [],
            "scan_duration_seconds": 0,
        }
        if not snapshot_path or not os.path.isdir(snapshot_path):
            return scan_result
        for root, _, files in os.walk(snapshot_path):
            for file_name in files:
                full_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(full_path, snapshot_path)
                try:
                    if os.path.getsize(full_path) > FORENSICS_MAX_FILE_SIZE:
                        scan_result["skipped_files"] += 1
                        continue
                    with open(full_path, "rb") as f:
                        content = f.read()
                    scan_result["scanned_files"] += 1
                    file_hash = hashlib.sha256(content).hexdigest()
                    lowered_name = file_name.lower()
                    threat = None
                    if file_hash in KNOWN_MALICIOUS_HASHES:
                        threat = {
                            "file": rel_path,
                            "threat_type": "KnownMaliciousHash",
                            "severity": "critical",
                            "hash": file_hash,
                            "reason": "sha256 matched known malicious hash",
                        }
                    elif any(pattern.search(rel_path) for pattern in SUSPICIOUS_NAME_PATTERNS):
                        threat = {
                            "file": rel_path,
                            "threat_type": "SuspiciousFilename",
                            "severity": "high",
                            "hash": file_hash,
                            "reason": "filename matched suspicious pattern",
                        }
                    elif lowered_name.endswith((".sh", ".py", ".ps1", ".bat")):
                        text = content[:4096].decode(errors="ignore")
                        if any(pattern.search(text) for pattern in SUSPICIOUS_COMMAND_PATTERNS):
                            threat = {
                                "file": rel_path,
                                "threat_type": "SuspiciousScriptBehavior",
                                "severity": "high",
                                "hash": file_hash,
                                "reason": "script contains suspicious command patterns",
                            }
                    if threat:
                        scan_result["threats_found"].append(threat)
                except (OSError, UnicodeDecodeError):
                    scan_result["skipped_files"] += 1
        scan_result["malware_detected"] = len(scan_result["threats_found"])
        scan_result["scan_duration_seconds"] = int(time.time() - start)
        return scan_result

    def _analyze_activities(self, snapshot_path: str) -> list[dict[str, Any]]:
        if not snapshot_path or not os.path.isdir(snapshot_path):
            return []
        findings: list[dict[str, Any]] = []
        for root, _, files in os.walk(snapshot_path):
            for file_name in files:
                if not file_name.lower().endswith(".log"):
                    continue
                log_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(log_path, snapshot_path)
                evidence: list[str] = []
                detected_ips = set()
                detected_domains = set()
                try:
                    with open(log_path, encoding="utf-8", errors="ignore") as log_file:
                        for idx, line in enumerate(log_file):
                            if idx >= FORENSICS_LOG_MAX_LINES:
                                break
                            if any(pattern.search(line) for pattern in SUSPICIOUS_COMMAND_PATTERNS):
                                evidence.append(line.strip()[:220])
                            for ip in IP_PATTERN.findall(line):
                                if not ip.startswith(
                                    (
                                        "10.",
                                        "127.",
                                        "192.168.",
                                        "172.16.",
                                        "172.17.",
                                        "172.18.",
                                        "172.19.",
                                        "172.2",
                                        "172.30.",
                                        "172.31.",
                                    )
                                ):
                                    detected_ips.add(ip)
                            for domain in DOMAIN_PATTERN.findall(line):
                                lowered = domain.lower()
                                if "." in lowered and lowered not in {"localhost", "googleapis.com"}:
                                    detected_domains.add(lowered)
                except OSError:
                    continue
                if evidence or detected_ips or detected_domains:
                    findings.append(
                        {
                            "type": "suspicious_log_activity",
                            "description": f"Suspicious runtime activity found in {rel_path}",
                            "severity": "high" if evidence else "medium",
                            "evidence": evidence[:10],
                            "ips": sorted(detected_ips),
                            "domains": sorted(detected_domains),
                        }
                    )
        return findings

    def _calculate_snapshot_risk_score(self, analysis: dict[str, Any]) -> int:
        base_score = 0
        malware_count = len(analysis.get("malware_scan", {}).get("threats_found", []))
        base_score += malware_count * 25
        activity_count = len(analysis.get("suspicious_activities", []))
        base_score += activity_count * 15
        suspicious_files = analysis.get("file_system_analysis", {}).get("suspicious_files", 0)
        base_score += suspicious_files * 10
        return min(base_score, 100)

    def _analyze_snapshots(self, snapshot_names: list[str], job_id: str) -> list[dict]:
        """Return metadata about each forensic snapshot."""
        info: list[dict] = []
        client = compute_v1.SnapshotsClient()

        for name in snapshot_names:
            try:
                snap = client.get(project=PROJECT_ID, snapshot=name)
                info.append(
                    {
                        "name": snap.name,
                        "status": snap.status,
                        "disk_size_gb": snap.disk_size_gb,
                        "storage_bytes": snap.storage_bytes,
                        "created": snap.creation_timestamp,
                        "labels": dict(snap.labels) if snap.labels else {},
                        "scan_path": "",
                        "file_system_analysis": {},
                        "malware_scan": {},
                        "suspicious_activities": [],
                        "risk_score": 0,
                    }
                )
                snapshot_path = self._resolve_snapshot_scan_path(name)
                info[-1]["scan_path"] = snapshot_path
                info[-1]["file_system_analysis"] = self._analyze_filesystem(snapshot_path)
                info[-1]["malware_scan"] = self._scan_malware(snapshot_path)
                info[-1]["suspicious_activities"] = self._analyze_activities(snapshot_path)
                info[-1]["risk_score"] = self._calculate_snapshot_risk_score(info[-1])
            except Exception as exc:
                info.append({"name": name, "error": str(exc)})

        self._log_step(job_id, "analyze_snapshots", "success", f"{len(info)} snapshots")
        return info

    def _check_iocs(self, instance_name: str, metadata: dict, snapshots: list[dict], job_id: str) -> dict[str, Any]:
        """
        Heuristic IOC checks based on available metadata.
        A real implementation would analyse disk images with YARA / ClamAV.
        """
        findings: list[str] = []
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

        for snapshot in snapshots:
            malware_findings = snapshot.get("malware_scan", {}).get("threats_found", [])
            for threat in malware_findings:
                findings.append(f"Malware signature in snapshot {snapshot.get('name')}: {threat.get('threat_type')}")
                severity_counts["high"] += 1
            for activity in snapshot.get("suspicious_activities", []):
                findings.append(
                    f"Suspicious log activity in snapshot {snapshot.get('name')}: {activity.get('description')}"
                )
                severity_counts["medium"] += 1

        self._log_step(job_id, "check_iocs", "success", f"{len(findings)} findings")
        return {"findings": findings, "summary": severity_counts}

    def _build_threat_intel(self, snapshots: list[dict], job_id: str) -> dict[str, Any]:
        indicators: list[dict[str, str]] = []
        seen = set()
        for snapshot in snapshots:
            for threat in snapshot.get("malware_scan", {}).get("threats_found", []):
                hash_value = threat.get("hash")
                if hash_value and ("file_hash", hash_value) not in seen:
                    seen.add(("file_hash", hash_value))
                    indicators.append(
                        {
                            "type": "file_hash",
                            "value": hash_value,
                            "reputation": "malicious" if hash_value in KNOWN_MALICIOUS_HASHES else "suspicious",
                            "confidence": "high" if hash_value in KNOWN_MALICIOUS_HASHES else "medium",
                        }
                    )
            for activity in snapshot.get("suspicious_activities", []):
                for ip in activity.get("ips", []):
                    if ("ip_address", ip) not in seen:
                        seen.add(("ip_address", ip))
                        indicators.append(
                            {
                                "type": "ip_address",
                                "value": ip,
                                "reputation": "suspicious",
                                "confidence": "medium",
                            }
                        )
                for domain in activity.get("domains", []):
                    if ("domain", domain) not in seen:
                        seen.add(("domain", domain))
                        indicators.append(
                            {
                                "type": "domain",
                                "value": domain,
                                "reputation": "suspicious",
                                "confidence": "medium",
                            }
                        )
        self._log_step(job_id, "threat_intel", "success", f"{len(indicators)} indicators")
        return {"indicators": indicators}

    def _build_report(self, job_id, instance_name, zone, metadata, snapshots, iocs, threat_intel) -> dict:
        return {
            "job_id": job_id,
            "generated_at": datetime.now(UTC).isoformat(),
            "instance": instance_name,
            "zone": zone,
            "metadata": metadata,
            "snapshots": snapshots,
            "ioc_findings": iocs.get("findings", []),
            "severity_summary": iocs.get("summary", {}),
            "threat_intelligence": threat_intel,
        }

    def _store_evidence(self, job_id: str, report: dict) -> str:
        """Upload forensic report to the evidence GCS bucket."""
        if not FORENSIC_BUCKET:
            logger.warning("FORENSIC_BUCKET not set — skipping evidence upload")
            return ""

        client = storage.Client()
        ts = datetime.now(UTC).strftime("%Y%m%d")
        blob_path = f"forensics/{report['instance']}/{ts}/{job_id}.json"

        bucket = client.bucket(FORENSIC_BUCKET)
        blob = bucket.blob(blob_path)
        blob.upload_from_string(json.dumps(report, default=str), content_type="application/json")

        path = f"gs://{FORENSIC_BUCKET}/{blob_path}"
        logger.info(f"Evidence stored at {path}")
        return path

    # ------------------------------------------------------------------ #

    def _log_step(self, job_id: str, step: str, status: str, detail: str = "") -> None:
        entry = {"step": step, "status": status, "detail": detail, "timestamp": datetime.now(UTC).isoformat()}
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
