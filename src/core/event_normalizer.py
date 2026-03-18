"""
GCP SOAR — Unified Event Normalizer
Converts native GCP security events into a standardized UnifiedIncident schema
for cross-platform analysis and incident correlation.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("gcp-soar.normalizer")


# ---------------------------------------------------------------------------
# Unified Incident Schema
# ---------------------------------------------------------------------------


class UnifiedIncident(BaseModel):
    """Platform-agnostic incident representation."""

    incident_id: str = ""
    platform: str = "gcp"
    timestamp: str = ""
    severity: str = "MEDIUM"
    source_ip: str = ""
    actor: str = ""
    action: str = ""
    resource: str = ""
    resource_type: str = ""
    risk_score: float = 0.0
    decision: str = "IGNORE"
    intel_summary: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    raw_event_type: str = ""
    correlation_keys: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------


class EventNormalizer:
    """Normalize native GCP security events into UnifiedIncident objects."""

    @staticmethod
    def _generate_id(event_type: str, resource: str, timestamp: str) -> str:
        raw = f"{event_type}:{resource}:{timestamp}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @classmethod
    def from_scc_finding(cls, event_data: dict[str, Any]) -> UnifiedIncident:
        """Normalize a Security Command Center finding into a UnifiedIncident."""
        resource_name = event_data.get("resourceName", "")
        severity = event_data.get("severity", "MEDIUM")
        category = event_data.get("category", "")
        state = event_data.get("state", "ACTIVE")
        source_props = event_data.get("sourceProperties", {})

        # Extract resource type from resourceName
        resource_type = "unknown"
        if "/instances/" in resource_name:
            resource_type = "compute_instance"
        elif "/buckets/" in resource_name:
            resource_type = "storage_bucket"
        elif "/serviceAccounts/" in resource_name:
            resource_type = "service_account"

        source_ip = source_props.get("sourceIp", "")
        actor = source_props.get("principalEmail", "")
        ts = event_data.get("eventTime", datetime.now(UTC).isoformat())
        incident_id = cls._generate_id("scc", resource_name, ts)

        correlation_keys = [k for k in [source_ip, actor, resource_name] if k]

        return UnifiedIncident(
            incident_id=incident_id,
            platform="gcp",
            timestamp=ts,
            severity=severity,
            source_ip=source_ip,
            actor=actor,
            action=category,
            resource=resource_name,
            resource_type=resource_type,
            tags=["scc", category, state],
            raw_event_type="SCCFinding",
            correlation_keys=correlation_keys,
        )

    @classmethod
    def from_iam_audit(cls, event_data: dict[str, Any]) -> UnifiedIncident:
        """Normalize an IAM Audit Log event into a UnifiedIncident."""
        proto = event_data.get("protoPayload", {})
        auth_info = proto.get("authenticationInfo", {})
        request = proto.get("request", {})

        actor = auth_info.get("principalEmail", "unknown")
        source_ip = request.get("callerIp", "")
        action = proto.get("methodName", "")
        resource_name = proto.get("resourceName", "")
        ts = event_data.get("timestamp", datetime.now(UTC).isoformat())

        incident_id = cls._generate_id("iam_audit", resource_name, ts)
        correlation_keys = [k for k in [source_ip, actor, resource_name] if k]

        return UnifiedIncident(
            incident_id=incident_id,
            platform="gcp",
            timestamp=ts,
            severity="HIGH",
            source_ip=source_ip,
            actor=actor,
            action=action,
            resource=resource_name,
            resource_type="service_account",
            tags=["audit_log", "iam", action],
            raw_event_type="IAMAuditEvent",
            correlation_keys=correlation_keys,
        )

    @classmethod
    def from_storage_audit(cls, event_data: dict[str, Any]) -> UnifiedIncident:
        """Normalize a Storage Audit Log event into a UnifiedIncident."""
        proto = event_data.get("protoPayload", {})
        auth_info = proto.get("authenticationInfo", {})

        actor = auth_info.get("principalEmail", "unknown")
        action = proto.get("methodName", "")
        resource_name = proto.get("resourceName", "")
        ts = event_data.get("timestamp", datetime.now(UTC).isoformat())

        # Extract bucket name from resource
        bucket = ""
        if "/buckets/" in resource_name:
            parts = resource_name.split("/buckets/")
            if len(parts) > 1:
                bucket = parts[1].split("/")[0]

        incident_id = cls._generate_id("storage_audit", resource_name, ts)
        correlation_keys = [k for k in [actor, bucket] if k]

        return UnifiedIncident(
            incident_id=incident_id,
            platform="gcp",
            timestamp=ts,
            severity="HIGH",
            source_ip="",
            actor=actor,
            action=action,
            resource=bucket or resource_name,
            resource_type="storage_bucket",
            tags=["audit_log", "storage", action],
            raw_event_type="StorageAuditEvent",
            correlation_keys=correlation_keys,
        )

    @classmethod
    def normalize(cls, event_data: dict[str, Any]) -> UnifiedIncident | None:
        """Auto-detect event type and normalize accordingly."""
        # SCC Finding detection
        if "category" in event_data and "resourceName" in event_data:
            return cls.from_scc_finding(event_data)

        proto = event_data.get("protoPayload", {})
        service = proto.get("serviceName", "")

        if service == "iam.googleapis.com":
            return cls.from_iam_audit(event_data)
        elif service == "storage.googleapis.com":
            return cls.from_storage_audit(event_data)

        logger.warning(f"Unknown event type, cannot normalize: {event_data.keys()}")
        return None
