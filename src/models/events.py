"""
GCP SOAR Event Models
Pydantic models for Security Command Center findings, Audit Log events, and Pub/Sub payloads.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingCategory(StrEnum):
    CRYPTOCURRENCY = "Cryptocurrency mining"
    BACKDOOR = "Backdoor"
    MALWARE = "Malware"
    BRUTE_FORCE = "Brute Force"
    DATA_EXFILTRATION = "Data Exfiltration"


# ---------------------------------------------------------------------------
# SCC Finding Models
# ---------------------------------------------------------------------------


class SCCResource(BaseModel):
    """Resource attached to an SCC finding."""

    model_config = ConfigDict(populate_by_name=True)

    name: str = ""
    project_display_name: str = Field("", alias="projectDisplayName")
    type: str = ""


class SCCFinding(BaseModel):
    """Represents a Security Command Center finding."""

    name: str = ""
    category: str = ""
    severity: str = Severity.MEDIUM
    resource_name: str = Field("", alias="resourceName")
    state: str = "ACTIVE"
    event_time: str | None = Field(None, alias="eventTime")
    create_time: str | None = Field(None, alias="createTime")
    source_properties: dict[str, Any] = Field(default_factory=dict, alias="sourceProperties")
    resource: SCCResource = Field(default_factory=lambda: SCCResource())  # type: ignore[call-arg]

    model_config = ConfigDict(populate_by_name=True)

    @property
    def is_compute_resource(self) -> bool:
        return "/instances/" in self.resource_name

    @property
    def is_high_severity(self) -> bool:
        return self.severity in (Severity.HIGH, Severity.CRITICAL)


# ---------------------------------------------------------------------------
# Cloud Audit Log Models
# ---------------------------------------------------------------------------


class AuthenticationInfo(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    principal_email: str = Field("", alias="principalEmail")


class AuditLogPayload(BaseModel):
    """Represents a Cloud Audit Log protoPayload."""

    method_name: str = Field("", alias="methodName")
    resource_name: str = Field("", alias="resourceName")
    service_name: str = Field("", alias="serviceName")
    authentication_info: AuthenticationInfo = Field(
        # mypy treats pydantic alias keywords as constructor args.
        default_factory=lambda: AuthenticationInfo(principalEmail=""),
        alias="authenticationInfo",
    )
    status: dict[str, Any] = Field(default_factory=dict)
    request: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)


class IAMAuditEvent(BaseModel):
    """IAM-specific audit event wrapper."""

    proto_payload: AuditLogPayload = Field(..., alias="protoPayload")
    timestamp: str | None = None
    resource: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)

    RISKY_METHODS: list[str] = [
        "CreateServiceAccountKey",
        "SetIamPolicy",
        "UndeleteServiceAccountKey",
        "CreateServiceAccount",
        "UploadServiceAccountKey",
    ]

    @property
    def is_risky(self) -> bool:
        return any(m in self.proto_payload.method_name for m in self.RISKY_METHODS)


class StorageAuditEvent(BaseModel):
    """Storage-specific audit event wrapper."""

    proto_payload: AuditLogPayload = Field(..., alias="protoPayload")
    timestamp: str | None = None

    model_config = ConfigDict(populate_by_name=True)

    READ_METHODS: list[str] = [
        "storage.objects.get",
        "storage.objects.list",
    ]

    @property
    def is_read_operation(self) -> bool:
        return any(m in self.proto_payload.method_name for m in self.READ_METHODS)


# ---------------------------------------------------------------------------
# Pub/Sub Message Model
# ---------------------------------------------------------------------------


class PubSubMessage(BaseModel):
    """Pub/Sub message envelope."""

    data: str = ""
    attributes: dict[str, str] = Field(default_factory=dict)
    message_id: str = Field("", alias="messageId")
    publish_time: str | None = Field(None, alias="publishTime")

    model_config = ConfigDict(populate_by_name=True)


# ---------------------------------------------------------------------------
# Cloud SQL Audit Event Models (Nhóm 1)
# ---------------------------------------------------------------------------

RISKY_CLOUDSQL_METHODS: list[str] = [
    "sql.instances.update",
    "sql.instances.delete",
    "sql.users.update",
    "sql.sslCerts.create",
    "sql.instances.export",
]


class CloudSQLAuditEvent(BaseModel):
    """Cloud SQL Admin API audit event."""

    proto_payload: AuditLogPayload = Field(..., alias="protoPayload")
    timestamp: str | None = None
    resource: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)

    @property
    def method_name(self) -> str:
        return self.proto_payload.method_name

    @property
    def service_name(self) -> str:
        return self.proto_payload.service_name

    @property
    def resource_name(self) -> str:
        return self.proto_payload.resource_name

    @property
    def caller_ip(self) -> str:
        return self.proto_payload.request.get("callerIp", "")

    @property
    def severity(self) -> str:
        return self.resource.get("labels", {}).get("severity", "MEDIUM")

    @property
    def is_risky(self) -> bool:
        return any(m in self.proto_payload.method_name for m in RISKY_CLOUDSQL_METHODS)


# ---------------------------------------------------------------------------
# GKE Audit Event Models (Nhóm 2)
# ---------------------------------------------------------------------------

RISKY_K8S_METHODS: list[str] = [
    "io.k8s.core.v1.pods.exec",
    "io.k8s.core.v1.pods.create",
    "io.k8s.batch.v1.jobs.create",
]


class GKEAuditEvent(BaseModel):
    """GKE Kubernetes audit log event."""

    proto_payload: AuditLogPayload = Field(..., alias="protoPayload")
    timestamp: str | None = None
    resource: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)

    @property
    def method_name(self) -> str:
        return self.proto_payload.method_name

    @property
    def is_risky(self) -> bool:
        method = self.proto_payload.method_name
        return "pods.exec" in method or "pods.attach" in method or "pods.create" in method or "jobs.create" in method


# ---------------------------------------------------------------------------
# Cloud Build Audit Event Models (Nhóm 3)
# ---------------------------------------------------------------------------

RISKY_CLOUDBUILD_METHODS: list[str] = [
    "google.devtools.cloudbuild.v1.CloudBuild.CreateBuild",
    "google.devtools.cloudbuild.v1.CloudBuild.UpdateBuildTrigger",
    "google.devtools.cloudbuild.v1.CloudBuild.CreateBuildTrigger",
    "google.devtools.cloudbuild.v1.CloudBuild.DeleteBuildTrigger",
]


class CloudBuildAuditEvent(BaseModel):
    """Cloud Build audit event."""

    proto_payload: AuditLogPayload = Field(..., alias="protoPayload")
    timestamp: str | None = None
    resource: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)

    @property
    def method_name(self) -> str:
        return self.proto_payload.method_name

    @property
    def service_name(self) -> str:
        return self.proto_payload.service_name

    @property
    def is_risky(self) -> bool:
        return any(m in self.proto_payload.method_name for m in RISKY_CLOUDBUILD_METHODS)
