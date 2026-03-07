"""
GCP SOAR Event Models
Pydantic models for Security Command Center findings, Audit Log events, and Pub/Sub payloads.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingCategory(str, Enum):
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
    event_time: Optional[str] = Field(None, alias="eventTime")
    create_time: Optional[str] = Field(None, alias="createTime")
    source_properties: Dict[str, Any] = Field(default_factory=dict, alias="sourceProperties")
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
        default_factory=lambda: AuthenticationInfo(), alias="authenticationInfo"  # type: ignore[call-arg]
    )
    status: Dict[str, Any] = Field(default_factory=dict)
    request: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)


class IAMAuditEvent(BaseModel):
    """IAM-specific audit event wrapper."""
    proto_payload: AuditLogPayload = Field(..., alias="protoPayload")
    timestamp: Optional[str] = None
    resource: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)

    RISKY_METHODS: List[str] = [
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
    timestamp: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)

    READ_METHODS: List[str] = [
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
    attributes: Dict[str, str] = Field(default_factory=dict)
    message_id: str = Field("", alias="messageId")
    publish_time: Optional[str] = Field(None, alias="publishTime")

    model_config = ConfigDict(populate_by_name=True)
