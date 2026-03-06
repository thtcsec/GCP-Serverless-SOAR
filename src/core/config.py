"""
GCP SOAR Configuration Management
Centralized configuration using environment variables with Pydantic validation.
"""

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SOARConfig:
    """Immutable SOAR configuration loaded from environment variables."""

    project_id: str = field(default_factory=lambda: os.environ.get("PROJECT_ID", ""))
    region: str = field(default_factory=lambda: os.environ.get("GCP_REGION", "us-central1"))
    zone: str = field(default_factory=lambda: os.environ.get("GCP_ZONE", "us-central1-a"))

    # Pub/Sub
    alert_topic: str = field(default_factory=lambda: os.environ.get("ALERT_TOPIC", ""))
    dlq_topic: str = field(default_factory=lambda: os.environ.get("DLQ_TOPIC", ""))

    # Thresholds
    exfiltration_threshold: int = field(
        default_factory=lambda: int(os.environ.get("EXFILTRATION_THRESHOLD", "10737418240"))
    )
    severity_threshold: float = field(
        default_factory=lambda: float(os.environ.get("SEVERITY_THRESHOLD", "7.0"))
    )

    # Networking
    isolation_tag: str = field(default_factory=lambda: os.environ.get("ISOLATION_TAG", "isolated-vm"))
    isolation_firewall_name: str = field(
        default_factory=lambda: os.environ.get("ISOLATION_FIREWALL_NAME", "soar-isolation-deny-all")
    )
    forensic_jump_host_ip: str = field(
        default_factory=lambda: os.environ.get("FORENSIC_JUMP_HOST_IP", "")
    )

    # Integrations
    slack_webhook_url: str = field(default_factory=lambda: os.environ.get("SLACK_WEBHOOK_URL", ""))

    # Workflow
    workflow_name: str = field(default_factory=lambda: os.environ.get("WORKFLOW_NAME", ""))
    approval_wait_time: int = field(
        default_factory=lambda: int(os.environ.get("APPROVAL_WAIT_TIME", "3600"))
    )

    # Logging
    log_level: str = field(default_factory=lambda: os.environ.get("LOG_LEVEL", "INFO"))

    # Forensics
    forensic_bucket: str = field(
        default_factory=lambda: os.environ.get("FORENSIC_BUCKET", "")
    )


# Singleton configuration instance
config = SOARConfig()
