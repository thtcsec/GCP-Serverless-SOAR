"""
GCP SOAR Engine — Single Production Entry Point

All security events MUST flow through handle_event().
Cloud Function / Pub/Sub adapters live in entrypoint.py.
"""

from __future__ import annotations

import logging
from typing import Any

from .core.pipeline import IncidentPipeline
from .playbooks.api_gateway_abuse import APIGatewayAbusePlaybook
from .playbooks.cloudsql_compromise import CloudSQLCompromisePlaybook
from .playbooks.gce_containment import GCEContainment
from .playbooks.gke_pod_isolation import GKEPodIsolationPlaybook
from .playbooks.ransomware_response import RansomwareResponsePlaybook
from .playbooks.registry import PlaybookRegistry
from .playbooks.sa_compromise import SACompromise
from .playbooks.storage_exfiltration import StorageExfiltration

logger = logging.getLogger("gcp-soar.handlers")

registry = PlaybookRegistry()
registry.register(GCEContainment())
registry.register(SACompromise())
registry.register(StorageExfiltration())
registry.register(APIGatewayAbusePlaybook())
registry.register(RansomwareResponsePlaybook())
registry.register(GKEPodIsolationPlaybook())
registry.register(CloudSQLCompromisePlaybook())

pipeline = IncidentPipeline(registry=registry)


def handle_event(event_data: dict[str, Any]) -> dict[str, Any]:
    """
    Canonical SOAR entry point.

    Pipeline: Event → Normalize → Correlate → Score → Decision → Playbook → Audit
    """
    logger.info("Processing event through unified incident pipeline")
    return pipeline.process(event_data)
