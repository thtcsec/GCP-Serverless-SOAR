"""
GCP SOAR Engine — Event Dispatcher (handlers.py)
Initialises playbook registry and routes incoming events to the correct playbook.
Mirrors the AWS handlers.py pattern.
"""

from __future__ import annotations

import logging
from typing import Any

from .playbooks.api_gateway_abuse import APIGatewayAbusePlaybook
from .playbooks.gce_containment import GCEContainment
from .playbooks.registry import PlaybookRegistry
from .playbooks.sa_compromise import SACompromise
from .playbooks.storage_exfiltration import StorageExfiltration

logger = logging.getLogger("gcp-soar.handlers")

# ---------------------------------------------------------------------------
# Registry initialisation (runs once at cold-start)
# ---------------------------------------------------------------------------

registry = PlaybookRegistry()
registry.register(GCEContainment())
registry.register(SACompromise())
registry.register(StorageExfiltration())
registry.register(APIGatewayAbusePlaybook())


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def handle_event(event_data: dict[str, Any]) -> dict[str, Any]:
    """
    Dispatch *event_data* to the first playbook that can handle it.

    Returns a dict suitable for an HTTP / Cloud Function response.
    """
    logger.info("Dispatching event to playbook registry")

    result = registry.dispatch(event_data)

    if result is None:
        logger.warning("Event was not handled by any playbook")
        return {"statusCode": 200, "body": "No matching playbook"}

    if result:
        return {"statusCode": 200, "body": "Playbook executed successfully"}

    return {"statusCode": 500, "body": "Playbook execution failed"}
