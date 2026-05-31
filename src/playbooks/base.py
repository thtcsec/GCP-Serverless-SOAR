"""
GCP SOAR Playbook Base
Defines the protocol every playbook must implement.
Playbooks are the ONLY execution unit — no containment logic elsewhere.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ..core.event_normalizer import UnifiedIncident


@runtime_checkable
class Playbook(Protocol):
    """Interface that all SOAR playbooks must satisfy."""

    def can_handle(self, incident: UnifiedIncident) -> bool:
        """Return True when this playbook knows how to process *incident*."""
        ...

    def execute(self, incident: UnifiedIncident) -> bool | dict[str, Any]:
        """Run the full response flow. Return True on success."""
        ...
