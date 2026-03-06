"""
GCP SOAR Playbook Base
Defines the protocol every playbook must implement.
"""

from __future__ import annotations

from typing import Any, Dict, Protocol, runtime_checkable


@runtime_checkable
class Playbook(Protocol):
    """Interface that all SOAR playbooks must satisfy."""

    def can_handle(self, event_data: Dict[str, Any]) -> bool:
        """Return True when this playbook knows how to process *event_data*."""
        ...

    def execute(self, event_data: Dict[str, Any]) -> bool:
        """Run the full response flow. Return True on success."""
        ...
