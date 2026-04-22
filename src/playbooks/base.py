"""
GCP SOAR Playbook Base
Defines the protocol every playbook must implement.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Playbook(Protocol):
    """Interface that all SOAR playbooks must satisfy."""

    def can_handle(self, event_data: dict[str, Any]) -> bool:
        """Return True when this playbook knows how to process *event_data*."""
        ...

    def execute(self, event_data: dict[str, Any]) -> bool | dict[str, Any]:
        """Run the full response flow. Return True on success."""
        ...
