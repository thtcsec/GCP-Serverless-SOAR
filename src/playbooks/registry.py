"""
GCP SOAR Playbook Registry
Central registry that dispatches UnifiedIncident objects to the correct playbook.
"""

from __future__ import annotations

import logging
from typing import Any

from ..core.event_normalizer import EventNormalizer, UnifiedIncident
from .base import Playbook

logger = logging.getLogger("gcp-soar.registry")


class PlaybookRegistry:
    """Thread-safe registry for SOAR playbooks."""

    def __init__(self) -> None:
        self._playbooks: list[Playbook] = []

    def register(self, playbook: Playbook) -> None:
        self._playbooks.append(playbook)
        logger.info(f"Registered playbook: {playbook.__class__.__name__}")

    def dispatch(self, incident: UnifiedIncident | dict[str, Any]) -> bool | dict[str, Any] | None:
        """Find the first playbook that can handle the incident and execute it."""
        unified = EventNormalizer.ensure(incident)
        for playbook in self._playbooks:
            if playbook.can_handle(unified):
                logger.info(f"Dispatching to playbook: {playbook.__class__.__name__}")
                return playbook.execute(unified)

        logger.warning(f"No playbook could handle incident {unified.incident_id}")
        return None

    @property
    def playbooks(self) -> list[Playbook]:
        return list(self._playbooks)
