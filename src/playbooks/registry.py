"""
GCP SOAR Playbook Registry
Central registry that dispatches events to the correct playbook.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .base import Playbook

logger = logging.getLogger("gcp-soar.registry")


class PlaybookRegistry:
    """Thread-safe registry for SOAR playbooks."""

    def __init__(self) -> None:
        self._playbooks: List[Playbook] = []

    def register(self, playbook: Playbook) -> None:
        self._playbooks.append(playbook)
        logger.info(f"Registered playbook: {playbook.__class__.__name__}")

    def dispatch(self, event_data: Dict[str, Any]) -> Optional[bool]:
        """Find the first playbook that can handle the event and execute it."""
        for playbook in self._playbooks:
            if playbook.can_handle(event_data):
                logger.info(f"Dispatching to playbook: {playbook.__class__.__name__}")
                return playbook.execute(event_data)

        logger.warning("No playbook could handle the event")
        return None
