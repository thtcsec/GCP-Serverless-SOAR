"""DEPRECATED — redirects to unified entrypoint. Use handlers.handle_event() for all logic."""

from .entrypoint import queue_processor

__all__ = ["queue_processor"]
