"""DEPRECATED — redirects to unified entrypoint. Use handlers.handle_event() for all logic."""

from .entrypoint import storage_exfil_responder

__all__ = ["storage_exfil_responder"]
