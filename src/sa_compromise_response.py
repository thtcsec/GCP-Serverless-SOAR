"""DEPRECATED — redirects to unified entrypoint. Use handlers.handle_event() for all logic."""

from .entrypoint import sa_compromise_responder

__all__ = ["sa_compromise_responder"]
