"""
DEPRECATED MODULE — use entrypoint.py for Cloud Function adapters.

Business logic entry point: handlers.handle_event()
"""

from .entrypoint import queue_processor, sa_compromise_responder, soar_responder, storage_exfil_responder

__all__ = ["soar_responder", "sa_compromise_responder", "storage_exfil_responder", "queue_processor"]
