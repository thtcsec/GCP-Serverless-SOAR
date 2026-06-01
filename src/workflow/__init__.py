"""
DEPRECATED — Cloud Workflow HTTP stubs.

Business logic has moved to handlers.handle_event() and playbooks/.
These endpoints remain for backward-compatible Terraform wiring only.
"""

from ._legacy import create_snapshot, detect_severity, isolate_instance, terminate_instance

__all__ = ["create_snapshot", "detect_severity", "isolate_instance", "terminate_instance"]
