"""
GCP SOAR Structured Logging
JSON-formatted logger compatible with Cloud Logging / Cloud Operations Suite.
"""

import json
import logging
import sys
from datetime import UTC, datetime


class StructuredFormatter(logging.Formatter):
    """JSON formatter that produces Cloud Logging-compatible entries."""

    def format(self, record):
        log_entry = {
            "severity": record.levelname,
            "message": record.getMessage(),
            "timestamp": datetime.now(UTC).isoformat(),
            "logger": record.name,
            "module": record.module,
        }

        # Merge extra json_fields when provided
        json_fields = getattr(record, "json_fields", None)
        if json_fields and isinstance(json_fields, dict):
            log_entry.update(json_fields)

        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


def get_logger(name: str = "soar") -> logging.Logger:
    """Return a logger configured with structured JSON output."""
    _logger = logging.getLogger(name)

    if not _logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(StructuredFormatter())
        _logger.addHandler(handler)
        _logger.setLevel(logging.INFO)
        _logger.propagate = False

    return _logger


# Default logger instance
logger = get_logger("gcp-soar")
