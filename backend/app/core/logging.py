"""
HashLens Structured Logging Module
Provides clean, structured, non-leaking logging for forensic and security events.
"""

import logging
import sys
from datetime import datetime, timezone
import json
from typing import Any, Dict


class SafeStructuredFormatter(logging.Formatter):
    """
    JSON / structured formatter ensuring no raw sensitive payload or stack trace
    is dumped unsafely into stdout.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Attach correlation / extra metadata if provided
        if hasattr(record, "request_id"):
            log_entry["request_id"] = record.request_id
        if hasattr(record, "client_ip"):
            log_entry["client_ip"] = record.client_ip
        if hasattr(record, "event_type"):
            log_entry["event_type"] = record.event_type
        if hasattr(record, "duration_ms"):
            log_entry["duration_ms"] = record.duration_ms
        if hasattr(record, "file_id"):
            log_entry["file_id"] = record.file_id

        # If an exception exists, keep exception type and message, but avoid full memory dumps
        if record.exc_info:
            log_entry["exception_type"] = record.exc_info[0].__name__ if record.exc_info[0] else "Unknown"
            log_entry["exception_message"] = str(record.exc_info[1])

        return json.dumps(log_entry)


def setup_logger(name: str = "hashlens", level: str = "INFO") -> logging.Logger:
    """Configures and returns a structured logger."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Avoid duplicate handlers on re-import
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(SafeStructuredFormatter())
        logger.addHandler(handler)
        logger.propagate = False

    return logger


logger = setup_logger()
