"""Central logging configuration.

Call setup_logging() once at process startup. Every module then uses the
standard library logger:  logger = logging.getLogger(__name__)
"""

import json
import logging
import sys
from datetime import datetime, timezone

from app.config import settings


class TextFormatter(logging.Formatter):
    """Human-readable single-line output for local development."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()
        return (
            f"{timestamp} "
            f"{record.levelname:<8} "
            f"{record.name} - "
            f"{record.getMessage()}"
        )


class JsonFormatter(logging.Formatter):
    """Machine-parseable JSON, one object per line, for production."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED_KEYS and not key.startswith("_"):
                payload[key] = value
        return json.dumps(payload)


_RESERVED_KEYS = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "taskName",
}


def setup_logging() -> None:
    """Configure the root logger once. Safe to call multiple times."""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    formatter: logging.Formatter = (
        JsonFormatter() if settings.log_format == "json" else TextFormatter()
    )
 
    handler = logging.StreamHandler(sys.stdout)   
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()                        
    root.addHandler(handler)
    root.setLevel(level)

    for noisy in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(noisy).handlers.clear()
        logging.getLogger(noisy).propagate = True