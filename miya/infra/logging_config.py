"""Structured logging configuration for Miya.

Call ``setup_logging()`` once at process start (in ``main.py``) to configure
a consistent, human-readable log format across all modules.

Env vars:
    MIYA_LOG_LEVEL   — root log level (default: INFO)
    MIYA_LOG_FORMAT   — "json" for machine-parseable output, anything else for
                        coloured human format (default: human)
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone


class _JsonFormatter(logging.Formatter):
    """Emit one JSON object per log line for machine consumption."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


class _HumanFormatter(logging.Formatter):
    """Coloured single-line format for interactive terminals."""

    _COLORS = {
        "DEBUG": "\033[2m",       # dim
        "INFO": "\033[36m",       # cyan
        "WARNING": "\033[33m",    # yellow
        "ERROR": "\033[31m",      # red
        "CRITICAL": "\033[1;31m", # bold red
    }
    _RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self._COLORS.get(record.levelname, "")
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        msg = record.getMessage()
        base = f"{color}{ts} {record.levelname:<8s}{self._RESET} [{record.name}] {msg}"
        if record.exc_info and record.exc_info[1]:
            base += "\n" + self.formatException(record.exc_info)
        return base


def setup_logging() -> None:
    """Configure root logger based on environment."""
    level_name = os.environ.get("MIYA_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    fmt = os.environ.get("MIYA_LOG_FORMAT", "human").lower()
    formatter: logging.Formatter
    if fmt == "json":
        formatter = _JsonFormatter()
    else:
        formatter = _HumanFormatter()

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root = logging.getLogger("miya")
    root.setLevel(level)
    root.addHandler(handler)
    # Prevent duplicate output if root logger also has handlers
    root.propagate = False
