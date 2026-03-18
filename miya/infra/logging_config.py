"""Structured logging configuration for Miya.

Call ``setup_logging()`` once at process start (in ``main.py``) to configure
a consistent, human-readable log format across all modules.

Env vars:
    MIYA_LOG_LEVEL   — root log level (default: INFO)
    MIYA_LOG_FORMAT   — "json" for machine-parseable output, anything else for
                        coloured human format (default: human)

Log levels (most → least verbose):
    TRACE (5)   — tool_use calls, tool results, SDK message blocks
    DEBUG (10)  — phase outputs, coordinator prompts, internal decisions
    INFO  (20)  — OODA iterations, phase transitions, events (default)
    WARNING (30)
    ERROR (40)
    CRITICAL (50)
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone

# ── Custom TRACE level (below DEBUG) ─────────────────────────────
TRACE = 5
logging.addLevelName(TRACE, "TRACE")


def _trace(self: logging.Logger, message: str, *args: object, **kwargs: object) -> None:
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kwargs)  # type: ignore[arg-type]


logging.Logger.trace = _trace  # type: ignore[attr-defined]


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
        "TRACE": "\033[2;35m",   # dim magenta
        "DEBUG": "\033[2m",       # dim
        "INFO": "\033[36m",       # cyan
        "WARNING": "\033[33m",    # yellow
        "ERROR": "\033[31m",      # red
        "CRITICAL": "\033[1;31m", # bold red
    }
    _RESET = "\033[0m"

    @staticmethod
    def _short_name(name: str) -> str:
        """Shorten logger name: 'miya.topology.ooda' → 'topology.ooda'."""
        return name.removeprefix("miya.")

    def format(self, record: logging.LogRecord) -> str:
        color = self._COLORS.get(record.levelname, "")
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        msg = record.getMessage()
        name = self._short_name(record.name)
        base = f"{color}{ts} {record.levelname:<8s}{self._RESET} [{name}] {msg}"
        if record.exc_info and record.exc_info[1]:
            base += "\n" + self.formatException(record.exc_info)
        return base


def setup_logging(level_override: int | None = None) -> None:
    """Configure root logger based on environment or explicit override.

    Args:
        level_override: If provided, overrides MIYA_LOG_LEVEL env var.
                        Use logging levels or ``TRACE`` (5) for tool-use detail.
    """
    if level_override is not None:
        level = level_override
    else:
        level_name = os.environ.get("MIYA_LOG_LEVEL", "INFO").upper()
        if level_name == "TRACE":
            level = TRACE
        else:
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
    # Remove existing handlers to avoid duplicates on re-init
    root.handlers.clear()
    root.setLevel(level)
    root.addHandler(handler)
    # Prevent duplicate output if root logger also has handlers
    root.propagate = False
