"""Shared value objects across all bounded contexts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Literal


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Target:
    """Anything we're pointing the agent at."""

    uri: str
    kind: Literal["source", "binary", "service", "challenge"]
    meta: dict[str, str] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"[{self.kind}] {self.uri}"


@dataclass(frozen=True)
class Finding:
    """A single actionable result from any bounded context."""

    title: str
    severity: Severity
    detail: str
    evidence: str  # proof — code snippet, payload, flag
    context: str  # "zeroday" | "oneday" | "ctf"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def oneliner(self) -> str:
        return f"[{self.severity.value.upper()}] {self.title}"
