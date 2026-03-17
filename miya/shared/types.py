"""Shared value objects used across all bounded contexts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4


# ═══════════════════════════════════════════════════════════════════
#  Enums
# ═══════════════════════════════════════════════════════════════════


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]

    def __gt__(self, other: Severity) -> bool:  # type: ignore[override]
        return self.score > other.score

    def __ge__(self, other: Severity) -> bool:  # type: ignore[override]
        return self.score >= other.score


class MissionType(str, Enum):
    ZERODAY = "zeroday"
    ONEDAY = "oneday"
    CTF = "ctf"


class OODAPhase(str, Enum):
    OBSERVE = "observe"
    ORIENT = "orient"
    DECIDE = "decide"
    ACT = "act"
    REFLECT = "reflect"


# ═══════════════════════════════════════════════════════════════════
#  Core Value Objects
# ═══════════════════════════════════════════════════════════════════


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid4())


@dataclass(frozen=True)
class Target:
    """What we're pointing Miya at."""

    uri: str
    kind: Literal["source", "binary", "service", "network", "challenge", "url"]
    meta: dict[str, str] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"[{self.kind}] {self.uri}"


@dataclass(frozen=True)
class Finding:
    """A single actionable result from any bounded context."""

    id: str = field(default_factory=_uuid)
    title: str = ""
    severity: Severity = Severity.INFO
    detail: str = ""
    evidence: str = ""
    context: str = ""  # bounded context that produced this
    mission: str = ""  # "zeroday" | "oneday" | "ctf"
    timestamp: datetime = field(default_factory=_now)

    def oneliner(self) -> str:
        return f"[{self.severity.value.upper():>8s}] {self.title}"


@dataclass(frozen=True)
class Credential:
    """Discovered credential."""

    username: str
    secret: str  # password, hash, token, key
    secret_type: Literal["password", "hash", "token", "ssh_key", "api_key"] = "password"
    target: str = ""  # where this credential is valid
    access_level: str = ""  # "user", "admin", "root", etc.


@dataclass(frozen=True)
class Asset:
    """A discovered network asset."""

    id: str = field(default_factory=_uuid)
    host: str = ""
    ip: str = ""
    ports: tuple[int, ...] = ()
    services: tuple[str, ...] = ()  # "http", "ssh", "mysql" etc.
    os: str = ""
    fingerprint: dict[str, str] = field(default_factory=dict)

    @property
    def address(self) -> str:
        return self.ip or self.host


@dataclass(frozen=True)
class AttackTechnique:
    """MITRE ATT&CK technique reference."""

    tactic: str  # "initial-access", "execution", "persistence", etc.
    technique_id: str  # T1190, T1059, etc.
    name: str  # "Exploit Public-Facing Application"
    sub_technique: str = ""


# ═══════════════════════════════════════════════════════════════════
#  Mission
# ═══════════════════════════════════════════════════════════════════


@dataclass
class Mission:
    """Top-level mission — the user's request."""

    id: str = field(default_factory=_uuid)
    mission_type: MissionType = MissionType.ONEDAY
    target: Target = field(default_factory=lambda: Target(uri="", kind="service"))
    topology: str = "ooda"
    options: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=_now)
    status: Literal["created", "running", "completed", "failed"] = "created"

    def start(self) -> None:
        self.status = "running"

    def complete(self) -> None:
        self.status = "completed"

    def fail(self) -> None:
        self.status = "failed"
