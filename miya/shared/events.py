"""Domain events — the atoms of event sourcing.

Every state change in Miya is captured as a DomainEvent, persisted to the
EventStore, and projected into the Blackboard.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, ClassVar
from uuid import uuid4


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid4())


# ═══════════════════════════════════════════════════════════════════
#  Base Event
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class DomainEvent:
    """Immutable base for all domain events."""

    event_id: str = field(default_factory=_uuid)
    timestamp: datetime = field(default_factory=_now)
    context: str = ""  # bounded context name
    mission: str = ""  # "zeroday" | "oneday" | "ctf"
    aggregate_id: str = ""
    aggregate_type: str = ""
    correlation_id: str = ""  # links related events across contexts
    causation_id: str = ""  # which event caused this one
    version: int = 0  # aggregate version for optimistic concurrency

    # Subclasses set this to their event type name
    event_type: ClassVar[str] = "DomainEvent"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d["event_type"] = self.__class__.event_type
        return d

    @classmethod
    def type_name(cls) -> str:
        return cls.event_type


# ═══════════════════════════════════════════════════════════════════
#  Shared Events (cross-context)
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class MissionStarted(DomainEvent):
    event_type: ClassVar[str] = "mission.started"
    mission_type: str = ""
    target_uri: str = ""
    topology: str = ""


@dataclass(frozen=True)
class MissionCompleted(DomainEvent):
    event_type: ClassVar[str] = "mission.completed"
    findings_count: int = 0
    duration_seconds: float = 0.0


@dataclass(frozen=True)
class MissionFailed(DomainEvent):
    event_type: ClassVar[str] = "mission.failed"
    reason: str = ""


@dataclass(frozen=True)
class PhaseTransition(DomainEvent):
    """Emitted when the topology transitions between phases."""
    event_type: ClassVar[str] = "topology.phase_transition"
    from_phase: str = ""
    to_phase: str = ""
    reason: str = ""


@dataclass(frozen=True)
class ReflectionCompleted(DomainEvent):
    """OODA reflection gate result."""
    event_type: ClassVar[str] = "topology.reflection"
    assessment: str = ""
    decision: str = ""  # "continue", "pivot", "retry", "complete"
    insights: str = ""


# ═══════════════════════════════════════════════════════════════════
#  Asset & Recon Events
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class AssetDiscovered(DomainEvent):
    event_type: ClassVar[str] = "recon.asset_discovered"
    host: str = ""
    ip: str = ""
    ports: tuple[int, ...] = ()
    services: tuple[str, ...] = ()
    os: str = ""
    context: str = "recon"


@dataclass(frozen=True)
class FingerprintCompleted(DomainEvent):
    event_type: ClassVar[str] = "recon.fingerprint_completed"
    asset_id: str = ""
    software: str = ""
    version: str = ""
    technology_stack: tuple[str, ...] = ()
    context: str = "recon"


# ═══════════════════════════════════════════════════════════════════
#  Vulnerability Events
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class ScanCompleted(DomainEvent):
    event_type: ClassVar[str] = "scan.completed"
    target_host: str = ""
    target_ports: tuple[int, ...] = ()
    findings_count: int = 0
    scanner: str = ""  # "nuclei", "nmap", etc.
    context: str = "scan"


@dataclass(frozen=True)
class VulnerabilityFound(DomainEvent):
    event_type: ClassVar[str] = "vuln.found"
    vuln_id: str = ""
    vuln_type: str = ""  # CWE name
    cwe_id: str = ""
    severity: str = "medium"
    location: str = ""  # file:line or URL
    description: str = ""
    context: str = "vuln"


@dataclass(frozen=True)
class CVEMatched(DomainEvent):
    event_type: ClassVar[str] = "vuln.cve_matched"
    cve_id: str = ""
    cvss: float = 0.0
    affected_software: str = ""
    exploit_available: bool = False
    context: str = "vuln"


# ═══════════════════════════════════════════════════════════════════
#  Exploit Events
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class ExploitAttempted(DomainEvent):
    event_type: ClassVar[str] = "exploit.attempted"
    cve_id: str = ""
    technique: str = ""
    payload_summary: str = ""
    context: str = "exploit"


@dataclass(frozen=True)
class ExploitSucceeded(DomainEvent):
    event_type: ClassVar[str] = "exploit.succeeded"
    cve_id: str = ""
    access_gained: str = ""  # "user", "root", "rce", "data_read"
    evidence: str = ""
    context: str = "exploit"


@dataclass(frozen=True)
class ExploitFailed(DomainEvent):
    event_type: ClassVar[str] = "exploit.failed"
    cve_id: str = ""
    reason: str = ""
    context: str = "exploit"


# ═══════════════════════════════════════════════════════════════════
#  0-day Events
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class EntryPointDiscovered(DomainEvent):
    event_type: ClassVar[str] = "zeroday.entrypoint_discovered"
    endpoint: str = ""
    input_vectors: tuple[str, ...] = ()
    framework: str = ""
    context: str = "entrypoint"
    mission: str = "zeroday"


@dataclass(frozen=True)
class TaintPathTraced(DomainEvent):
    event_type: ClassVar[str] = "zeroday.taint_path_traced"
    source: str = ""
    sink: str = ""
    path: tuple[str, ...] = ()
    sanitized: bool = False
    context: str = "dataflow"
    mission: str = "zeroday"


@dataclass(frozen=True)
class SinkConfirmed(DomainEvent):
    event_type: ClassVar[str] = "zeroday.sink_confirmed"
    sink_type: str = ""
    cwe_id: str = ""
    exploitability: str = ""
    context: str = "sink"
    mission: str = "zeroday"


@dataclass(frozen=True)
class PoCValidated(DomainEvent):
    event_type: ClassVar[str] = "zeroday.poc_validated"
    vuln_type: str = ""
    poc_code: str = ""
    result: str = ""
    context: str = "poc"
    mission: str = "zeroday"


# ═══════════════════════════════════════════════════════════════════
#  CTF Events
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class ChallengeIdentified(DomainEvent):
    event_type: ClassVar[str] = "ctf.challenge_identified"
    challenge_name: str = ""
    category: str = ""
    points: int = 0
    context: str = "ctf"
    mission: str = "ctf"


@dataclass(frozen=True)
class ChallengeSolved(DomainEvent):
    event_type: ClassVar[str] = "ctf.challenge_solved"
    challenge_name: str = ""
    flag: str = ""
    approach: str = ""
    context: str = "ctf"
    mission: str = "ctf"


# ═══════════════════════════════════════════════════════════════════
#  Post-exploitation Events
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class PrivilegeEscalated(DomainEvent):
    event_type: ClassVar[str] = "post.privilege_escalated"
    from_level: str = ""
    to_level: str = ""
    technique: str = ""
    context: str = "post"


@dataclass(frozen=True)
class LootCollected(DomainEvent):
    event_type: ClassVar[str] = "post.loot_collected"
    loot_type: str = ""  # "credential", "config", "data", "key"
    description: str = ""
    value: str = ""  # the actual secret/data/flag
    context: str = "post"


# ═══════════════════════════════════════════════════════════════════
#  Operator (HITL) Events
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class OperatorMessage(DomainEvent):
    """Human-in-the-loop message injected by the operator during execution."""
    event_type: ClassVar[str] = "operator.message"
    content: str = ""
    context: str = "operator"


# ═══════════════════════════════════════════════════════════════════
#  Event Registry
# ═══════════════════════════════════════════════════════════════════


_EVENT_REGISTRY: dict[str, type[DomainEvent]] = {}


def _register_events() -> None:
    """Auto-discover all DomainEvent subclasses in this module."""
    import inspect
    for name, obj in globals().items():
        if (
            inspect.isclass(obj)
            and issubclass(obj, DomainEvent)
            and obj is not DomainEvent
        ):
            _EVENT_REGISTRY[obj.event_type] = obj


_register_events()


def event_from_dict(data: dict[str, Any]) -> DomainEvent:
    """Reconstruct a DomainEvent from its serialized form."""
    event_type = data.pop("event_type", "DomainEvent")
    cls = _EVENT_REGISTRY.get(event_type, DomainEvent)

    # Parse timestamp
    ts = data.get("timestamp")
    if isinstance(ts, str):
        data["timestamp"] = datetime.fromisoformat(ts)

    # Handle tuple fields
    for f_name in ("ports", "services", "input_vectors", "path", "technology_stack", "target_ports"):
        if f_name in data and isinstance(data[f_name], list):
            data[f_name] = tuple(data[f_name])

    # Filter to only fields this class accepts
    import dataclasses
    valid_fields = {f.name for f in dataclasses.fields(cls)}
    filtered = {k: v for k, v in data.items() if k in valid_fields}

    return cls(**filtered)


# ═══════════════════════════════════════════════════════════════════
#  Event Bus (in-process pub/sub)
# ═══════════════════════════════════════════════════════════════════


from typing import Callable, Coroutine
import asyncio

Handler = Callable[[DomainEvent], Coroutine[Any, Any, None]]


class EventBus:
    """Simple in-process event bus for cross-context communication."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = {}
        self._global_handlers: list[Handler] = []

    def subscribe(self, event_type: str, handler: Handler) -> None:
        """Subscribe to a specific event type."""
        self._handlers.setdefault(event_type, []).append(handler)

    def subscribe_all(self, handler: Handler) -> None:
        """Subscribe to ALL events."""
        self._global_handlers.append(handler)

    async def publish(self, event: DomainEvent) -> None:
        type_name = event.__class__.event_type
        handlers = self._handlers.get(type_name, []) + self._global_handlers
        await asyncio.gather(*(h(event) for h in handlers))

    async def publish_all(self, events: list[DomainEvent]) -> None:
        for event in events:
            await self.publish(event)
