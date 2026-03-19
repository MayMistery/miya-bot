"""Post-exploitation bounded context — domain model.

Aggregate Root: PostSession
Entities: LootItem
Value Objects: AccessLevel, PivotTarget
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from miya.shared.events import (
    DomainEvent,
    PrivilegeEscalated,
    LootCollected,
)
from miya.shared.types import new_id as _uuid


# ═══════════════════════════════════════════════════════════════════
#  Value Objects
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class AccessLevel:
    """Current privilege level on a compromised system."""

    level: str = "none"  # "none", "user", "admin", "root", "system"
    username: str = ""
    groups: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()  # specific capabilities/permissions

    @property
    def is_privileged(self) -> bool:
        return self.level in ("admin", "root", "system")


@dataclass(frozen=True)
class PivotTarget:
    """A lateral movement candidate discovered during post-exploitation."""

    host: str = ""
    ip: str = ""
    port: int = 0
    service: str = ""
    credential_id: str = ""  # reference to a discovered credential
    route: str = ""  # how to reach this target (e.g., "via session 1")
    confidence: str = "low"  # "low", "medium", "high"


# ═══════════════════════════════════════════════════════════════════
#  Entity
# ═══════════════════════════════════════════════════════════════════


@dataclass
class LootItem:
    """A piece of collected data from a compromised system."""

    id: str = field(default_factory=_uuid)
    loot_type: str = ""  # "credential", "config", "data", "key", "hash", "token"
    description: str = ""
    content: str = ""  # actual loot data (credentials, config snippets, etc.)
    source: str = ""  # where it was found (file path, registry key, etc.)
    target_host: str = ""


# ═══════════════════════════════════════════════════════════════════
#  Aggregate Root
# ═══════════════════════════════════════════════════════════════════


@dataclass
class PostSession:
    """Aggregate root for the post-exploitation bounded context.

    Manages a post-exploitation session: privilege escalation, data
    collection, credential harvesting, and lateral movement planning.
    """

    id: str = field(default_factory=_uuid)
    session_id: str = ""  # meterpreter/shell session ID
    target_host: str = ""
    access_level: AccessLevel = field(default_factory=AccessLevel)
    loot: list[LootItem] = field(default_factory=list)
    pivot_targets: list[PivotTarget] = field(default_factory=list)
    version: int = 0
    pending_events: list[DomainEvent] = field(default_factory=list)

    # ── Commands ──────────────────────────────────────────────────

    def escalate_privileges(
        self,
        to_level: str,
        username: str = "",
        technique: str = "",
        groups: tuple[str, ...] = (),
        correlation_id: str = "",
    ) -> None:
        """Record a privilege escalation."""
        from_level = self.access_level.level
        self.access_level = AccessLevel(
            level=to_level,
            username=username,
            groups=groups,
        )
        self.version += 1

        event = PrivilegeEscalated(
            aggregate_id=self.id,
            aggregate_type="PostSession",
            from_level=from_level,
            to_level=to_level,
            technique=technique,
            correlation_id=correlation_id,
            version=self.version,
            mission="oneday",
        )
        self.pending_events.append(event)

    def collect_loot(
        self,
        loot_type: str,
        description: str,
        content: str = "",
        source: str = "",
        correlation_id: str = "",
    ) -> LootItem:
        """Record collected loot (credentials, configs, data)."""
        item = LootItem(
            loot_type=loot_type,
            description=description,
            content=content,
            source=source,
            target_host=self.target_host,
        )
        self.loot.append(item)
        self.version += 1

        event = LootCollected(
            aggregate_id=self.id,
            aggregate_type="PostSession",
            loot_type=loot_type,
            description=description,
            correlation_id=correlation_id,
            version=self.version,
            mission="oneday",
        )
        self.pending_events.append(event)
        return item

    def add_pivot_target(self, target: PivotTarget) -> None:
        """Register a potential lateral movement target."""
        self.pivot_targets.append(target)

    # ── Queries ───────────────────────────────────────────────────

    def credentials(self) -> list[LootItem]:
        """Return all collected credentials."""
        return [l for l in self.loot if l.loot_type in ("credential", "hash", "token", "key")]

    def high_confidence_pivots(self) -> list[PivotTarget]:
        """Return pivot targets with high confidence."""
        return [p for p in self.pivot_targets if p.confidence == "high"]

    # ── Event Sourcing ────────────────────────────────────────────

    def apply(self, event: DomainEvent) -> None:
        """Reconstitute state from a persisted event."""
        if isinstance(event, PrivilegeEscalated):
            self.access_level = AccessLevel(level=event.to_level)
            self.version = event.version

        elif isinstance(event, LootCollected):
            item = LootItem(
                loot_type=event.loot_type,
                description=event.description,
            )
            self.loot.append(item)
            self.version = event.version

    def collect_events(self) -> list[DomainEvent]:
        """Drain pending events."""
        events = list(self.pending_events)
        self.pending_events.clear()
        return events
