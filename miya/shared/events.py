"""Lightweight domain event bus for cross-context communication."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine


@dataclass(frozen=True)
class DomainEvent:
    """Base for all domain events."""

    context: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ── Concrete events ────────────────────────────────────────────────

@dataclass(frozen=True)
class VulnDiscovered(DomainEvent):
    """0-day context found a vulnerability."""

    vuln_type: str = ""
    location: str = ""
    severity: str = "high"
    context: str = "zeroday"


@dataclass(frozen=True)
class ExploitSucceeded(DomainEvent):
    """1-day context successfully exploited a target."""

    cve_id: str = ""
    target: str = ""
    context: str = "oneday"


@dataclass(frozen=True)
class ChallengeSolved(DomainEvent):
    """CTF context captured a flag."""

    challenge: str = ""
    flag: str = ""
    category: str = ""
    context: str = "ctf"


# ── Event bus ──────────────────────────────────────────────────────

Handler = Callable[[DomainEvent], Coroutine[Any, Any, None]]


class EventBus:
    """Simple in-process pub/sub. One per agent process."""

    def __init__(self) -> None:
        self._handlers: dict[type[DomainEvent], list[Handler]] = {}

    def subscribe(self, event_type: type[DomainEvent], handler: Handler) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    async def publish(self, event: DomainEvent) -> None:
        for handler in self._handlers.get(type(event), []):
            await handler(event)

    async def publish_all(self, events: list[DomainEvent]) -> None:
        await asyncio.gather(*(self.publish(e) for e in events))
