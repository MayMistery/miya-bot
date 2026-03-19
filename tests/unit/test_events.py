"""Unit tests for miya.shared.events — domain events, serialization, and event bus."""

from __future__ import annotations

import asyncio
import pytest
from datetime import datetime, timezone

from miya.shared.events import (
    DomainEvent,
    MissionStarted,
    MissionCompleted,
    MissionFailed,
    PhaseTransition,
    ReflectionCompleted,
    AssetDiscovered,
    FingerprintCompleted,
    ScanCompleted,
    VulnerabilityFound,
    CVEMatched,
    ExploitAttempted,
    ExploitSucceeded,
    ExploitFailed,
    EntryPointDiscovered,
    TaintPathTraced,
    SinkConfirmed,
    PoCValidated,
    ChallengeIdentified,
    ChallengeSolved,
    PrivilegeEscalated,
    LootCollected,
    EventBus,
    event_from_dict,
    _EVENT_REGISTRY,
)


# ═══════════════════════════════════════════════════════════════════
#  Base Event
# ═══════════════════════════════════════════════════════════════════


class TestDomainEvent:
    def test_auto_id_and_timestamp(self):
        e = DomainEvent()
        assert e.event_id
        assert e.timestamp is not None

    def test_immutable(self):
        e = DomainEvent()
        with pytest.raises(AttributeError):
            e.context = "changed"  # type: ignore[misc]

    def test_to_dict(self):
        e = MissionStarted(
            mission_type="oneday",
            target_uri="10.0.0.1",
            topology="ooda",
        )
        d = e.to_dict()
        assert d["event_type"] == "mission.started"
        assert d["mission_type"] == "oneday"
        assert d["target_uri"] == "10.0.0.1"
        assert isinstance(d["timestamp"], str)

    def test_type_name(self):
        assert MissionStarted.type_name() == "mission.started"
        assert ExploitSucceeded.type_name() == "exploit.succeeded"


# ═══════════════════════════════════════════════════════════════════
#  Event Registry
# ═══════════════════════════════════════════════════════════════════


class TestEventRegistry:
    def test_all_events_registered(self):
        expected_types = [
            "mission.started",
            "mission.completed",
            "mission.failed",
            "topology.phase_transition",
            "topology.reflection",
            "recon.asset_discovered",
            "recon.fingerprint_completed",
            "scan.completed",
            "vuln.found",
            "vuln.cve_matched",
            "exploit.attempted",
            "exploit.succeeded",
            "exploit.failed",
            "zeroday.entrypoint_discovered",
            "zeroday.taint_path_traced",
            "zeroday.sink_confirmed",
            "zeroday.poc_validated",
            "ctf.challenge_identified",
            "ctf.challenge_solved",
            "post.privilege_escalated",
            "post.loot_collected",
        ]
        for et in expected_types:
            assert et in _EVENT_REGISTRY, f"Event type '{et}' not registered"


# ═══════════════════════════════════════════════════════════════════
#  Serialization Round-trip
# ═══════════════════════════════════════════════════════════════════


class TestEventSerialization:
    def test_roundtrip_simple(self):
        original = MissionStarted(
            mission_type="oneday",
            target_uri="10.0.0.1",
            topology="ooda",
            aggregate_id="mission-1",
        )
        d = original.to_dict()
        restored = event_from_dict(d)
        assert isinstance(restored, MissionStarted)
        assert restored.mission_type == "oneday"
        assert restored.target_uri == "10.0.0.1"

    def test_roundtrip_with_tuples(self):
        original = AssetDiscovered(
            host="example.com",
            ip="10.0.0.1",
            ports=(22, 80, 443),
            services=("ssh", "http", "https"),
        )
        d = original.to_dict()
        # asdict converts tuples to lists
        assert isinstance(d["ports"], (list, tuple))
        restored = event_from_dict(d)
        assert isinstance(restored, AssetDiscovered)
        assert restored.ports == (22, 80, 443)
        assert restored.services == ("ssh", "http", "https")

    def test_roundtrip_taint_path(self):
        original = TaintPathTraced(
            source="request.GET['id']",
            sink="cursor.execute()",
            path=("param", "validate", "query"),
            sanitized=False,
        )
        d = original.to_dict()
        restored = event_from_dict(d)
        assert isinstance(restored, TaintPathTraced)
        assert restored.path == ("param", "validate", "query")
        assert restored.sanitized is False

    def test_unknown_event_type_returns_base(self):
        d = {"event_type": "unknown.event", "event_id": "test-1", "timestamp": datetime.now(timezone.utc).isoformat()}
        restored = event_from_dict(d)
        assert isinstance(restored, DomainEvent)


# ═══════════════════════════════════════════════════════════════════
#  Event Bus
# ═══════════════════════════════════════════════════════════════════


class TestEventBus:
    @pytest.fixture
    def bus(self):
        return EventBus()

    @pytest.mark.asyncio
    async def test_subscribe_and_publish(self, bus):
        received = []

        async def handler(event: DomainEvent) -> None:
            received.append(event)

        bus.subscribe("mission.started", handler)
        event = MissionStarted(mission_type="oneday")
        await bus.publish(event)

        assert len(received) == 1
        assert received[0] is event

    @pytest.mark.asyncio
    async def test_subscribe_all(self, bus):
        received = []

        async def handler(event: DomainEvent) -> None:
            received.append(event)

        bus.subscribe_all(handler)

        await bus.publish(MissionStarted())
        await bus.publish(MissionCompleted())

        assert len(received) == 2

    @pytest.mark.asyncio
    async def test_no_cross_fire(self, bus):
        received = []

        async def handler(event: DomainEvent) -> None:
            received.append(event)

        bus.subscribe("mission.started", handler)
        await bus.publish(MissionCompleted())

        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_publish_all(self, bus):
        received = []

        async def handler(event: DomainEvent) -> None:
            received.append(event)

        bus.subscribe_all(handler)
        events = [MissionStarted(), ExploitSucceeded(), MissionCompleted()]
        await bus.publish_all(events)

        assert len(received) == 3
