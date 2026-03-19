"""Tests for fanout topology type safety — ensures stringified challenges don't crash."""

from __future__ import annotations

import json
import pytest
import pytest_asyncio

from miya.shared.blackboard import Blackboard
from miya.shared.events import (
    DomainEvent, PhaseTransition,
)
from miya.shared.types import Mission, MissionType, Target
from miya.infra.event_store import SQLiteEventStore
from miya.topology.fanout_topo import FanoutTopology


class MockCoordinator:
    """Mock coordinator that returns ChallengeIdentified events for PREPARE phase."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def run(self, prompt: str, agents: dict, mcp_servers: list[str]) -> str:
        self.calls.append(prompt[:200])
        if "## REFLECT" in prompt:
            return "DECISION: complete"
        if "## ACT" in prompt:
            return "[Mock ACT]"
        return "[Mock response - no challenges found]"


def _fake_agent():
    from miya.topology.base import AgentHandle
    return AgentHandle(
        name="web", description="Test", system_prompt="test",
        tools=[], mcp_servers=[], model="sonnet",
    )


@pytest_asyncio.fixture
async def store(tmp_path):
    s = SQLiteEventStore(str(tmp_path / "test.db"))
    await s.initialize()
    yield s
    await s.close()


class TestFanoutTypeSafety:
    """Regression tests for the 'str' object has no attribute 'get' bug."""

    @pytest.mark.asyncio
    async def test_stringified_challenges_do_not_crash(self, store):
        """If challenges option is a string (from str() conversion), should not raise."""
        mock = MockCoordinator()
        topo = FanoutTopology(
            max_parallel=1, max_iterations_per_challenge=1, coordinator=mock,
        )

        # Simulate the bug: challenges passed as str() of a list
        stringified = str([{"name": "Easy-Gin", "target": "http://127.0.0.1:16235"}])

        mission = Mission(
            mission_type=MissionType.CTF,
            target=Target(uri="http://10.37.225.178", kind="url"),
            topology="fanout",
            options={"challenges": stringified},
        )
        mission.start()

        bb = Blackboard()
        events: list[DomainEvent] = []

        # This should NOT raise AttributeError
        async for ev in topo.execute(mission, bb, {"web": _fake_agent()}, store):
            events.append(ev)

        # Since the stringified challenges are invalid, it should fall through
        # to the enumerate phase instead of crashing
        phase_transitions = [e for e in events if isinstance(e, PhaseTransition)]
        enum_phases = [p for p in phase_transitions if p.to_phase == "enumerate"]
        assert len(enum_phases) >= 1, "Should fallback to enumerate when challenges are invalid"

    @pytest.mark.asyncio
    async def test_list_of_strings_do_not_crash(self, store):
        """If challenges is a list of strings (not dicts), should not raise."""
        mock = MockCoordinator()
        topo = FanoutTopology(
            max_parallel=1, max_iterations_per_challenge=1, coordinator=mock,
        )

        mission = Mission(
            mission_type=MissionType.CTF,
            target=Target(uri="http://10.37.225.178", kind="url"),
            topology="fanout",
            options={"challenges": ["Easy-Gin", "Easy-JWT"]},
        )
        mission.start()

        bb = Blackboard()
        events: list[DomainEvent] = []

        # Should not crash — should fallback to enumerate
        async for ev in topo.execute(mission, bb, {"web": _fake_agent()}, store):
            events.append(ev)

        phase_transitions = [e for e in events if isinstance(e, PhaseTransition)]
        enum_phases = [p for p in phase_transitions if p.to_phase == "enumerate"]
        assert len(enum_phases) >= 1

    @pytest.mark.asyncio
    async def test_valid_json_string_challenges_recovered(self, store):
        """A valid JSON string of challenges should be recovered and used."""
        mock = MockCoordinator()
        topo = FanoutTopology(
            max_parallel=1, max_iterations_per_challenge=1, coordinator=mock,
        )

        challenges = [
            {"name": "Easy-Gin", "target": "http://127.0.0.1:16235", "category": "web"},
        ]
        # Pass as JSON string instead of list
        mission = Mission(
            mission_type=MissionType.CTF,
            target=Target(uri="http://10.37.225.178", kind="url"),
            topology="fanout",
            options={"challenges": json.dumps(challenges)},
        )
        mission.start()

        bb = Blackboard()
        events: list[DomainEvent] = []
        async for ev in topo.execute(mission, bb, {"web": _fake_agent()}, store):
            events.append(ev)

        # Should have used the recovered challenges (skip enumerate)
        phase_transitions = [e for e in events if isinstance(e, PhaseTransition)]
        enum_phases = [p for p in phase_transitions if p.to_phase == "enumerate"]
        assert len(enum_phases) >= 1
        assert "user-provided" in enum_phases[0].reason.lower()

    @pytest.mark.asyncio
    async def test_prepare_phase_shows_challenge_targets(self, store):
        """PREPARE phase transition should include challenge target details."""
        mock = MockCoordinator()
        topo = FanoutTopology(
            max_parallel=1, max_iterations_per_challenge=1, coordinator=mock,
        )

        challenges = [
            {"name": "Easy-Gin", "target": "http://10.0.0.1:16235", "category": "web"},
            {"name": "Easy-JWT", "target": "http://10.0.0.1:17855", "category": "web"},
        ]
        mission = Mission(
            mission_type=MissionType.CTF,
            target=Target(uri="http://10.0.0.1", kind="url"),
            topology="fanout",
            options={
                "challenges": challenges,
                "general_instructions": ["switch to bench branch"],
            },
        )
        mission.start()

        bb = Blackboard()
        events: list[DomainEvent] = []
        async for ev in topo.execute(mission, bb, {"web": _fake_agent()}, store):
            events.append(ev)

        # PREPARE phase transition should mention challenge targets
        prepare_phases = [
            e for e in events
            if isinstance(e, PhaseTransition) and e.to_phase == "prepare"
        ]
        assert len(prepare_phases) == 1
        reason = prepare_phases[0].reason
        assert "Easy-Gin" in reason
        assert "Easy-JWT" in reason
        assert "10.0.0.1:16235" in reason
        assert "10.0.0.1:17855" in reason
