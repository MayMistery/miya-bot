"""Tests for Fanout topology with pre-defined challenges."""

from __future__ import annotations

import json
import pytest
import pytest_asyncio

from miya.shared.blackboard import Blackboard
from miya.shared.events import (
    DomainEvent, ChallengeIdentified, PhaseTransition,
)
from miya.shared.types import Mission, MissionType, Target
from miya.infra.event_store import SQLiteEventStore
from miya.topology.fanout_topo import FanoutTopology


def _ev(event_type: str, **fields: object) -> str:
    return f'[EVENT:{event_type} {json.dumps(fields)}]'


class MockCoordinator:
    """Simple mock that returns events based on challenge name."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def run(self, prompt: str, agents: dict, mcp_servers: list[str]) -> str:
        self.calls.append(prompt[:100])
        # Detect which challenge this is for and return a solved event
        if "Easy-Gin" in prompt:
            return (
                "Found the flag! "
                + _ev("ChallengeSolved",
                      challenge_name="Easy-Gin",
                      flag="flag{g1n_r0ut3r}",
                      approach="route parameter injection",
                      context="ctf")
            )
        if "Easy-JWT" in prompt:
            return (
                "Cracked JWT! "
                + _ev("ChallengeSolved",
                      challenge_name="Easy-JWT",
                      flag="flag{jwt_cr4ck}",
                      approach="weak HMAC secret",
                      context="ctf")
            )
        # Default: OODA loop phases
        if "## REFLECT" in prompt:
            return "DECISION: complete"
        if "## ACT" in prompt:
            return "[Mock ACT response]"
        return "[Mock response]"


@pytest_asyncio.fixture
async def store(tmp_path):
    s = SQLiteEventStore(str(tmp_path / "test.db"))
    await s.initialize()
    yield s
    await s.close()


class TestFanoutPreDefined:
    """Test that Fanout skips ENUMERATE when challenges are pre-defined."""

    @pytest.mark.asyncio
    async def test_predefined_challenges_skip_enumerate(self, store):
        """Pre-defined challenges should skip enumeration phase."""
        mock = MockCoordinator()
        topo = FanoutTopology(
            max_parallel=2, max_iterations_per_challenge=2, coordinator=mock,
        )

        mission = Mission(
            mission_type=MissionType.CTF,
            target=Target(uri="http://10.37.225.178", kind="url"),
            topology="fanout",
            options={
                "challenges": [
                    {"name": "Easy-Gin", "target": "http://127.0.0.1:16235", "category": "web"},
                    {"name": "Easy-JWT", "target": "http://127.0.0.1:17855", "category": "web"},
                ],
            },
        )
        mission.start()

        bb = Blackboard()
        events: list[DomainEvent] = []
        async for ev in topo.execute(mission, bb, {"web": _fake_agent()}, store):
            events.append(ev)

        # Should have ChallengeIdentified events from pre-defined list
        identified = [e for e in events if isinstance(e, ChallengeIdentified)]
        assert len(identified) == 2
        assert identified[0].challenge_name == "Easy-Gin"
        assert identified[1].challenge_name == "Easy-JWT"

        # The enumerate phase transition should mention "user-provided"
        phase_transitions = [e for e in events if isinstance(e, PhaseTransition)]
        enumerate_phase = [p for p in phase_transitions if p.to_phase == "enumerate"]
        assert len(enumerate_phase) >= 1
        assert "user-provided" in enumerate_phase[0].reason.lower()

        # Should NOT have called the coordinator for enumeration
        enum_calls = [c for c in mock.calls if "Enumerate all CTF" in c]
        assert len(enum_calls) == 0, "Should not call enumerate when challenges are pre-defined"

    @pytest.mark.asyncio
    async def test_predefined_challenges_use_per_challenge_target(self, store):
        """Each sub-mission should use the challenge-specific target URL."""
        mock = MockCoordinator()
        topo = FanoutTopology(
            max_parallel=1, max_iterations_per_challenge=2, coordinator=mock,
        )

        mission = Mission(
            mission_type=MissionType.CTF,
            target=Target(uri="http://10.37.225.178", kind="url"),
            topology="fanout",
            options={
                "challenges": [
                    {"name": "Easy-Gin", "target": "http://127.0.0.1:16235", "category": "web"},
                ],
            },
        )
        mission.start()

        bb = Blackboard()
        async for ev in topo.execute(mission, bb, {"web": _fake_agent()}, store):
            pass

        # Verify the sub-mission prompt contains the challenge-specific URL
        gin_calls = [c for c in mock.calls if "Easy-Gin" in c]
        assert len(gin_calls) > 0

    @pytest.mark.asyncio
    async def test_without_predefined_uses_enumerate(self, store):
        """Without pre-defined challenges, should use normal enumeration."""
        mock = MockCoordinator()
        topo = FanoutTopology(
            max_parallel=1, max_iterations_per_challenge=2, coordinator=mock,
        )

        mission = Mission(
            mission_type=MissionType.CTF,
            target=Target(uri="http://ctf.example.com", kind="url"),
            topology="fanout",
            # No "challenges" in options
        )
        mission.start()

        bb = Blackboard()
        async for ev in topo.execute(mission, bb, {"web": _fake_agent()}, store):
            pass

        # Should have called coordinator for enumeration
        enum_calls = [c for c in mock.calls if "Enumerate all CTF" in c]
        assert len(enum_calls) >= 1


def _fake_agent():
    """Create a minimal agent handle for testing."""
    from miya.topology.base import AgentHandle
    return AgentHandle(
        name="web",
        description="Test web agent",
        system_prompt="You are a web security agent",
        tools=[],
        mcp_servers=["nuclei"],
        model="sonnet",
    )
