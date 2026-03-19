"""Tests for PREPARE phase, file_paths propagation, SDKSession, and hybrid OODA mode."""

from __future__ import annotations

import json
import pytest
import pytest_asyncio

from miya.shared.blackboard import Blackboard, ChallengeView, ClassificationView
from miya.shared.events import (
    ChallengeIdentified,
    ChallengeSolved,
    DomainEvent,
    MissionStarted,
    MissionCompleted,
    PhaseTransition,
    event_from_dict,
)
from miya.shared.ports import CoordinatorPort
from miya.shared.types import Mission, MissionType, Target
from miya.infra.event_store import SQLiteEventStore
from miya.topology.base import extract_events_from_output, SDKSession
from miya.topology.fanout_topo import FanoutTopology


def _ev(event_type: str, **fields: object) -> str:
    return f'[EVENT:{event_type} {json.dumps(fields)}]'


# ═══════════════════════════════════════════════════════════════════
#  Mock Coordinator
# ═══════════════════════════════════════════════════════════════════


class PrepareAwareCoordinator:
    """Mock coordinator that responds to PREPARE, ENUMERATE, OODA phases."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def run(self, prompt: str, agents: dict, mcp_servers: list[str]) -> str:
        self.calls.append(prompt[:200])

        # PREPARE phase — discover attachments
        if "preparation assistant" in prompt.lower() or "Discover Challenge Attachments" in prompt:
            return (
                "Executed general instructions. Found challenge files.\n"
                + _ev("ChallengeIdentified",
                      challenge_name="Easy-Gin",
                      category="web",
                      file_paths=["/challenges/easy-gin/app.py", "/challenges/easy-gin/Dockerfile"],
                      context="ctf")
                + "\n"
                + _ev("ChallengeIdentified",
                      challenge_name="Baby-Pwn",
                      category="pwn",
                      file_paths=["/challenges/baby-pwn/vuln"],
                      context="ctf")
            )

        # OODA phases
        if "## REFLECT" in prompt:
            return "DECISION: complete\nASSESSMENT: solved"
        if "## ACT" in prompt or "Solve challenge" in prompt:
            if "Easy-Gin" in prompt:
                return _ev("ChallengeSolved",
                           challenge_name="Easy-Gin",
                           flag="flag{g1n}",
                           approach="SSTI",
                           context="ctf")
            if "Baby-Pwn" in prompt:
                return _ev("ChallengeSolved",
                           challenge_name="Baby-Pwn",
                           flag="flag{pwn}",
                           approach="buffer overflow",
                           context="ctf")
            return "[Mock ACT]"

        # Classify
        if "Explore and classify" in prompt:
            return "CATEGORY: web\nCONFIDENCE: 0.9\nREASONING: web app\nRECON_SUMMARY:\nFlask app"

        return "[Mock response]"


@pytest_asyncio.fixture
async def store(tmp_path):
    s = SQLiteEventStore(str(tmp_path / "test.db"))
    await s.initialize()
    yield s
    await s.close()


def _fake_agent(name="web", category="web"):
    from miya.topology.base import AgentHandle
    return AgentHandle(
        name=name,
        description=f"Test {category} agent",
        system_prompt=f"You are a {category} agent",
        tools=[],
        mcp_servers=[],
        model="sonnet",
        context_name=f"ctf.{category}",
    )


# ═══════════════════════════════════════════════════════════════════
#  Fix #2: file_paths in event_from_dict tuple conversion
# ═══════════════════════════════════════════════════════════════════


class TestFilePathsTupleConversion:
    def test_event_from_dict_converts_file_paths_list_to_tuple(self):
        """event_from_dict should convert file_paths from list to tuple."""
        data = {
            "event_type": "ctf.challenge_identified",
            "challenge_name": "test",
            "category": "web",
            "file_paths": ["/a/b.py", "/c/d.py"],
        }
        event = event_from_dict(data)
        assert isinstance(event, ChallengeIdentified)
        assert isinstance(event.file_paths, tuple)
        assert event.file_paths == ("/a/b.py", "/c/d.py")

    def test_event_from_dict_empty_file_paths(self):
        """Empty file_paths list should become empty tuple."""
        data = {
            "event_type": "ctf.challenge_identified",
            "challenge_name": "test",
            "file_paths": [],
        }
        event = event_from_dict(data)
        assert event.file_paths == ()

    def test_extract_events_converts_file_paths(self):
        """extract_events_from_output should convert file_paths from JSON array to tuple."""
        mission = Mission(
            mission_type=MissionType.CTF,
            target=Target(uri="http://test", kind="url"),
        )
        output = _ev("ChallengeIdentified",
                      challenge_name="ch1",
                      category="web",
                      file_paths=["/x/y.py"])
        events = extract_events_from_output(output, mission)
        assert len(events) == 1
        assert isinstance(events[0].file_paths, tuple)
        assert events[0].file_paths == ("/x/y.py",)


# ═══════════════════════════════════════════════════════════════════
#  Fix #3: file_paths in Blackboard.to_context_prompt()
# ═══════════════════════════════════════════════════════════════════


class TestBlackboardFilePathsRendering:
    def test_context_prompt_shows_file_paths_for_unsolved(self):
        """Unsolved challenges should show file_paths in context prompt."""
        bb = Blackboard()
        bb.apply(ChallengeIdentified(
            challenge_name="Easy-Gin",
            category="web",
            file_paths=("/app.py", "/Dockerfile"),
        ))
        prompt = bb.to_context_prompt()
        assert "Easy-Gin" in prompt
        assert "/app.py" in prompt
        assert "/Dockerfile" in prompt

    def test_context_prompt_omits_file_paths_when_empty(self):
        """Challenges without file_paths should not show files= tag."""
        bb = Blackboard()
        bb.apply(ChallengeIdentified(
            challenge_name="NoFiles",
            category="misc",
        ))
        prompt = bb.to_context_prompt()
        assert "NoFiles" in prompt
        assert "files=" not in prompt


# ═══════════════════════════════════════════════════════════════════
#  Fix #4: Sub-mission blackboard seeded with file_paths
# ═══════════════════════════════════════════════════════════════════


class TestSubMissionBlackboardSeeding:
    @pytest.mark.asyncio
    async def test_sub_mission_prompt_includes_file_paths(self, store):
        """Sub-mission prompt should include challenge attachment paths."""
        mock = PrepareAwareCoordinator()
        topo = FanoutTopology(
            max_parallel=1, max_iterations_per_challenge=1, coordinator=mock,
        )

        mission = Mission(
            mission_type=MissionType.CTF,
            target=Target(uri="http://test", kind="url"),
            topology="fanout",
            options={
                "challenges": [
                    {"name": "Easy-Gin", "target": "http://127.0.0.1:8080", "category": "web"},
                ],
            },
        )
        mission.start()

        bb = Blackboard()
        events: list[DomainEvent] = []
        async for ev in topo.execute(mission, bb, {"web": _fake_agent()}, store):
            events.append(ev)

        # The sub-mission prompt should reference the attachment files
        solve_calls = [c for c in mock.calls if "Easy-Gin" in c and "Solve" in c]
        # At least one solve call should mention the file paths
        assert any("/challenges/easy-gin/app.py" in c for c in solve_calls), (
            f"Expected file paths in solve prompt, got: {solve_calls}"
        )


# ═══════════════════════════════════════════════════════════════════
#  PREPARE phase tests
# ═══════════════════════════════════════════════════════════════════


class TestPreparePhase:
    @pytest.mark.asyncio
    async def test_prepare_runs_with_general_instructions(self, store):
        """PREPARE phase should run when general_instructions are provided."""
        mock = PrepareAwareCoordinator()
        topo = FanoutTopology(
            max_parallel=1, max_iterations_per_challenge=1, coordinator=mock,
        )

        mission = Mission(
            mission_type=MissionType.CTF,
            target=Target(uri="http://test", kind="url"),
            topology="fanout",
            options={
                "general_instructions": ["git checkout bench", "pip install -r requirements.txt"],
                "challenges": [
                    {"name": "Easy-Gin", "target": "http://127.0.0.1:8080", "category": "web"},
                ],
            },
        )
        mission.start()

        bb = Blackboard()
        events: list[DomainEvent] = []
        async for ev in topo.execute(mission, bb, {"web": _fake_agent()}, store):
            events.append(ev)

        # Should have PREPARE phase transition
        prepare_phases = [e for e in events
                         if isinstance(e, PhaseTransition) and e.to_phase == "prepare"]
        assert len(prepare_phases) == 1

        # Should have called coordinator with PREPARE prompt containing instructions
        prepare_calls = [c for c in mock.calls if "preparation assistant" in c.lower()
                         or "General Instructions" in c]
        assert len(prepare_calls) >= 1

    @pytest.mark.asyncio
    async def test_prepare_discovers_file_paths(self, store):
        """PREPARE phase should discover file_paths and populate blackboard."""
        mock = PrepareAwareCoordinator()
        topo = FanoutTopology(
            max_parallel=1, max_iterations_per_challenge=1, coordinator=mock,
        )

        mission = Mission(
            mission_type=MissionType.CTF,
            target=Target(uri="http://test", kind="url"),
            topology="fanout",
            options={
                "challenges": [
                    {"name": "Easy-Gin", "target": "http://127.0.0.1:8080", "category": "web"},
                    {"name": "Baby-Pwn", "target": "http://127.0.0.1:9090", "category": "pwn"},
                ],
            },
        )
        mission.start()

        bb = Blackboard()
        events: list[DomainEvent] = []
        async for ev in topo.execute(
            mission, bb, {"web": _fake_agent(), "pwn": _fake_agent("pwn", "pwn")}, store,
        ):
            events.append(ev)

        # Challenges should have file_paths from PREPARE discovery
        identified = [e for e in events if isinstance(e, ChallengeIdentified)]
        gin_ids = [e for e in identified if e.challenge_name == "Easy-Gin"]
        assert len(gin_ids) >= 1
        assert any(e.file_paths for e in gin_ids), "Easy-Gin should have file_paths from PREPARE"

    @pytest.mark.asyncio
    async def test_no_prepare_without_triggers(self, store):
        """PREPARE should NOT run without general_instructions or predefined challenges."""
        mock = PrepareAwareCoordinator()
        topo = FanoutTopology(
            max_parallel=1, max_iterations_per_challenge=1, coordinator=mock,
        )

        mission = Mission(
            mission_type=MissionType.CTF,
            target=Target(uri="http://ctf.example.com", kind="url"),
            topology="fanout",
            # No challenges, no general_instructions
        )
        mission.start()

        bb = Blackboard()
        events: list[DomainEvent] = []
        async for ev in topo.execute(mission, bb, {"web": _fake_agent()}, store):
            events.append(ev)

        # Should NOT have PREPARE phase
        prepare_phases = [e for e in events
                         if isinstance(e, PhaseTransition) and e.to_phase == "prepare"]
        assert len(prepare_phases) == 0


# ═══════════════════════════════════════════════════════════════════
#  _build_file_map tests
# ═══════════════════════════════════════════════════════════════════


class TestBuildFileMap:
    def test_builds_map_from_challenges_with_paths(self):
        """_build_file_map should extract challenge_name → file_paths."""
        bb = Blackboard()
        bb.apply(ChallengeIdentified(
            challenge_name="ch1",
            category="web",
            file_paths=("/a.py", "/b.py"),
        ))
        bb.apply(ChallengeIdentified(
            challenge_name="ch2",
            category="pwn",
            file_paths=("/vuln",),
        ))

        result = FanoutTopology._build_file_map(bb)
        assert result == {
            "ch1": ["/a.py", "/b.py"],
            "ch2": ["/vuln"],
        }

    def test_empty_file_paths_excluded(self):
        """Challenges without file_paths should not appear in map."""
        bb = Blackboard()
        bb.apply(ChallengeIdentified(
            challenge_name="no_files",
            category="misc",
        ))

        result = FanoutTopology._build_file_map(bb)
        assert result == {}

    def test_empty_blackboard(self):
        """Empty blackboard should return empty map."""
        bb = Blackboard()
        assert FanoutTopology._build_file_map(bb) == {}


# ═══════════════════════════════════════════════════════════════════
#  Fix #5: EVENT_INSTRUCTION no longer references emit_event tool
# ═══════════════════════════════════════════════════════════════════


class TestEventInstruction:
    def test_no_emit_event_tool_reference(self):
        """EVENT_INSTRUCTION should not reference non-existent emit_event tool."""
        from miya.topology.base import EVENT_INSTRUCTION
        assert "emit_event" not in EVENT_INSTRUCTION
        # Should still describe inline markers
        assert "[EVENT:" in EVENT_INSTRUCTION


# ═══════════════════════════════════════════════════════════════════
#  Fix #6: SDKSession fallback (unit-level)
# ═══════════════════════════════════════════════════════════════════


class TestSDKSessionInit:
    def test_session_has_unique_id(self):
        """Each SDKSession should have a unique session_id."""
        s1 = SDKSession({}, [])
        s2 = SDKSession({}, [])
        assert s1._session_id != s2._session_id

    def test_session_custom_id(self):
        """Custom session_id should be preserved."""
        s = SDKSession({}, [], session_id="my-session")
        assert s._session_id == "my-session"

    def test_query_before_connect_raises(self):
        """Calling query() before connect() should raise RuntimeError."""
        import asyncio
        s = SDKSession({}, [])
        with pytest.raises(RuntimeError, match="not connected"):
            asyncio.get_event_loop().run_until_complete(s.query("test"))


# ═══════════════════════════════════════════════════════════════════
#  Fix #7: PREPARE max_turns
# ═══════════════════════════════════════════════════════════════════


class TestPrepareMaxTurns:
    @pytest.mark.asyncio
    async def test_prepare_uses_run_with_max_turns(self, store):
        """PREPARE phase should pass max_turns to _run."""
        calls_with_kwargs: list[dict] = []
        original_run = FanoutTopology._run

        async def patched_run(self, prompt, agents, blackboard, max_turns=None):
            calls_with_kwargs.append({"max_turns": max_turns, "prompt_snippet": prompt[:80]})
            return await original_run(self, prompt, agents, blackboard, max_turns=max_turns)

        mock = PrepareAwareCoordinator()
        topo = FanoutTopology(
            max_parallel=1, max_iterations_per_challenge=1, coordinator=mock,
        )

        mission = Mission(
            mission_type=MissionType.CTF,
            target=Target(uri="http://test", kind="url"),
            topology="fanout",
            options={
                "challenges": [
                    {"name": "Easy-Gin", "target": "http://127.0.0.1:8080", "category": "web"},
                ],
            },
        )
        mission.start()

        bb = Blackboard()
        # Monkey-patch _run to capture max_turns
        import types
        topo._run = types.MethodType(patched_run, topo)

        async for ev in topo.execute(mission, bb, {"web": _fake_agent()}, store):
            pass

        # Find the PREPARE call
        prepare_calls = [c for c in calls_with_kwargs
                         if "preparation assistant" in c["prompt_snippet"].lower()
                         or "Discover" in c["prompt_snippet"]]
        assert len(prepare_calls) >= 1
        assert prepare_calls[0]["max_turns"] == 50


# ═══════════════════════════════════════════════════════════════════
#  Hybrid OODA mode tests (via mock coordinator)
# ═══════════════════════════════════════════════════════════════════


class TestOODAHybridMode:
    """Test OODA topology behavior with coordinator mock (non-session path)."""

    @pytest.mark.asyncio
    async def test_ctf_ooda_uses_observe_act_reflect(self, store):
        """CTF OODA should run OBSERVE, ACT (skipping ORIENT/DECIDE), REFLECT."""
        from miya.topology.ooda import OODATopology

        mock = PrepareAwareCoordinator()
        ooda = OODATopology(max_iterations=1, coordinator=mock)

        mission = Mission(
            mission_type=MissionType.CTF,
            target=Target(uri="http://127.0.0.1:8080", kind="url"),
            topology="ooda",
            prompt="Solve Easy-Gin",
        )
        mission.start()

        bb = Blackboard()
        events: list[DomainEvent] = []
        async for ev in ooda.execute(
            mission, bb, {"web": _fake_agent()}, store,
        ):
            events.append(ev)

        phases = [e for e in events if isinstance(e, PhaseTransition)]
        phase_names = [p.to_phase for p in phases]

        # CTF should have OBSERVE and ACT but NOT ORIENT or DECIDE
        assert "observe" in phase_names
        assert "act" in phase_names
        assert "orient" not in phase_names
        assert "decide" not in phase_names

    @pytest.mark.asyncio
    async def test_ooda_reflection_parsing(self, store):
        """OODA should correctly parse DECISION from reflect output."""
        from miya.topology.ooda import OODATopology

        result = OODATopology._parse_reflection(
            "DECISION: complete\n"
            "ASSESSMENT: Found the flag\n"
            "INSIGHTS: SQL injection in login form\n"
            "NEXT_FOCUS: n/a"
        )
        assert result["decision"] == "complete"
        assert "Found the flag" in result["assessment"]
        assert "SQL injection" in result["insights"]


# ═══════════════════════════════════════════════════════════════════
#  Integration: full fanout with PREPARE + file_paths + solve
# ═══════════════════════════════════════════════════════════════════


class TestFanoutPrepareIntegration:
    @pytest.mark.asyncio
    async def test_full_flow_prepare_to_solve(self, store):
        """Full fanout: PREPARE discovers files → sub-missions get file_paths → solve."""
        mock = PrepareAwareCoordinator()
        topo = FanoutTopology(
            max_parallel=2, max_iterations_per_challenge=1, coordinator=mock,
        )

        mission = Mission(
            mission_type=MissionType.CTF,
            target=Target(uri="http://ctf.local", kind="url"),
            topology="fanout",
            options={
                "general_instructions": ["git checkout bench"],
                "challenges": [
                    {"name": "Easy-Gin", "target": "http://127.0.0.1:8080", "category": "web"},
                    {"name": "Baby-Pwn", "target": "http://127.0.0.1:9090", "category": "pwn"},
                ],
            },
        )
        mission.start()

        bb = Blackboard()
        events: list[DomainEvent] = []
        async for ev in topo.execute(
            mission, bb,
            {"web": _fake_agent(), "pwn": _fake_agent("pwn", "pwn")},
            store,
        ):
            events.append(ev)

        # Should have PREPARE → ENUMERATE → CLASSIFY → FANOUT → COLLECT
        phases = [e for e in events if isinstance(e, PhaseTransition)]
        phase_names = [p.to_phase for p in phases]
        assert "prepare" in phase_names

        # Should have solved challenges
        solved = [e for e in events if isinstance(e, ChallengeSolved)]
        solved_names = {e.challenge_name for e in solved}
        # At least one challenge should be solved
        assert len(solved) >= 1

        # Mission should complete
        completed = [e for e in events if isinstance(e, MissionCompleted)]
        assert len(completed) == 1
