"""Fan-out Topology — parallel challenge solving for CTF competitions.

Designed for multi-challenge CTF scenarios:
1. ENUMERATE: discover all challenges on the platform
2. CLASSIFY: auto-detect each challenge's category
3. FAN-OUT: spawn parallel OODA loops, one per challenge
4. COLLECT: aggregate results, share knowledge via Campaign

Architecture:
    ┌─────────────┐
    │  ENUMERATE   │ → discover challenge list
    └──────┬──────┘
           │
    ┌──────▼──────┐
    │  CLASSIFY    │ → categorize each challenge
    └──────┬──────┘
           │
    ┌──────▼──────────────────────────┐
    │  FAN-OUT (parallel OODA loops)  │
    │  ┌────┐ ┌────┐ ┌────┐ ┌────┐   │
    │  │web │ │pwn │ │cry │ │rev │   │
    │  └────┘ └────┘ └────┘ └────┘   │
    └──────┬──────────────────────────┘
           │
    ┌──────▼──────┐
    │   COLLECT    │ → aggregate flags & report
    └─────────────┘
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, AsyncIterator

from miya.shared.blackboard import Blackboard
from miya.shared.campaign import Campaign
from miya.shared.events import (
    DomainEvent,
    MissionStarted,
    MissionCompleted,
    ChallengeIdentified,
    ChallengeClassified,
    ChallengeSolved,
    PhaseTransition,
)
from miya.shared.ports import EventStorePort
from miya.shared.types import Mission, MissionType, Target
from miya.topology.base import (
    Topology,
    TopologyRegistry,
    AgentHandle,
    extract_events_from_output,
    EVENT_INSTRUCTION,
    run_sdk_coordinator,
    _get_topology_config,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
#  Prompts — minimal by design
# ═══════════════════════════════════════════════════════════════════

_ENUMERATE_PROMPT = """Enumerate all CTF challenges on this platform.

Target: {target}
{operator_hint}

For each challenge, report:
[EVENT:ChallengeIdentified {"challenge_name": "...", "category": "web|pwn|crypto|reverse|misc", "points": 0, "context": "ctf"}]

List every challenge you can find. Use the platform's API, web interface, or challenge list page.
"""

_CLASSIFY_BATCH_PROMPT = """Classify these CTF challenges by category.

Challenges:
{challenge_list}

For each, respond with:
[EVENT:ChallengeClassified {"challenge_name": "...", "category": "web|pwn|crypto|reverse|misc", "confidence": 0.8, "reasoning": "...", "context": "ctf"}]
"""


# ═══════════════════════════════════════════════════════════════════
#  Fan-out Topology
# ═══════════════════════════════════════════════════════════════════


class FanoutTopology:
    """Parallel challenge-solving topology for CTF competitions.

    Enumerates challenges, classifies them, then runs parallel OODA
    loops — one per challenge — with a shared campaign for knowledge
    cross-pollination.
    """

    def __init__(
        self,
        max_parallel: int = 3,
        max_iterations_per_challenge: int = 5,
        per_challenge_timeout: float = 1800.0,  # 30 minutes default
        coordinator: Any | None = None,
    ) -> None:
        self._max_parallel = max_parallel
        self._max_iter = max_iterations_per_challenge
        self._per_challenge_timeout = per_challenge_timeout
        self._coordinator = coordinator

    @property
    def name(self) -> str:
        return "fanout"

    @property
    def description(self) -> str:
        return (
            "Fan-out topology — parallel OODA loops for multi-challenge CTF. "
            "Enumerates challenges, classifies, then solves them concurrently."
        )

    async def execute(
        self,
        mission: Mission,
        blackboard: Blackboard,
        agents: dict[str, AgentHandle],
        event_store: EventStorePort,
        operator_queue: asyncio.Queue[str] | None = None,
        campaign: Any | None = None,
    ) -> AsyncIterator[DomainEvent]:
        """Run the fan-out topology."""
        from miya.topology.ooda import OODATopology

        # ── Mission Start ─────────────────────────────────────────
        start_event = MissionStarted(
            aggregate_id=mission.id,
            aggregate_type="Mission",
            mission_type=mission.mission_type.value,
            target_uri=mission.target.uri,
            topology=self.name,
            mission=mission.mission_type.value,
        )
        yield start_event
        blackboard.apply(start_event)

        operator_hint = f"Operator: {mission.prompt}" if mission.prompt else ""

        # ── Phase 1: ENUMERATE ────────────────────────────────────
        yield PhaseTransition(
            to_phase="enumerate",
            reason="Discovering challenges on the platform",
            aggregate_id=mission.id,
            mission=mission.mission_type.value,
        )
        logger.info("▶ ENUMERATE — discovering challenges")

        enum_prompt = _ENUMERATE_PROMPT.format(
            target=mission.target.uri,
            operator_hint=operator_hint,
        ) + EVENT_INSTRUCTION

        enum_output = await self._run(enum_prompt, agents, blackboard)

        challenges: list[dict[str, Any]] = []
        for ev in extract_events_from_output(enum_output, mission):
            yield ev
            blackboard.apply(ev)
            if isinstance(ev, ChallengeIdentified):
                challenges.append({
                    "name": ev.challenge_name,
                    "category": ev.category,
                    "points": ev.points,
                })

        # If no challenges discovered via events, try a minimal fallback:
        # treat the single target as one challenge
        if not challenges:
            logger.info("No challenges enumerated — treating target as single challenge")
            challenges = [{
                "name": "challenge",
                "category": "",
                "points": 0,
            }]

        logger.info("Discovered %d challenge(s)", len(challenges))

        # ── Phase 2: CLASSIFY (batch) ─────────────────────────────
        unclassified = [c for c in challenges if not c.get("category")]
        if unclassified:
            yield PhaseTransition(
                from_phase="enumerate",
                to_phase="classify",
                reason=f"Classifying {len(unclassified)} challenge(s)",
                aggregate_id=mission.id,
                mission=mission.mission_type.value,
            )
            logger.info("▶ CLASSIFY — categorizing %d challenges", len(unclassified))

            challenge_list = "\n".join(
                f"- {c['name']} ({c.get('points', '?')}pts)" for c in unclassified
            )
            classify_prompt = _CLASSIFY_BATCH_PROMPT.format(
                challenge_list=challenge_list,
            ) + EVENT_INSTRUCTION
            classify_output = await self._run(classify_prompt, agents, blackboard)

            for ev in extract_events_from_output(classify_output, mission):
                yield ev
                blackboard.apply(ev)
                if isinstance(ev, ChallengeClassified):
                    for c in challenges:
                        if c["name"] == ev.challenge_name:
                            c["category"] = ev.category

        # Skip already-solved challenges (campaign awareness)
        if isinstance(campaign, Campaign):
            unsolved = [c for c in challenges if not campaign.is_solved(c["name"])]
            skipped = len(challenges) - len(unsolved)
            if skipped:
                logger.info("Skipping %d already-solved challenge(s)", skipped)
            challenges = unsolved

        if not challenges:
            logger.info("All challenges already solved!")
            yield MissionCompleted(
                aggregate_id=mission.id,
                findings_count=len(blackboard.findings),
                mission=mission.mission_type.value,
            )
            return

        # ── Phase 3: FAN-OUT — parallel OODA loops ────────────────
        yield PhaseTransition(
            from_phase="classify",
            to_phase="fanout",
            reason=f"Launching {len(challenges)} parallel solver(s), max {self._max_parallel} concurrent",
            aggregate_id=mission.id,
            mission=mission.mission_type.value,
        )
        logger.info(
            "▶ FAN-OUT — %d challenges, %d parallel slots",
            len(challenges), self._max_parallel,
        )

        # Semaphore for concurrency control
        sem = asyncio.Semaphore(self._max_parallel)
        event_queue: asyncio.Queue[DomainEvent | None] = asyncio.Queue()

        # Event types from sub-OODA that should NOT pollute the main mission
        _SUB_MISSION_FILTER = {"mission.started", "mission.completed", "mission.failed"}

        async def _solve_challenge(challenge: dict[str, Any]) -> None:
            """Solve a single challenge using a dedicated OODA loop."""
            async with sem:
                ch_name = challenge["name"]
                ch_cat = challenge.get("category", "")
                logger.info("  → Solving: %s (%s)", ch_name, ch_cat or "unknown")

                # Create sub-mission for this challenge
                sub_mission = Mission(
                    mission_type=MissionType.CTF,
                    target=Target(uri=mission.target.uri, kind="challenge"),
                    topology="ooda",
                    prompt=f"Solve challenge: {ch_name}. " + (mission.prompt or ""),
                    options={"challenge_name": ch_name, "category": ch_cat},
                )
                sub_mission.start()

                sub_bb = Blackboard()
                # Seed with classification if available
                if ch_cat:
                    from miya.shared.blackboard import ClassificationView
                    sub_bb.classification = ClassificationView(
                        category=ch_cat,
                        confidence=0.8,
                        reasoning="from enumerate phase",
                    )

                # Select agent subset based on category
                sub_agents = agents
                if ch_cat:
                    from miya.topology.ooda import OODATopology as _OT
                    direct = _OT._pick_direct_agent(ch_cat, agents)
                    if direct:
                        sub_agents = direct

                ooda = OODATopology(
                    max_iterations=self._max_iter,
                    coordinator=self._coordinator,
                )

                try:
                    async def _run_ooda() -> None:
                        async for ev in ooda.execute(
                            sub_mission, sub_bb, sub_agents, event_store,
                            campaign=campaign,
                        ):
                            # Filter out sub-mission lifecycle events to avoid
                            # polluting the parent mission's event stream (BUG-2)
                            if ev.__class__.event_type not in _SUB_MISSION_FILTER:
                                await event_queue.put(ev)

                    await asyncio.wait_for(
                        _run_ooda(),
                        timeout=self._per_challenge_timeout,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "Challenge %s timed out after %.0fs",
                        ch_name, self._per_challenge_timeout,
                    )
                except Exception:
                    logger.error("Challenge %s failed", ch_name, exc_info=True)

        # Launch all challenge solvers
        tasks = [
            asyncio.create_task(_solve_challenge(c))
            for c in challenges
        ]

        # Use a sentinel to signal completion instead of polling (BUG-1 fix)
        _SENTINEL = None

        async def _wait_all() -> None:
            await asyncio.gather(*tasks, return_exceptions=True)
            await event_queue.put(_SENTINEL)

        waiter = asyncio.create_task(_wait_all())

        # Drain events until sentinel received — no race condition
        while True:
            ev = await event_queue.get()
            if ev is None:
                break
            yield ev
            blackboard.apply(ev)

        await waiter  # ensure cleanup

        # ── Phase 4: COLLECT — final report ───────────────────────
        yield PhaseTransition(
            from_phase="fanout",
            to_phase="collect",
            reason="Aggregating results",
            aggregate_id=mission.id,
            mission=mission.mission_type.value,
        )

        solved_count = len(blackboard.solved_flags)
        total_count = len(challenges)
        logger.info(
            "▶ COLLECT — Solved %d/%d challenges",
            solved_count, total_count,
        )

        yield MissionCompleted(
            aggregate_id=mission.id,
            findings_count=len(blackboard.findings),
            mission=mission.mission_type.value,
        )

    async def _run(
        self,
        prompt: str,
        agents: dict[str, AgentHandle],
        blackboard: Blackboard,
    ) -> str:
        """Run coordinator with all agents."""
        all_mcp_names: set[str] = set()
        for handle in agents.values():
            all_mcp_names.update(handle.mcp_servers)
        agent_defs = {
            name: handle.to_agent_definition()
            for name, handle in agents.items()
        }
        return await run_sdk_coordinator(prompt, agent_defs, list(all_mcp_names))


# ── Register ──────────────────────────────────────────────────────

TopologyRegistry.register("fanout", FanoutTopology)
