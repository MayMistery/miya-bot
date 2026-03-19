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
import os
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

_ENUMERATE_PROMPT = (
    "Enumerate all CTF challenges on this platform.\n\n"
    "Target: {target}\n"
    "{operator_hint}\n\n"
    "For each challenge, report:\n"
    '[EVENT:ChallengeIdentified {{"challenge_name": "...", "category": "web|pwn|crypto|reverse|misc", "points": 0, "context": "ctf"}}]\n\n'
    "List every challenge you can find. Use the platform's API, web interface, or challenge list page.\n"
)

_CLASSIFY_BATCH_PROMPT = (
    "Classify these CTF challenges by category.\n\n"
    "Challenges:\n{challenge_list}\n\n"
    "For each, respond with:\n"
    '[EVENT:ChallengeClassified {{"challenge_name": "...", "category": "web|pwn|crypto|reverse|misc", "confidence": 0.8, "reasoning": "...", "context": "ctf"}}]\n'
)

_PREPARE_PROMPT = """\
You are a CTF competition preparation assistant. Your job is to set up the \
environment before challenge solving begins.

## Working Directory
{cwd}

## Challenges to Solve
{challenge_list}

{general_instructions_section}

## Phase 1: Execute General Instructions
{general_instructions_detail}

## Phase 2: Discover Challenge Attachments
Explore the working directory and subdirectories to find attachment files \
(source code, binaries, archives, docker-compose, Dockerfiles, etc.) for \
each challenge listed above. Use Glob, Read, Bash (ls, find, file) as needed.

**Matching strategies** (try in order):
1. Directories named after challenges (exact or fuzzy match)
2. Archive files (.zip, .tar.gz) containing challenge names
3. Files with challenge-related names in common CTF directory structures
4. Docker/container files that reference challenge names or ports

## Output Format
For EACH challenge, emit an event with the discovered file paths:
[EVENT:ChallengeIdentified {{"challenge_name": "...", "category": "...", \
"file_paths": ["/absolute/path/to/file1", "/absolute/path/to/dir/"], "context": "ctf"}}]

If no attachments are found for a challenge, still emit the event with an \
empty file_paths array.

IMPORTANT: Use absolute paths. Include directories (with trailing /) if the \
entire directory is relevant to the challenge.
"""


def _validate_challenges(raw: Any) -> list[dict[str, Any]] | None:
    """Validate and normalise the ``challenges`` option.

    Accepts:
    - ``None`` → ``None`` (no predefined challenges).
    - ``list[dict]`` → returned as-is.
    - A JSON string (can happen if the interactive editor round-tripped
      through ``str()``) → parsed back into ``list[dict]``.
    - Anything else → ``None`` with a warning.

    Each item must be a dict with at least a ``name`` key.  Items that
    fail validation are logged and skipped.
    """
    if raw is None:
        return None

    items: list[Any] | None = None

    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, str):
        # Attempt JSON parse (handles accidental stringification)
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                items = parsed
            else:
                logger.warning(
                    "challenges option is a JSON string but not a list — ignoring"
                )
                return None
        except (json.JSONDecodeError, ValueError):
            logger.warning(
                "challenges option is a non-JSON string — ignoring "
                "(first 80 chars: %s)", raw[:80],
            )
            return None
    else:
        logger.warning(
            "challenges option has unexpected type %s — ignoring",
            type(raw).__name__,
        )
        return None

    # Validate each item is a dict with a name
    valid: list[dict[str, Any]] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            logger.warning(
                "challenges[%d] is %s, expected dict — skipping",
                i, type(item).__name__,
            )
            continue
        if "name" not in item:
            logger.warning("challenges[%d] has no 'name' key — skipping", i)
            continue
        valid.append(item)

    return valid if valid else None


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

        # ── Phase 0: PREPARE (general setup + attachment discovery) ──
        general_instructions = mission.options.get("general_instructions", [])
        predefined = _validate_challenges(mission.options.get("challenges"))

        # Run PREPARE phase when there are general instructions OR
        # pre-defined challenges that need attachment discovery
        if general_instructions or predefined:
            async for ev in self._run_prepare(
                mission, agents, blackboard, general_instructions, predefined,
            ):
                yield ev

        # ── Phase 1: ENUMERATE (or use pre-defined challenges) ───
        challenges: list[dict[str, Any]] = []

        if predefined and isinstance(predefined, list):
            # Challenges enriched by PREPARE phase (file_paths from blackboard)
            prepare_file_map = self._build_file_map(blackboard)

            logger.info("▶ ENUMERATE — skipped (user provided %d challenges)", len(predefined))
            yield PhaseTransition(
                to_phase="enumerate",
                reason=f"Using {len(predefined)} user-provided challenge(s)",
                aggregate_id=mission.id,
                mission=mission.mission_type.value,
            )
            for ch in predefined:
                ch_name = ch.get("name", "challenge")
                ch_target = ch.get("target", mission.target.uri)
                ch_cat = ch.get("category", "")
                # Merge file_paths from PREPARE discovery
                ch_files = prepare_file_map.get(ch_name, [])
                challenges.append({
                    "name": ch_name,
                    "target": ch_target,
                    "category": ch_cat,
                    "points": ch.get("points", 0),
                    "file_paths": ch_files,
                })
                # Only emit ChallengeIdentified if PREPARE didn't already
                if ch_name not in prepare_file_map:
                    ev = ChallengeIdentified(
                        challenge_name=ch_name,
                        category=ch_cat,
                        points=ch.get("points", 0),
                        context="ctf",
                        mission="ctf",
                    )
                    yield ev
                    blackboard.apply(ev)

            # ── Pre-flight connectivity probe ──────────────────
            reachable, unreachable = await self._probe_targets(challenges)
            if unreachable:
                logger.warning(
                    "Unreachable challenges: %s",
                    ", ".join(f"{c['name']} ({c['target']})" for c in unreachable),
                )
            if reachable:
                logger.info(
                    "Pre-flight: %d/%d targets reachable",
                    len(reachable), len(challenges),
                )
        else:
            # No pre-defined list — discover via agent
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

            for ev in extract_events_from_output(enum_output, mission):
                yield ev
                blackboard.apply(ev)
                if isinstance(ev, ChallengeIdentified):
                    challenges.append({
                        "name": ev.challenge_name,
                        "category": ev.category,
                        "points": ev.points,
                        "file_paths": list(ev.file_paths),
                    })

            # If no challenges discovered via events, try a minimal fallback:
            # treat the single target as one challenge
            if not challenges:
                logger.info("No challenges enumerated — treating target as single challenge")
                challenges = [{
                    "name": "challenge",
                    "category": "",
                    "points": 0,
                    "file_paths": [],
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
                # Use per-challenge target URL if available, else fall back to mission target
                ch_target = challenge.get("target", mission.target.uri)
                ch_files = challenge.get("file_paths", [])

                # Build challenge-specific prompt (NO general instructions leak)
                sub_prompt = f"Solve challenge: {ch_name}."
                if ch_files:
                    sub_prompt += f"\nChallenge attachments: {', '.join(ch_files)}"

                sub_mission = Mission(
                    mission_type=MissionType.CTF,
                    target=Target(uri=ch_target, kind="challenge"),
                    topology="ooda",
                    prompt=sub_prompt,
                    options={
                        "challenge_name": ch_name,
                        "category": ch_cat,
                        "file_paths": ch_files,
                    },
                )
                sub_mission.start()

                sub_bb = Blackboard()
                # Seed sub-blackboard with challenge context
                if ch_files:
                    from miya.shared.blackboard import ChallengeView
                    sub_bb.challenges.append(ChallengeView(
                        name=ch_name,
                        category=ch_cat,
                        file_paths=tuple(ch_files),
                    ))
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

    async def _run_prepare(
        self,
        mission: Mission,
        agents: dict[str, AgentHandle],
        blackboard: Blackboard,
        general_instructions: list[str],
        predefined: list[dict[str, Any]] | None,
    ) -> AsyncIterator[DomainEvent]:
        """PREPARE phase: execute general setup commands + discover challenge attachments.

        Runs in a single SDK coordinator call. Emits ChallengeIdentified events
        with file_paths populated from filesystem exploration.
        """
        # Build a human-readable summary for the phase transition
        prepare_details: list[str] = []
        if general_instructions:
            prepare_details.append(
                f"general instructions ({len(general_instructions)}): "
                + "; ".join(general_instructions[:3])
                + ("..." if len(general_instructions) > 3 else "")
            )
        if predefined:
            targets_summary = ", ".join(
                f"{ch.get('name', '?')} → {ch.get('target', '?')}"
                for ch in predefined
            )
            prepare_details.append(f"challenges: {targets_summary}")

        reason = "Environment setup + attachment discovery"
        if prepare_details:
            reason += " | " + " | ".join(prepare_details)

        yield PhaseTransition(
            to_phase="prepare",
            reason=reason,
            aggregate_id=mission.id,
            mission=mission.mission_type.value,
        )
        logger.info("▶ PREPARE — environment setup + attachment discovery")
        if predefined:
            for ch in predefined:
                logger.info(
                    "  challenge: %s → %s",
                    ch.get("name", "?"), ch.get("target", "?"),
                )

        # Build challenge list section for the prompt
        if predefined:
            ch_lines = []
            for ch in predefined:
                name = ch.get("name", "?")
                target = ch.get("target", "?")
                cat = ch.get("category", "")
                line = f"- {name} (target: {target})"
                if cat:
                    line += f" [category: {cat}]"
                ch_lines.append(line)
            challenge_list = "\n".join(ch_lines)
        else:
            challenge_list = "(No predefined challenges — discover from filesystem)"

        # Build general instructions sections
        if general_instructions:
            gi_section = "## General Instructions (execute these first)\n"
            gi_detail = (
                "Execute these commands/actions in order. For DESTRUCTIVE operations "
                "(delete, reset --hard, force push, drop, rm -rf), list them and ask "
                "for confirmation before executing.\n\n"
                + "\n".join(f"{i+1}. {instr}" for i, instr in enumerate(general_instructions))
            )
        else:
            gi_section = ""
            gi_detail = "No general instructions — skip to attachment discovery."

        prepare_prompt = _PREPARE_PROMPT.format(
            cwd=os.getcwd(),
            challenge_list=challenge_list,
            general_instructions_section=gi_section,
            general_instructions_detail=gi_detail,
        ) + EVENT_INSTRUCTION

        prepare_output = await self._run(prepare_prompt, agents, blackboard, max_turns=50)

        for ev in extract_events_from_output(prepare_output, mission):
            yield ev
            blackboard.apply(ev)

        logger.info("PREPARE phase complete")

    @staticmethod
    def _build_file_map(blackboard: Blackboard) -> dict[str, list[str]]:
        """Build a map of challenge_name → file_paths from blackboard state.

        Used to merge PREPARE discoveries into the challenge definitions.
        """
        result: dict[str, list[str]] = {}
        for ch_view in blackboard.challenges:
            if ch_view.file_paths:
                result[ch_view.name] = list(ch_view.file_paths)
        return result

    async def _probe_targets(
        self,
        challenges: list[dict[str, Any]],
        timeout: float = 5.0,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Pre-flight connectivity check for challenge targets.

        Returns (reachable, unreachable) lists.
        """
        reachable: list[dict[str, Any]] = []
        unreachable: list[dict[str, Any]] = []

        async def _check(ch: dict[str, Any]) -> None:
            target = ch.get("target", "")
            if not target:
                unreachable.append(ch)
                return
            try:
                # Parse host:port from URL
                from urllib.parse import urlparse
                parsed = urlparse(target)
                host = parsed.hostname or ""
                port = parsed.port or 80
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout,
                )
                writer.close()
                await writer.wait_closed()
                reachable.append(ch)
            except Exception:
                unreachable.append(ch)

        await asyncio.gather(*(_check(ch) for ch in challenges), return_exceptions=True)
        return reachable, unreachable

    async def _run(
        self,
        prompt: str,
        agents: dict[str, AgentHandle],
        blackboard: Blackboard,
        max_turns: int | None = None,
    ) -> str:
        """Run coordinator with all agents."""
        all_mcp_names: set[str] = set()
        for handle in agents.values():
            all_mcp_names.update(handle.mcp_servers)
        agent_defs = {
            name: handle.to_agent_definition()
            for name, handle in agents.items()
        }
        # Use injected coordinator (for testing) or SDK
        if self._coordinator is not None:
            return await self._coordinator.run(prompt, agent_defs, list(all_mcp_names))
        return await run_sdk_coordinator(prompt, agent_defs, list(all_mcp_names), max_turns=max_turns)


# ── Register ──────────────────────────────────────────────────────

TopologyRegistry.register("fanout", FanoutTopology)
