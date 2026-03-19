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
from typing import Any, AsyncIterator

from miya.shared.blackboard import Blackboard
from miya.shared.campaign import Campaign
from miya.shared.events import (
    DomainEvent,
    MissionStarted,
    MissionCompleted,
    ChallengeIdentified,
    ChallengeClassified,
    PhaseTransition,
    TargetUnreachable,
)
from miya.shared.ports import EventStorePort
from miya.shared.types import Mission, MissionType, Target
from miya.topology.base import (
    TopologyRegistry,
    AgentHandle,
    extract_events_from_output,
    EVENT_INSTRUCTION,
    run_sdk_coordinator,
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
        max_parallel: int | None = None,
        max_iterations_per_challenge: int = 5,
        per_challenge_timeout: float | None = None,
        coordinator: Any | None = None,
    ) -> None:
        from miya.topology.base import _get_topology_config
        cfg = _get_topology_config()
        self._max_parallel = max_parallel if max_parallel is not None else cfg["fanout_parallel"]
        self._max_iter = max_iterations_per_challenge
        self._per_challenge_timeout = per_challenge_timeout if per_challenge_timeout is not None else float(cfg["fanout_timeout"])
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
            if reachable:
                logger.info(
                    "Pre-flight: %d/%d targets reachable",
                    len(reachable), len(challenges),
                )
            if unreachable:
                # Yield TargetUnreachable events so the operator sees them
                for uc in unreachable:
                    ev = TargetUnreachable(
                        challenge_name=uc["name"],
                        target_url=uc.get("target", ""),
                        error="TCP connect failed",
                        aggregate_id=mission.id,
                        mission=mission.mission_type.value,
                    )
                    yield ev
                    blackboard.apply(ev)

                # ── HITL decision: block until operator responds ──
                challenges = await self._handle_unreachable(
                    challenges, reachable, unreachable,
                    operator_queue, mission,
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
            "▶ FAN-OUT — %d challenges, %d parallel slots, timeout %dm",
            len(challenges), self._max_parallel,
            self._per_challenge_timeout / 60,
        )

        # ── Rich Live display for parallel progress ───────────
        from miya.topology.fanout_display import FanoutDisplay
        display = FanoutDisplay(
            [dict(ch, _max_iter=self._max_iter) for ch in challenges],
            max_columns=self._max_parallel,
            timeout=self._per_challenge_timeout,
        )

        def _on_progress(challenge_name: str, **kwargs: Any) -> None:
            """Callback from sub-OODAs to update display state."""
            display.update(challenge_name, **kwargs)

        def _on_log(challenge_name: str, line: str) -> None:
            """Callback from sub-OODAs to capture log lines."""
            display.capture_log(challenge_name, line)

        # ── Per-challenge HITL queues ─────────────────────────
        ch_queues: dict[str, asyncio.Queue[str]] = {
            ch["name"]: asyncio.Queue() for ch in challenges
        }

        # ── Per-challenge timeout extension events ────────────
        # Maps challenge_name → asyncio.Event that's set to cancel timeout
        timeout_extensions: dict[str, asyncio.Event] = {
            ch["name"]: asyncio.Event() for ch in challenges
        }

        # Semaphore for concurrency control
        sem = asyncio.Semaphore(self._max_parallel)
        event_queue: asyncio.Queue[DomainEvent | None] = asyncio.Queue()

        # Event types from sub-OODA that should NOT pollute the main mission
        _SUB_MISSION_FILTER = {"mission.started", "mission.completed", "mission.failed"}

        # ── Timeout warning threshold ─────────────────────────
        _WARN_BEFORE = 300.0  # warn 5 minutes before timeout

        async def _solve_challenge(challenge: dict[str, Any]) -> None:
            """Solve a single challenge using a dedicated OODA loop."""
            import time as _time
            async with sem:
                ch_name = challenge["name"]
                ch_cat = challenge.get("category", "")
                now = _time.monotonic()
                timeout_deadline = now + self._per_challenge_timeout

                display.update(ch_name, status="running", started_at=now)
                display.mark_timeout_at(ch_name, timeout_deadline)
                display.log_event(f"\u2192 Solving: {ch_name} ({ch_cat or 'unknown'})")

                ch_target = challenge.get("target", mission.target.uri)
                ch_files = challenge.get("file_paths", [])

                is_whitebox = challenge.get("_whitebox", False)
                sub_prompt = f"Solve challenge: {ch_name}."
                if is_whitebox:
                    sub_prompt += (
                        "\n\n\u26a0 WHITEBOX MODE: The target service is unreachable. "
                        "Analyze source code ONLY. Find vulnerabilities, construct "
                        "exploit payloads, and determine the flag from static analysis. "
                        "Do NOT attempt network connections to the target."
                    )
                    original_target = challenge.get("_original_target", "")
                    if original_target:
                        sub_prompt += f"\nOriginal target (offline): {original_target}"
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
                if ch_files:
                    from miya.shared.blackboard import ChallengeView
                    sub_bb.challenges.append(ChallengeView(
                        name=ch_name, category=ch_cat,
                        file_paths=tuple(ch_files),
                    ))
                if ch_cat:
                    from miya.shared.blackboard import ClassificationView
                    sub_bb.classification = ClassificationView(
                        category=ch_cat, confidence=0.8,
                        reasoning="from enumerate phase",
                    )

                sub_agents = agents
                if ch_cat:
                    from miya.topology.ooda import OODATopology as _OT
                    direct = _OT._pick_direct_agent(ch_cat, agents)
                    if direct:
                        sub_agents = direct

                # Per-challenge HITL queue
                ch_op_queue = ch_queues.get(ch_name)

                ooda = OODATopology(
                    max_iterations=self._max_iter,
                    coordinator=self._coordinator,
                    challenge_tag=ch_name,
                    on_progress=_on_progress,
                    on_log=_on_log,
                )

                async def _run_ooda() -> None:
                    from miya.shared.events import ChallengeSolved
                    async for ev in ooda.execute(
                        sub_mission, sub_bb, sub_agents, event_store,
                        operator_queue=ch_op_queue,
                        campaign=campaign,
                    ):
                        if ev.__class__.event_type not in _SUB_MISSION_FILTER:
                            await event_queue.put(ev)
                        if isinstance(ev, ChallengeSolved):
                            display.update(ch_name, status="solved",
                                           flag=ev.flag, phase="DONE")
                            display.log_event(
                                f"\u2713 {ch_name} SOLVED: {ev.flag[:40]}"
                            )

                # ── Run with timeout + renewal ────────────────
                ooda_task = asyncio.create_task(_run_ooda())
                extend_event = timeout_extensions[ch_name]
                warned = False

                try:
                    while not ooda_task.done():
                        remaining = timeout_deadline - _time.monotonic()

                        if remaining <= 0:
                            # Timeout expired — notify and wait for extension
                            display.update(ch_name, status="timeout", phase="TIMEOUT")
                            display.log_event(
                                f"\u23f0 {ch_name}: timeout! "
                                f"Type 'extend {ch_name}' to add 30m"
                            )

                            # Wait up to 60s for an extend command
                            extend_event.clear()
                            try:
                                await asyncio.wait_for(
                                    extend_event.wait(), timeout=60.0,
                                )
                                # Extended! Reset deadline
                                timeout_deadline = _time.monotonic() + 1800.0
                                display.mark_timeout_at(ch_name, timeout_deadline)
                                display.update(ch_name, status="running",
                                               phase=display._states[ch_name].phase
                                               if ch_name in display._states else "ACT")
                                display.log_event(
                                    f"\u27f3 {ch_name}: extended +30m"
                                )
                                warned = False
                                continue
                            except asyncio.TimeoutError:
                                # No extension — cancel the task
                                ooda_task.cancel()
                                try:
                                    await ooda_task
                                except (asyncio.CancelledError, Exception):
                                    pass
                                display.log_event(
                                    f"\u274c {ch_name}: timed out (no extension)"
                                )
                                logger.warning(
                                    "Challenge %s timed out after %.0fs (no extension)",
                                    ch_name, self._per_challenge_timeout,
                                )
                                return

                        # Warn before timeout
                        if not warned and remaining <= _WARN_BEFORE:
                            display.log_event(
                                f"\u26a0 {ch_name}: {remaining / 60:.0f}m remaining"
                            )
                            warned = True

                        # Wait for task or check interval
                        wait_time = min(remaining, 30.0)
                        done, _ = await asyncio.wait(
                            {ooda_task}, timeout=max(wait_time, 1.0),
                        )
                        if done:
                            # Propagate any exception
                            ooda_task.result()

                except asyncio.CancelledError:
                    ooda_task.cancel()
                    try:
                        await ooda_task
                    except (asyncio.CancelledError, Exception):
                        pass
                    raise
                except Exception:
                    display.update(ch_name, status="failed", phase="FAILED")
                    display.log_event(f"\u274c {ch_name} failed")
                    logger.error("Challenge %s failed", ch_name, exc_info=True)

        # Launch all challenge solvers
        tasks = [
            asyncio.create_task(_solve_challenge(c))
            for c in challenges
        ]

        _SENTINEL = None

        async def _wait_all() -> None:
            await asyncio.gather(*tasks, return_exceptions=True)
            await event_queue.put(_SENTINEL)

        waiter = asyncio.create_task(_wait_all())

        # ── HITL router: dispatch operator messages ───────────
        async def _hitl_router() -> None:
            """Route HITL messages to per-challenge queues or handle commands."""
            if operator_queue is None:
                return
            while True:
                try:
                    msg = await asyncio.wait_for(
                        operator_queue.get(), timeout=1.0,
                    )
                except asyncio.TimeoutError:
                    # Check if all tasks are done
                    if all(t.done() for t in tasks):
                        return
                    continue
                except asyncio.CancelledError:
                    return

                msg = msg.strip()
                if not msg:
                    continue

                # ── Display commands ──────────────────────
                parts = msg.split(None, 1)
                cmd = parts[0].lower()

                if cmd == "help":
                    display.log_event("── HITL Commands ──")
                    display.log_event("  @<name> <msg>     send message to specific challenge")
                    display.log_event("  <msg>             broadcast to all running challenges")
                    display.log_event("  logs <name> [n]   show last n (default 30) log lines")
                    display.log_event("  attach <name>     live-follow a challenge's logs")
                    display.log_event("  detach            return to grid view")
                    display.log_event("  status <name>     show detailed status of a challenge")
                    display.log_event("  extend <name|all> extend timeout +30m")
                    display.log_event("  ref <src> @<dst>  inject src's knowledge into dst")
                    display.log_event("  stop              cancel entire mission")
                    continue

                if cmd == "status" and len(parts) == 1:
                    # No args: reprint the panel grid
                    display._refresh(force=True)
                    continue

                if cmd == "status" and len(parts) > 1:
                    name = parts[1].strip()
                    state = display._states.get(name)
                    if state:
                        display.log_event(
                            f"── {state.status_icon} {name} ──"
                        )
                        display.log_event(
                            f"  Category: {state.category or '?'} | "
                            f"Phase: {state.phase} | "
                            f"Iter: {state.iteration}/{state.max_iterations}"
                        )
                        display.log_event(
                            f"  Status: {state.status} | "
                            f"Elapsed: {state.elapsed} | "
                            f"Remaining: {state.remaining_str or 'N/A'}"
                        )
                        if state.flag:
                            display.log_event(f"  Flag: {state.flag}")
                        if state.last_activity:
                            display.log_event(
                                f"  Last: {state.last_activity}"
                            )
                    else:
                        display.log_event(
                            f"Unknown: {name}. "
                            f"Available: {', '.join(display.challenge_names)}"
                        )
                    continue

                if cmd == "attach" and len(parts) > 1:
                    display.attach(parts[1].strip())
                    continue

                if cmd == "detach":
                    display.detach()
                    continue

                if cmd == "logs" and len(parts) > 1:
                    log_args = parts[1].strip().split()
                    name = log_args[0]
                    n = 30
                    if len(log_args) > 1:
                        try:
                            n = int(log_args[1])
                        except ValueError:
                            pass
                    lines = display.get_logs(name, n=n)
                    display.log_event(
                        f"── logs {name} (last {len(lines)}) ──"
                    )
                    for line in lines:
                        display.log_event(line)
                    continue

                if cmd == "extend":
                    target_name = parts[1].strip() if len(parts) > 1 else "all"
                    ext_parts = target_name.split()
                    name = ext_parts[0]
                    # Parse optional minutes: extend <name> [min]
                    # For now, just signal the event
                    if name.lower() == "all":
                        for evt in timeout_extensions.values():
                            evt.set()
                        display.log_event("Extended all challenges +30m")
                    elif name in timeout_extensions:
                        timeout_extensions[name].set()
                    else:
                        display.log_event(f"Unknown challenge: {name}")
                    continue

                # ── Cross-challenge knowledge: ref <source> @<target> ──
                if cmd == "ref" and len(parts) > 1:
                    ref_parts = parts[1].strip().split()
                    source_name = ref_parts[0]
                    # Optional: ref source @target (default: broadcast)
                    target_name = ref_parts[1].lstrip("@") if len(ref_parts) > 1 else ""

                    # Pull knowledge from source challenge's sub-blackboard
                    source_logs = display.get_logs(source_name, n=50)
                    if not source_logs:
                        display.log_event(
                            f"No logs for '{source_name}'. "
                            f"Available: {', '.join(display.challenge_names)}"
                        )
                        continue

                    # Build knowledge injection message
                    knowledge = (
                        f"## Reference from challenge '{source_name}'\n"
                        f"The following is the progress log from another "
                        f"challenge. Use relevant findings to help solve "
                        f"the current challenge.\n\n"
                        + "\n".join(source_logs[-30:])
                    )
                    if target_name and target_name in ch_queues:
                        ch_queues[target_name].put_nowait(knowledge)
                        display.log_event(
                            f"\U0001f4d6 ref {source_name} → @{target_name}"
                        )
                    else:
                        # Broadcast to all running
                        for n in display.challenge_names:
                            if n != source_name and n in ch_queues:
                                state = display._states.get(n)
                                if state and state.status in ("running", "classifying"):
                                    ch_queues[n].put_nowait(knowledge)
                        display.log_event(
                            f"\U0001f4d6 ref {source_name} → all running"
                        )
                    continue

                # ── Per-challenge HITL: @name message ─────
                if msg.startswith("@"):
                    at_parts = msg[1:].split(None, 1)
                    target_name = at_parts[0] if at_parts else ""
                    hitl_msg = at_parts[1] if len(at_parts) > 1 else ""
                    if target_name in ch_queues and hitl_msg:
                        ch_queues[target_name].put_nowait(hitl_msg)
                        display.log_event(
                            f"\U0001f4e8 @{target_name}: {hitl_msg[:50]}"
                        )
                    elif target_name not in ch_queues:
                        display.log_event(
                            f"Unknown challenge: {target_name}. "
                            f"Available: {', '.join(ch_queues.keys())}"
                        )
                    continue

                # ── Broadcast to all running challenges ───
                running_names = [
                    n for n, s in display._states.items()
                    if s.status in ("running", "classifying")
                ]
                for name in running_names:
                    ch_queues[name].put_nowait(msg)
                if running_names:
                    display.log_event(
                        f"\U0001f4e8 broadcast → {len(running_names)} challenge(s): "
                        f"{msg[:40]}"
                    )

        router_task = asyncio.create_task(_hitl_router())

        # Drain events with display active
        try:
            with display:
                while True:
                    ev = await event_queue.get()
                    if ev is None:
                        break
                    yield ev
                    blackboard.apply(ev)
        except asyncio.CancelledError:
            # Ctrl+C during fanout — cancel all sub-tasks and clean up
            for t in tasks:
                if not t.done():
                    t.cancel()
            raise
        finally:
            router_task.cancel()
            try:
                await router_task
            except asyncio.CancelledError:
                pass
            # Wait for sub-tasks to finish (they may already be cancelled)
            if not waiter.done():
                waiter.cancel()
                try:
                    await waiter
                except (asyncio.CancelledError, Exception):
                    pass

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

        # ── Log PREPARE summary ──────────────────────────────────
        file_map = self._build_file_map(blackboard)
        total_files = sum(len(v) for v in file_map.values())
        if general_instructions:
            logger.info(
                "  executed %d general instruction(s)", len(general_instructions),
            )
        if file_map:
            logger.info(
                "  discovered %d attachment(s) across %d challenge(s)",
                total_files, len(file_map),
            )
            for ch_name, paths in file_map.items():
                logger.info("    %s: %s", ch_name, ", ".join(paths[:5])
                            + (f" (+{len(paths)-5} more)" if len(paths) > 5 else ""))
        elif predefined:
            logger.info("  no attachments discovered for %d challenge(s)", len(predefined))
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

    async def _handle_unreachable(
        self,
        all_challenges: list[dict[str, Any]],
        reachable: list[dict[str, Any]],
        unreachable: list[dict[str, Any]],
        operator_queue: asyncio.Queue[str] | None,
        mission: Mission,
    ) -> list[dict[str, Any]]:
        """Block and wait for operator decision on unreachable targets.

        Operator commands (via HITL queue):
            skip <name>      — remove challenge from solve list
            skip all         — remove all unreachable challenges
            url <name> <url> — update target URL, re-probe
            whitebox <name>  — switch to pure source-code analysis (no network)
            whitebox all     — whitebox all unreachable challenges
            continue         — proceed with all challenges (attempt anyway)

        Returns the updated challenge list.
        """
        unreachable_names = {c["name"] for c in unreachable}

        logger.warning(
            "⚠ %d/%d targets unreachable — waiting for operator decision:",
            len(unreachable), len(all_challenges),
        )
        for uc in unreachable:
            logger.warning(
                "  ✗ %s → %s", uc["name"], uc.get("target", "(no target)"),
            )
        logger.info(
            "  Commands: skip <name|all> | url <name> <new_url> | "
            "whitebox <name|all> | continue"
        )

        if operator_queue is None:
            logger.warning(
                "No operator queue — cannot block for input. "
                "Skipping unreachable challenges."
            )
            return reachable

        # Block until we get a valid resolution for all unreachable challenges
        resolved: set[str] = set()
        result = list(reachable)

        while resolved != unreachable_names:
            try:
                msg = await operator_queue.get()
            except asyncio.CancelledError:
                logger.warning("Cancelled while waiting — skipping unreachable")
                return reachable

            msg = msg.strip()
            parts = msg.split(None, 2)
            cmd = parts[0].lower() if parts else ""

            if cmd == "continue":
                # Proceed with everything, including unreachable
                logger.info("Operator: continue — proceeding with all challenges")
                return all_challenges

            elif cmd == "skip":
                target_name = parts[1] if len(parts) > 1 else ""
                if target_name.lower() == "all":
                    logger.info("Operator: skip all unreachable challenges")
                    resolved = set(unreachable_names)
                elif target_name in unreachable_names:
                    logger.info("Operator: skip %s", target_name)
                    resolved.add(target_name)
                else:
                    logger.warning(
                        "Unknown challenge '%s'. Unreachable: %s",
                        target_name, ", ".join(unreachable_names - resolved),
                    )
                    continue

            elif cmd == "url" and len(parts) >= 3:
                target_name = parts[1]
                new_url = parts[2]
                if target_name in unreachable_names:
                    # Update the challenge's target URL
                    for ch in all_challenges:
                        if ch["name"] == target_name:
                            old_url = ch.get("target", "")
                            ch["target"] = new_url
                            logger.info(
                                "Operator: url %s → %s (was %s)",
                                target_name, new_url, old_url,
                            )
                            # Re-probe the new URL
                            probe_ok, probe_fail = await self._probe_targets([ch])
                            if probe_ok:
                                logger.info("  ✓ %s now reachable", target_name)
                                result.append(ch)
                                resolved.add(target_name)
                            else:
                                logger.warning(
                                    "  ✗ %s still unreachable at %s",
                                    target_name, new_url,
                                )
                            break
                else:
                    logger.warning(
                        "Unknown challenge '%s'. Unreachable: %s",
                        target_name, ", ".join(unreachable_names - resolved),
                    )

            elif cmd == "whitebox":
                target_name = parts[1] if len(parts) > 1 else ""
                names_to_whitebox: list[str] = []
                if target_name.lower() == "all":
                    names_to_whitebox = list(unreachable_names - resolved)
                elif target_name in unreachable_names:
                    names_to_whitebox = [target_name]
                else:
                    logger.warning(
                        "Unknown challenge '%s'. Unreachable: %s",
                        target_name, ", ".join(unreachable_names - resolved),
                    )
                    continue

                for name in names_to_whitebox:
                    for ch in all_challenges:
                        if ch["name"] == name:
                            ch_files = ch.get("file_paths", [])
                            if not ch_files:
                                logger.warning(
                                    "  %s has no source files — "
                                    "whitebox analysis may be limited",
                                    name,
                                )
                            # Mark as whitebox mode: clear network target,
                            # set target to file paths
                            ch["_whitebox"] = True
                            ch["_original_target"] = ch.get("target", "")
                            if ch_files:
                                ch["target"] = ch_files[0]
                            logger.info(
                                "Operator: whitebox %s — source-only analysis "
                                "(files: %s)",
                                name,
                                ", ".join(ch_files[:3]) or "(none)",
                            )
                            result.append(ch)
                            resolved.add(name)
                            break

            else:
                logger.info(
                    "Unknown command '%s'. Use: skip <name|all> | "
                    "url <name> <new_url> | whitebox <name|all> | continue",
                    msg,
                )
                continue

            # Show remaining unresolved
            remaining = unreachable_names - resolved
            if remaining:
                logger.info(
                    "  %d unresolved: %s",
                    len(remaining), ", ".join(remaining),
                )

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
