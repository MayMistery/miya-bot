"""OODA Topology — Observe, Orient, Decide, Act with Reflection Gate.

The OODA loop is a decision-making framework from military strategy,
adapted here for adversarial security testing:

  OBSERVE  → Gather information about the target
  ORIENT   → Analyze findings, identify patterns and opportunities
  DECIDE   → Plan the next action based on analysis
  ACT      → Execute the plan using specialized agents
  REFLECT  → Evaluate results, decide whether to continue/pivot/complete

The loop repeats until the mission objective is achieved or max iterations reached.
Nested OODA: each phase can invoke sub-agents that themselves follow OODA internally.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, AsyncIterator

from miya.shared.blackboard import Blackboard
from miya.shared.events import (
    DomainEvent,
    MissionStarted,
    MissionCompleted,
    OperatorMessage,
    PhaseTransition,
    ReflectionCompleted,
    ChallengeClassified,
    ChallengeSolved,
)
from miya.shared.ports import CoordinatorPort, EventStorePort
from miya.shared.types import Mission, OODAPhase, MissionType
from miya.topology.base import (
    TopologyRegistry, AgentHandle,
    extract_events_from_output, EVENT_INSTRUCTION,
    run_sdk_coordinator, _get_topology_config, drain_hitl_queue,
    SDKSession,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
#  Phase prompts — mission-type-aware, minimal by design.
#
#  Design principle: give the model the GOAL, not the STEPS.
#  Claude already knows how to do security testing and CTF.
#  Over-prompting degrades capability by boxing the model in.
# ═══════════════════════════════════════════════════════════════════

# ── Generic (pentest / oneday / zeroday) ──────────────────────────

_OBSERVE_GENERIC = """## OBSERVE
{blackboard_context}
Mission: {mission_description}
Agents: {agent_descriptions}
Gather intelligence on the target. Build on blackboard state — don't repeat prior work.
"""

_ORIENT_GENERIC = """## ORIENT
{blackboard_context}
Mission: {mission_description}
Observations: {observe_output}
Analyze findings. Rank attack vectors by impact and feasibility.
"""

_DECIDE_GENERIC = """## DECIDE
{blackboard_context}
Mission: {mission_description}
Analysis: {orient_output}
Pick the next concrete action. Specify which agent, what parameters, success criteria.
"""

_ACT_GENERIC = """## ACT
{blackboard_context}
Mission: {mission_description}
Plan: {decide_output}
Agents: {agent_descriptions}
Execute the plan. Stop after 2-3 failed attempts — the next cycle will adapt.
"""

_REFLECT_GENERIC = """## REFLECT
{blackboard_context}
Mission: {mission_description}
Results: {act_output}
Previous insights: {previous_insights}

Decide: CONTINUE / PIVOT / COMPLETE.
DECISION: <continue|pivot|complete>
ASSESSMENT: <what happened>
INSIGHTS: <what we learned>
NEXT_FOCUS: <what to do next>
"""

# ── CTF-specific (minimal — let the model reason freely) ─────────

_OBSERVE_CTF = """## OBSERVE
{blackboard_context}
Mission: {mission_description}
Agents: {agent_descriptions}
Examine the challenge files and target. Identify the category and attack surface.
If you identify specific software/library versions, use **WebSearch** to look up \
known CVEs and vulnerabilities for those versions.
"""

_ORIENT_CTF = """## ORIENT
{blackboard_context}
Mission: {mission_description}
Observations: {observe_output}
Identify the vulnerability class and plan the exploitation approach.
"""

_DECIDE_CTF = """## DECIDE
{blackboard_context}
Mission: {mission_description}
Analysis: {orient_output}
Choose the exploitation technique and specify the agent to use.
"""

_ACT_CTF = """## ACT
{blackboard_context}
Mission: {mission_description}
Plan: {decide_output}
Agents: {agent_descriptions}
Exploit the vulnerability and capture the flag.
"""

_REFLECT_CTF = """## REFLECT
{blackboard_context}
Mission: {mission_description}
Results: {act_output}
Previous insights: {previous_insights}

Did we get the flag? Decide: CONTINUE / PIVOT / COMPLETE.
DECISION: <continue|pivot|complete>
ASSESSMENT: <what happened>
INSIGHTS: <what we learned>
NEXT_FOCUS: <what to do next>
"""

# ── Autonomous continuation prompt (subsequent OODA iterations) ──

_CONTINUE_CTF = """\
## CONTINUE (Iteration {iteration})
Previous focus: {previous_insights}

You have all prior context from this session. Continue the OODA cycle autonomously:
1. **OBSERVE**: Check what changed, gather new intelligence based on the previous focus.
2. **ACT**: Execute the next exploitation step.
3. **REFLECT**: Evaluate results. Did we get the flag?

When done, output your reflection:
DECISION: <continue|pivot|complete>
ASSESSMENT: <what happened>
INSIGHTS: <what we learned>
NEXT_FOCUS: <what to do next>
"""

_CONTINUE_GENERIC = """\
## CONTINUE (Iteration {iteration})
Previous focus: {previous_insights}

You have all prior context from this session. Continue the OODA cycle autonomously:
1. **OBSERVE**: Gather new intelligence based on the previous focus.
2. **ORIENT**: Analyze new findings.
3. **ACT**: Execute the next action.
4. **REFLECT**: Evaluate results.

When done, output your reflection:
DECISION: <continue|pivot|complete>
ASSESSMENT: <what happened>
INSIGHTS: <what we learned>
NEXT_FOCUS: <what to do next>
"""

# ── Prompt selector by mission type ──────────────────────────────

_PHASE_PROMPTS: dict[str, dict[str, str]] = {
    "ctf": {
        "OBSERVE": _OBSERVE_CTF,
        "ORIENT": _ORIENT_CTF,
        "DECIDE": _DECIDE_CTF,
        "ACT": _ACT_CTF,
        "REFLECT": _REFLECT_CTF,
    },
    "_default": {
        "OBSERVE": _OBSERVE_GENERIC,
        "ORIENT": _ORIENT_GENERIC,
        "DECIDE": _DECIDE_GENERIC,
        "ACT": _ACT_GENERIC,
        "REFLECT": _REFLECT_GENERIC,
    },
}


def _get_phase_prompt(mission_type: str, phase: str) -> str:
    """Select the minimal phase prompt template for a mission type."""
    prompts = _PHASE_PROMPTS.get(mission_type, _PHASE_PROMPTS["_default"])
    return prompts[phase]


# ── Auto-classification prompt (CTF only) ─────────────────────────

_CLASSIFY_PROMPT = """Explore and classify this CTF challenge.

Target: {target}
{file_info}

## Instructions
1. **Explore**: Read challenge files, check file types, inspect source code, \
examine provided artifacts. If there's a URL, make an initial request to observe \
behavior. Use `file`, `strings`, `checksec` as appropriate.
2. **Research Known Vulnerabilities**: When you identify specific software, \
frameworks, or libraries with version numbers (e.g. GORM v1.21.14, Flask 2.0.1, \
PHP 7.4), use **WebSearch** to look up known CVEs and security advisories for \
those exact versions. Search queries like "GORM 1.21 CVE", "Flask 2.0.1 vulnerability", \
or "<library> <version> security issue" are very effective. Include any relevant \
CVEs or known vulnerabilities in your recon summary.
3. **Classify**: Based on your exploration, determine the challenge category.
4. **Strategize**: Based on what you found, outline your initial attack approach.

## Response Format
CATEGORY: <web|pwn|crypto|reverse|misc>
CONFIDENCE: <0.0-1.0>
REASONING: <one sentence>

RECON_SUMMARY:
<Multi-line summary of what you discovered during exploration. Include: \
technology stack, key files, identified entry points, initial observations \
about potential vulnerabilities or approach, and any known CVEs/advisories \
found via WebSearch. This will be fed to the specialist agent who will \
solve the challenge.>
"""

# ── Flag submission prompt ────────────────────────────────────────

_FLAG_SUBMIT_INSTRUCTION = """
When you find a flag, also try to submit it. Use curl or the platform's API.
Report the result:
[EVENT:FlagSubmitted {"challenge_name": "...", "flag": "flag{...}", "accepted": true, "response": "...", "context": "ctf"}]
If submission fails or no API is available, just report the flag via ChallengeSolved.
"""


class OODATopology:
    """OODA loop orchestration with reflection gate."""

    _PHASE_DESC = {
        "OBSERVE": "gathering intelligence",
        "ORIENT":  "analyzing findings",
        "DECIDE":  "planning next action",
        "ACT":     "executing plan",
        "REFLECT": "evaluating results",
    }

    def __init__(
        self,
        max_iterations: int | None = None,
        coordinator: CoordinatorPort | None = None,
        challenge_tag: str = "",
        on_progress: Any | None = None,
        on_log: Any | None = None,
    ) -> None:
        cfg = _get_topology_config()
        self._max_iterations = max_iterations if max_iterations is not None else cfg["ooda_max_iterations"]
        self._coordinator = coordinator
        self._tag = f"[{challenge_tag}] " if challenge_tag else ""
        self._challenge_tag = challenge_tag
        self._on_progress = on_progress  # callback(challenge_name, **kwargs)
        self._on_log = on_log  # callback(challenge_name, line)

    def _log(self, level: int, msg: str, *args: Any) -> None:
        """Log with optional challenge tag prefix + capture to log buffer."""
        formatted = msg % args if args else msg
        logger.log(level, "%s%s", self._tag, formatted)
        if self._on_log and self._challenge_tag:
            self._on_log(self._challenge_tag, formatted)

    def _report(self, **kwargs: Any) -> None:
        """Report progress to display callback."""
        if self._on_progress and self._challenge_tag:
            self._on_progress(self._challenge_tag, **kwargs)

    def _log_output_summary(self, phase: str, output: str) -> None:
        """Log a truncated summary of SDK phase output to the log buffer.

        Captures the first meaningful lines of the agent's response so that
        ``logs <name>`` shows useful detail, not just phase transitions.
        """
        if not output or not self._on_log or not self._challenge_tag:
            return
        # Take first non-empty lines, skip JSON event blocks
        lines = []
        for raw_line in output.splitlines():
            stripped = raw_line.strip()
            if not stripped:
                continue
            # Skip structured event JSON emitted for extract_events_from_output
            if stripped.startswith(("{", "[")) and any(
                k in stripped for k in ('"event_type"', '"events"')
            ):
                continue
            lines.append(stripped)
            if len(lines) >= 8:
                break
        if lines:
            self._on_log(
                self._challenge_tag,
                f"  [{phase}] " + lines[0][:120],
            )
            for line in lines[1:]:
                self._on_log(self._challenge_tag, f"    {line[:120]}")

    @property
    def name(self) -> str:
        return "ooda"

    @property
    def description(self) -> str:
        return (
            "OODA Loop (Observe→Orient→Decide→Act) with Reflection Gate. "
            "Adaptive, adversarial decision-making with forced reflection after each action."
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
        """Run the OODA loop until completion or max iterations.

        Hybrid session mode (CTF only):
        - First iteration: 3 separate query() calls on a shared session
          (OBSERVE → ACT → REFLECT), building rich context.
        - Subsequent iterations: 1 query() per iteration (CONTINUE),
          leveraging session context to avoid re-sending everything.

        Non-CTF missions use stateless calls (no session reuse).
        """
        from miya.shared.campaign import Campaign as _Campaign

        # ── Mission Start ─────────────────────────────────────────
        import json as _json
        start_event = MissionStarted(
            aggregate_id=mission.id,
            aggregate_type="Mission",
            mission_type=mission.mission_type.value,
            target_uri=mission.target.uri,
            topology=self.name,
            mission=mission.mission_type.value,
            prompt=mission.prompt,
            model=mission.options.get("_model_override", ""),
            options_json=_json.dumps(
                {k: v for k, v in mission.options.items()
                 if not k.startswith("_") and isinstance(v, (str, int, float, bool))},
                ensure_ascii=False,
            ),
        )
        yield start_event
        blackboard.apply(start_event)

        mission_desc = f"{mission.mission_type.value}: {mission.target}"
        agent_desc = "\n".join(
            f"- **{name}**: {a.description}" for name, a in agents.items()
        )

        # ── Campaign context (cross-mission knowledge) ────────────
        campaign_context = ""
        if isinstance(campaign, _Campaign) and campaign.entries:
            campaign_context = campaign.to_context_prompt()

        # ── Operator initial prompt ───────────────────────────────
        operator_prompt = ""
        if mission.prompt:
            operator_prompt = (
                f"\n\n## Operator Instructions\n{mission.prompt}\n"
            )
            self._log(logging.INFO, "📋 Operator prompt: %s", mission.prompt[:120])

        observe_output = ""
        orient_output = ""
        decide_output = ""
        act_output = ""
        previous_insights = ""
        classified_category = ""  # populated by auto-classify for CTF
        mission_key = mission.mission_type.value

        def _drain_hitl() -> tuple[list[OperatorMessage], str]:
            return drain_hitl_queue(
                operator_queue, mission.id, mission.mission_type.value, operator_prompt,
            )

        # ── Auto-classify (CTF only) ──────────────────────────────
        recon_summary = ""
        if mission.mission_type == MissionType.CTF:
            classified_category, recon_summary = await self._auto_classify(
                mission, agents, blackboard,
            )
            if classified_category:
                classify_event = ChallengeClassified(
                    aggregate_id=mission.id,
                    category=classified_category,
                    confidence=0.8,
                    reasoning="auto-classified from challenge artifacts",
                    mission=mission.mission_type.value,
                )
                yield classify_event
                blackboard.apply(classify_event)
                self._log(logging.INFO, "Auto-classified as: %s", classified_category)
                self._report(category=classified_category, status="classifying")
                if recon_summary:
                    self._log(logging.INFO, "  recon summary: %s", recon_summary[:120])

        # ── Determine agents for session ──────────────────────────
        # For CTF with known category, use specialist agent
        session_agents = agents
        if classified_category and mission_key == "ctf":
            direct = self._pick_direct_agent(classified_category, agents)
            if direct:
                session_agents = direct

        # ── Create session for CTF (hybrid mode) ──────────────────
        use_session = mission_key == "ctf" and self._coordinator is None
        session: SDKSession | None = None

        if use_session:
            all_mcp_names: set[str] = set()
            for handle in session_agents.values():
                all_mcp_names.update(handle.mcp_servers)
            agent_defs = {
                name: handle.to_agent_definition()
                for name, handle in session_agents.items()
            }
            session = SDKSession(agent_defs, list(all_mcp_names))
            try:
                await session.connect()
            except Exception:
                self._log(
                    logging.WARNING,
                    "SDKSession connect failed — falling back to stateless mode",
                )
                logger.debug("Session connect error details", exc_info=True)
                # Clean up partially-connected session to avoid resource leak
                try:
                    await session.disconnect()
                except Exception:
                    pass
                session = None

        try:
            _stagnation_count = 0
            _prev_finding_count = len(blackboard.findings)
            _prev_exploit_count = len(blackboard.exploit_attempts)
            _STAGNATION_THRESHOLD = 3  # consecutive iterations with no progress

            for iteration in range(1, self._max_iterations + 1):
                # Compact blackboard between iterations to bound memory growth
                if iteration > 1:
                    removed = blackboard.compact()
                    if removed:
                        logger.debug("Blackboard compacted: %s", removed)

                self._log(
                    logging.INFO,
                    "━━━━ OODA #%d/%d ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                    iteration, self._max_iterations,
                )
                self._report(iteration=iteration, status="running")
                if previous_insights:
                    self._log(logging.INFO, "  focus: %s", previous_insights[:120])

                # ── Drain HITL ────────────────────────────────────
                hitl_events, op_suffix = _drain_hitl()
                for ev in hitl_events:
                    yield ev
                    blackboard.apply(ev)

                # ── HYBRID: subsequent iterations use single CONTINUE query ──
                if iteration > 1 and session is not None:
                    yield PhaseTransition(
                        from_phase=OODAPhase.REFLECT.value,
                        to_phase="continue",
                        reason=f"Iteration {iteration} — Focus: {previous_insights}",
                        aggregate_id=mission.id,
                        mission=mission.mission_type.value,
                    )

                    self._log(logging.INFO, "▶ CONTINUE (autonomous iteration)")
                    self._report(phase="CONTINUE", iteration=iteration)
                    continue_tmpl = _CONTINUE_CTF if mission_key == "ctf" else _CONTINUE_GENERIC
                    continue_prompt = continue_tmpl.format(
                        iteration=iteration,
                        previous_insights=previous_insights or "(none)",
                    ) + op_suffix + EVENT_INSTRUCTION + (
                        _FLAG_SUBMIT_INSTRUCTION if mission_key == "ctf" else ""
                    )

                    continue_output = await session.query(
                        continue_prompt, phase_label=f"CONTINUE-{iteration}",
                    )

                    _solved_in_continue = False
                    for extracted in extract_events_from_output(continue_output, mission):
                        if isinstance(extracted, ChallengeSolved):
                            object.__setattr__(
                                extracted, "phase_output",
                                continue_output[:8000],
                            )
                            _solved_in_continue = True
                        yield extracted
                        blackboard.apply(extracted)

                    # Fast-exit: flag captured in CONTINUE phase
                    if _solved_in_continue:
                        self._log(logging.INFO, "✓ Flag captured — done")
                        self._report(status="solved", phase="DONE")
                        yield ReflectionCompleted(
                            decision="complete",
                            assessment="Flag captured during CONTINUE phase",
                            insights="",
                            next_focus="",
                            aggregate_id=mission.id,
                            mission=mission.mission_type.value,
                        )
                        break

                    # Parse reflection from the combined output
                    decision = self._parse_reflection(continue_output)

                else:
                    # ── FIRST ITERATION (or non-session): full phase separation ──

                    # ── OBSERVE ────────────────────────────────────
                    phase_event = PhaseTransition(
                        from_phase=OODAPhase.REFLECT.value if iteration > 1 else "",
                        to_phase=OODAPhase.OBSERVE.value,
                        reason=(f"Iteration {iteration}"
                                + (f" — Focus: {previous_insights}" if previous_insights else "")),
                        aggregate_id=mission.id,
                        mission=mission.mission_type.value,
                    )
                    yield phase_event
                    blackboard.apply(phase_event)

                    self._log(logging.INFO, "▶ OBSERVE — %s", self._PHASE_DESC["OBSERVE"])
                    self._report(phase="OBSERVE")
                    focus_hint = ""
                    if previous_insights:
                        focus_hint = f"\nFocus from last REFLECT: {previous_insights}\n"
                    recon_hint = ""
                    if recon_summary and iteration == 1:
                        recon_hint = (
                            f"\n## Initial Reconnaissance (from CLASSIFY phase)\n"
                            f"{recon_summary}\n"
                        )
                    observe_prompt = _get_phase_prompt(mission_key, "OBSERVE").format(
                        blackboard_context=blackboard.to_context_prompt(),
                        mission_description=mission_desc,
                        agent_descriptions=agent_desc,
                    ) + campaign_context + focus_hint + recon_hint + op_suffix + EVENT_INSTRUCTION

                    if session is not None:
                        observe_output = await session.query(observe_prompt, phase_label="OBSERVE")
                    else:
                        observe_output = await self._run_coordinator(
                            observe_prompt, mission, session_agents, blackboard, phase_label="OBSERVE"
                        )
                    self._log_output_summary("OBSERVE", observe_output)

                    for extracted in extract_events_from_output(
                        observe_output, mission, causation_id=phase_event.event_id,
                    ):
                        yield extracted
                        blackboard.apply(extracted)

                    # ── CTF fast-path: skip ORIENT+DECIDE ─────────
                    if mission_key == "ctf":
                        orient_output = ""
                        decide_output = observe_output
                    else:
                        # ── ORIENT ────────────────────────────────
                        hitl_events, op_suffix = _drain_hitl()
                        for ev in hitl_events:
                            yield ev
                            blackboard.apply(ev)

                        yield PhaseTransition(
                            from_phase=OODAPhase.OBSERVE.value,
                            to_phase=OODAPhase.ORIENT.value,
                            aggregate_id=mission.id,
                            mission=mission.mission_type.value,
                        )
                        self._log(logging.INFO, "▶ ORIENT — %s", self._PHASE_DESC["ORIENT"])
                        self._report(phase="ORIENT")
                        orient_prompt = _get_phase_prompt(mission_key, "ORIENT").format(
                            blackboard_context=blackboard.to_context_prompt(),
                            mission_description=mission_desc,
                            observe_output=observe_output[:4000],
                        ) + op_suffix + EVENT_INSTRUCTION
                        orient_output = await self._run_coordinator(
                            orient_prompt, mission, agents, blackboard, phase_label="ORIENT"
                        )
                        self._log_output_summary("ORIENT", orient_output)
                        for extracted in extract_events_from_output(orient_output, mission):
                            yield extracted
                            blackboard.apply(extracted)

                        # ── DECIDE ────────────────────────────────
                        hitl_events, op_suffix = _drain_hitl()
                        for ev in hitl_events:
                            yield ev
                            blackboard.apply(ev)
                        yield PhaseTransition(
                            from_phase=OODAPhase.ORIENT.value,
                            to_phase=OODAPhase.DECIDE.value,
                            aggregate_id=mission.id,
                            mission=mission.mission_type.value,
                        )
                        self._log(logging.INFO, "▶ DECIDE — %s", self._PHASE_DESC["DECIDE"])
                        self._report(phase="DECIDE")
                        decide_prompt = _get_phase_prompt(mission_key, "DECIDE").format(
                            blackboard_context=blackboard.to_context_prompt(),
                            mission_description=mission_desc,
                            orient_output=orient_output[:4000],
                        ) + op_suffix + EVENT_INSTRUCTION
                        decide_output = await self._run_coordinator(
                            decide_prompt, mission, agents, blackboard, phase_label="DECIDE"
                        )
                        self._log_output_summary("DECIDE", decide_output)

                    # ── ACT ────────────────────────────────────────
                    hitl_events, op_suffix = _drain_hitl()
                    for ev in hitl_events:
                        yield ev
                        blackboard.apply(ev)

                    yield PhaseTransition(
                        from_phase=(OODAPhase.OBSERVE.value if mission_key == "ctf"
                                    else OODAPhase.DECIDE.value),
                        to_phase=OODAPhase.ACT.value,
                        aggregate_id=mission.id,
                        mission=mission.mission_type.value,
                    )
                    self._log(logging.INFO, "▶ ACT — %s", self._PHASE_DESC["ACT"])
                    self._report(phase="ACT")
                    flag_hint = _FLAG_SUBMIT_INSTRUCTION if mission_key == "ctf" else ""
                    act_prompt = _get_phase_prompt(mission_key, "ACT").format(
                        blackboard_context=blackboard.to_context_prompt(),
                        mission_description=mission_desc,
                        decide_output=decide_output[:4000],
                        agent_descriptions=agent_desc,
                    ) + op_suffix + EVENT_INSTRUCTION + flag_hint

                    if session is not None:
                        act_output = await session.query(act_prompt, phase_label="ACT")
                    else:
                        act_agents = agents
                        if classified_category and mission_key == "ctf":
                            direct = self._pick_direct_agent(classified_category, agents)
                            if direct:
                                act_agents = direct
                        act_output = await self._run_coordinator(
                            act_prompt, mission, act_agents, blackboard, phase_label="ACT"
                        )
                    self._log_output_summary("ACT", act_output)

                    _solved_in_act = False
                    for extracted in extract_events_from_output(act_output, mission):
                        if isinstance(extracted, ChallengeSolved):
                            # Attach raw ACT output so writeup has payload detail
                            object.__setattr__(
                                extracted, "phase_output",
                                act_output[:8000],
                            )
                            _solved_in_act = True
                        yield extracted
                        blackboard.apply(extracted)

                    # ── Fast-exit: if flag was captured, skip REFLECT ──
                    if _solved_in_act:
                        self._log(logging.INFO, "✓ Flag captured — skipping REFLECT")
                        self._report(status="solved", phase="DONE")
                        yield ReflectionCompleted(
                            decision="complete",
                            assessment="Flag captured during ACT phase",
                            insights="",
                            next_focus="",
                            aggregate_id=mission.id,
                            mission=mission.mission_type.value,
                        )
                        break

                    # ── REFLECT ────────────────────────────────────
                    hitl_events, op_suffix = _drain_hitl()
                    for ev in hitl_events:
                        yield ev
                        blackboard.apply(ev)

                    yield PhaseTransition(
                        from_phase=OODAPhase.ACT.value,
                        to_phase=OODAPhase.REFLECT.value,
                        aggregate_id=mission.id,
                        mission=mission.mission_type.value,
                    )
                    self._log(logging.INFO, "▶ REFLECT — %s", self._PHASE_DESC["REFLECT"])
                    self._report(phase="REFLECT")
                    reflect_prompt = _get_phase_prompt(mission_key, "REFLECT").format(
                        blackboard_context=blackboard.to_context_prompt(),
                        mission_description=mission_desc,
                        act_output=act_output[:4000],
                        previous_insights=previous_insights or "(first iteration)",
                    ) + op_suffix

                    if session is not None:
                        reflect_output = await session.query(reflect_prompt, phase_label="REFLECT")
                    else:
                        reflect_output = await self._run_coordinator(
                            reflect_prompt, mission, agents, blackboard, phase_label="REFLECT"
                        )
                    self._log_output_summary("REFLECT", reflect_output)

                    decision = self._parse_reflection(reflect_output)

                # ── Stagnation detection ────────────────────────
                _cur_finding_count = len(blackboard.findings)
                _cur_exploit_count = len(blackboard.exploit_attempts)
                if (_cur_finding_count == _prev_finding_count
                        and _cur_exploit_count == _prev_exploit_count):
                    _stagnation_count += 1
                else:
                    _stagnation_count = 0
                _prev_finding_count = _cur_finding_count
                _prev_exploit_count = _cur_exploit_count

                # ── Common: process reflection decision ───────────
                previous_insights = decision.get("next_focus", "") or decision.get("insights", "")
                d = decision.get("decision", "continue")

                if d == "continue" and _stagnation_count >= _STAGNATION_THRESHOLD:
                    self._log(
                        logging.WARNING,
                        "⚠ Stagnation detected: %d iterations with no new findings "
                        "or exploit attempts — ending loop",
                        _stagnation_count,
                    )
                    d = "complete"
                    decision["decision"] = "complete"
                    decision["assessment"] = (
                        f"Auto-complete: no progress in {_stagnation_count} consecutive iterations"
                    )
                _DECISION_ICONS = {"complete": "\u2713", "pivot": "\u21bb", "continue": "\u27f3"}
                self._log(
                    logging.INFO,
                    "%s %s — %s",
                    _DECISION_ICONS.get(d, "?"), d.upper(),
                    (decision.get("assessment", "") or decision.get("insights", ""))[:120],
                )
                if d == "complete":
                    self._report(status="solved", phase="DONE")

                reflection_event = ReflectionCompleted(
                    aggregate_id=mission.id,
                    assessment=decision.get("assessment", ""),
                    decision=d,
                    insights=decision.get("insights", ""),
                    mission=mission.mission_type.value,
                )
                yield reflection_event
                blackboard.apply(reflection_event)

                if d == "complete":
                    break
            else:
                # Loop exhausted — check if a flag was actually found
                _ch_name = mission.options.get("challenge_name", "")
                _flag_found = False

                # Check 1: explicit ChallengeSolved already in blackboard
                if blackboard.solved_flags:
                    _flag_found = True

                # Check 2: flag pattern in findings (LootCollected with flag)
                if not _flag_found:
                    import re as _re
                    _FLAG_RE = _re.compile(r'flag\{[^}]+\}', _re.IGNORECASE)
                    for f in blackboard.findings:
                        if _FLAG_RE.search(f.detail or "") or _FLAG_RE.search(f.evidence or ""):
                            _flag_found = True
                            _flag_match = _FLAG_RE.search(f.detail or "") or _FLAG_RE.search(f.evidence or "")
                            if _flag_match and _ch_name:
                                self._log(
                                    logging.INFO,
                                    "\u2713 Flag found in findings: %s — emitting ChallengeSolved",
                                    _flag_match.group()[:50],
                                )
                                solved_ev = ChallengeSolved(
                                    aggregate_id=mission.id,
                                    challenge_name=_ch_name,
                                    flag=_flag_match.group(),
                                    approach="extracted from findings after OODA exhaustion",
                                    mission=mission.mission_type.value,
                                )
                                yield solved_ev
                                blackboard.apply(solved_ev)
                            break

                if _flag_found:
                    self._log(
                        logging.INFO,
                        "OODA loop exhausted after %d iterations but flag was found",
                        self._max_iterations,
                    )
                    self._report(status="solved", phase="DONE")
                else:
                    self._log(
                        logging.WARNING,
                        "OODA loop exhausted after %d iterations "
                        "without explicit completion",
                        self._max_iterations,
                    )
                    self._report(status="failed", phase="FAILED")
        finally:
            # Always clean up the session
            if session is not None:
                await session.disconnect()

        # ── Mission Complete ──────────────────────────────────────
        complete_event = MissionCompleted(
            aggregate_id=mission.id,
            findings_count=len(blackboard.findings),
            mission=mission.mission_type.value,
        )
        yield complete_event
        blackboard.apply(complete_event)

    async def _run_coordinator(
        self,
        prompt: str,
        mission: Mission,
        agents: dict[str, AgentHandle],
        blackboard: Blackboard,
        phase_label: str = "",
        max_turns: int | None = None,
        operator_queue: asyncio.Queue[str] | None = None,
    ) -> str:
        """Run the coordinator agent with a prompt and collect text output.

        On SDKTimeoutError, asks the operator whether to retry, skip,
        or abort. This prevents silent failures and gives the human
        a chance to decide.
        """
        from miya.topology.base import SDKTimeoutError

        all_mcp_names: set[str] = set()
        for handle in agents.values():
            all_mcp_names.update(handle.mcp_servers)

        agent_defs = {
            name: handle.to_agent_definition()
            for name, handle in agents.items()
        }

        while True:
            try:
                # Use injected coordinator port if available
                if self._coordinator is not None:
                    return await self._coordinator.run(
                        prompt=prompt,
                        agents=agent_defs,
                        mcp_servers=list(all_mcp_names),
                    )

                # Fallback: use shared Claude Agent SDK coordinator
                return await run_sdk_coordinator(
                    prompt, agent_defs, list(all_mcp_names),
                    phase_label=phase_label, max_turns=max_turns,
                )
            except SDKTimeoutError as exc:
                self._log(logging.WARNING, f"SDK timeout: {exc}")

                # Ask operator: retry / skip / abort
                if operator_queue is not None:
                    self._log(
                        logging.WARNING,
                        "SDK timed out. Type 'retry', 'skip', or 'abort' in HITL.",
                    )
                    # Wait for operator decision (up to 120s)
                    try:
                        decision = await asyncio.wait_for(
                            operator_queue.get(), timeout=120,
                        )
                    except asyncio.TimeoutError:
                        decision = "skip"

                    decision = decision.strip().lower()
                    if decision == "retry":
                        self._log(logging.INFO, "Retrying SDK call...")
                        continue
                    elif decision == "abort":
                        raise
                    else:
                        # skip — return empty so the phase is skipped
                        self._log(logging.INFO, "Skipping timed-out phase")
                        return f"[SKIPPED: SDK timeout — {exc}]"
                else:
                    raise

    @staticmethod
    def _parse_reflection(output: str) -> dict[str, str]:
        """Parse the reflection gate output into a structured decision.

        Supports multi-line field values and case-insensitive field matching.
        Falls back to heuristics if structured parsing fails.
        """
        import re

        result: dict[str, str] = {
            "decision": "continue",
            "assessment": "",
            "insights": "",
            "next_focus": "",
        }

        fields = ("DECISION", "ASSESSMENT", "INSIGHTS", "NEXT_FOCUS")
        # Build regex that captures FIELD: <value until next FIELD: or end>
        pattern = re.compile(
            r"(?:^|\n)\s*(" + "|".join(fields) + r")\s*:\s*(.*?)(?=\n\s*(?:"
            + "|".join(fields) + r")\s*:|$)",
            re.IGNORECASE | re.DOTALL,
        )

        decision_parsed = False
        for match in pattern.finditer(output):
            key = match.group(1).upper().strip()
            val = match.group(2).strip()
            if key == "DECISION":
                # Strict: only accept first word as decision value
                first_word = val.split()[0].lower().rstrip(".,;:!") if val.split() else ""
                for d in ("complete", "pivot", "continue"):
                    if first_word == d:
                        result["decision"] = d
                        decision_parsed = True
                        break
            else:
                result[key.lower()] = val

        # Heuristic fallback ONLY if no DECISION field was parsed at all.
        # Only trigger on phrases in the LAST 300 chars (conclusion area)
        # to avoid false positives from the model discussing past outcomes.
        if not decision_parsed:
            tail = output[-300:].lower() if len(output) > 300 else output.lower()
            _completion_phrases = (
                "objective achieved", "mission complete", "flag found",
                "successfully exploited", "root access obtained",
            )
            matched = sum(1 for phrase in _completion_phrases if phrase in tail)
            if matched >= 1:
                result["decision"] = "complete"
                if not result["assessment"]:
                    result["assessment"] = "Objective achieved (auto-detected)"

        return result

    # ── Auto-classification (#1) ──────────────────────────────────

    async def _auto_classify(
        self,
        mission: Mission,
        agents: dict[str, AgentHandle],
        blackboard: Blackboard,
    ) -> tuple[str, str]:
        """Explore and classify a CTF challenge before OBSERVE.

        Inspired by D-CIPHER's Auto-Prompter pattern: instead of just
        classifying the category, the agent briefly explores the challenge
        environment (reads files, checks services, inspects artifacts) and
        produces BOTH a category AND a recon summary that feeds into the
        specialist agent's OBSERVE phase.

        Returns (category, recon_summary) where category is one of
        web|pwn|crypto|reverse|misc (or "" if classification fails)
        and recon_summary is the exploration findings (or "").
        """
        import re

        classify_prompt = _CLASSIFY_PROMPT.format(
            target=mission.target.uri,
            file_info=f"Operator hint: {mission.prompt[:200]}" if mission.prompt else "",
        )

        self._log(logging.INFO, "▶ CLASSIFY — exploring and classifying challenge")
        self._report(phase="CLASSIFY", status="classifying")
        try:
            output = await self._run_coordinator(
                classify_prompt, mission, agents, blackboard,
                phase_label="CLASSIFY",
                max_turns=5,  # slightly more turns to allow actual exploration
            )
        except Exception:
            logger.warning("Auto-classify failed, skipping", exc_info=True)
            return "", ""

        # Extract any events emitted during classification exploration
        for extracted in extract_events_from_output(output, mission):
            blackboard.apply(extracted)

        # Parse CATEGORY: from output
        m = re.search(r"CATEGORY\s*:\s*(web|pwn|crypto|reverse|misc)", output, re.IGNORECASE)
        category = m.group(1).lower() if m else ""

        # Parse RECON_SUMMARY: from output (everything after the marker)
        recon_summary = ""
        rs = re.search(r"RECON_SUMMARY:\s*\n(.*)", output, re.DOTALL | re.IGNORECASE)
        if rs:
            recon_summary = rs.group(1).strip()[:3000]  # cap to avoid context bloat

        return category, recon_summary

    # ── Direct agent selection (#5) ───────────────────────────────

    @staticmethod
    def _pick_direct_agent(
        category: str,
        agents: dict[str, AgentHandle],
    ) -> dict[str, AgentHandle] | None:
        """Pick the specialist agent for a known CTF category.

        Returns a single-agent dict, or None if no match found.
        For ACT phases: skip the coordinator overhead and invoke directly.
        """
        # Map category to agent context_name patterns
        _CAT_PATTERNS = {
            "web": ("ctf.web", "web"),
            "pwn": ("ctf.pwn", "pwn"),
            "crypto": ("ctf.crypto", "crypto"),
            "reverse": ("ctf.reverse", "reverse"),
            "misc": ("ctf.misc", "misc"),
        }
        patterns = _CAT_PATTERNS.get(category, ())
        for name, handle in agents.items():
            ctx = handle.context_name.lower()
            nm = name.lower()
            if any(p in ctx or p == nm for p in patterns):
                return {name: handle}
        return None


# ── Register ──────────────────────────────────────────────────────

TopologyRegistry.register("ooda", OODATopology)
