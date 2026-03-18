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
    MissionFailed,
    OperatorMessage,
    PhaseTransition,
    ReflectionCompleted,
    ChallengeClassified,
    FlagSubmitted,
)
from miya.shared.ports import CoordinatorPort, EventStorePort
from miya.shared.types import Mission, OODAPhase, MissionType
from miya.topology.base import (
    Topology, TopologyRegistry, AgentHandle,
    extract_events_from_output, _sdk_env, EVENT_INSTRUCTION,
    run_sdk_coordinator, _get_topology_config, drain_hitl_queue,
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
2. **Classify**: Based on your exploration, determine the challenge category.
3. **Strategize**: Based on what you found, outline your initial attack approach.

## Response Format
CATEGORY: <web|pwn|crypto|reverse|misc>
CONFIDENCE: <0.0-1.0>
REASONING: <one sentence>

RECON_SUMMARY:
<Multi-line summary of what you discovered during exploration. Include: \
technology stack, key files, identified entry points, initial observations \
about potential vulnerabilities or approach. This will be fed to the specialist \
agent who will solve the challenge.>
"""

# ── Flag submission prompt ────────────────────────────────────────

_FLAG_SUBMIT_INSTRUCTION = """
When you find a flag, also try to submit it. Use curl or the platform's API.
Report the result:
[EVENT:FlagSubmitted {{"challenge_name": "...", "flag": "flag{{...}}", "accepted": true, "response": "...", "context": "ctf"}}]
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
    ) -> None:
        cfg = _get_topology_config()
        self._max_iterations = max_iterations if max_iterations is not None else cfg["ooda_max_iterations"]
        self._coordinator = coordinator

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
        """Run the OODA loop until completion or max iterations."""
        from miya.shared.campaign import Campaign as _Campaign

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
            logger.info("📋 Operator prompt: %s", mission.prompt[:120])

        observe_output = ""
        orient_output = ""
        decide_output = ""
        act_output = ""
        previous_insights = ""
        classified_category = ""  # populated by auto-classify for CTF

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
                logger.info("Auto-classified as: %s", classified_category)
                if recon_summary:
                    logger.info("  recon summary: %s", recon_summary[:120])

        for iteration in range(1, self._max_iterations + 1):
            logger.info(
                "━━━━ OODA #%d/%d ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                iteration, self._max_iterations,
            )
            if previous_insights:
                logger.info("  focus: %s", previous_insights[:120])

            # ── OBSERVE ───────────────────────────────────────────
            hitl_events, op_suffix = _drain_hitl()
            for ev in hitl_events:
                yield ev
                blackboard.apply(ev)

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

            logger.info("▶ OBSERVE — %s", self._PHASE_DESC["OBSERVE"])
            mission_key = mission.mission_type.value
            focus_hint = ""
            if previous_insights:
                focus_hint = (
                    f"\nFocus from last REFLECT: {previous_insights}\n"
                )
            # Inject recon summary from CLASSIFY into first OBSERVE iteration
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

            observe_output = await self._run_coordinator(
                observe_prompt, mission, agents, blackboard, phase_label="OBSERVE"
            )

            for extracted in extract_events_from_output(observe_output, mission):
                yield extracted
                blackboard.apply(extracted)

            # ── CTF fast-path: skip ORIENT+DECIDE, go straight to ACT ──
            # For CTF, the model already knows what to do after OBSERVE.
            # Splitting analysis/planning into separate SDK calls wastes tokens.
            if mission_key == "ctf":
                orient_output = ""
                decide_output = observe_output  # feed observations directly to ACT
            else:
                # ── ORIENT ────────────────────────────────────────
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

                logger.info("▶ ORIENT — %s", self._PHASE_DESC["ORIENT"])
                orient_prompt = _get_phase_prompt(mission_key, "ORIENT").format(
                    blackboard_context=blackboard.to_context_prompt(),
                    mission_description=mission_desc,
                    observe_output=observe_output[:4000],
                ) + op_suffix + EVENT_INSTRUCTION
                orient_output = await self._run_coordinator(
                    orient_prompt, mission, agents, blackboard, phase_label="ORIENT"
                )

                for extracted in extract_events_from_output(orient_output, mission):
                    yield extracted
                    blackboard.apply(extracted)

                # ── DECIDE ────────────────────────────────────────
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

                logger.info("▶ DECIDE — %s", self._PHASE_DESC["DECIDE"])
                decide_prompt = _get_phase_prompt(mission_key, "DECIDE").format(
                    blackboard_context=blackboard.to_context_prompt(),
                    mission_description=mission_desc,
                    orient_output=orient_output[:4000],
                ) + op_suffix
                decide_output = await self._run_coordinator(
                    decide_prompt, mission, agents, blackboard, phase_label="DECIDE"
                )

            # ── ACT ───────────────────────────────────────────────
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

            logger.info("▶ ACT — %s", self._PHASE_DESC["ACT"])
            flag_hint = _FLAG_SUBMIT_INSTRUCTION if mission_key == "ctf" else ""
            act_prompt = _get_phase_prompt(mission_key, "ACT").format(
                blackboard_context=blackboard.to_context_prompt(),
                mission_description=mission_desc,
                decide_output=decide_output[:4000],
                agent_descriptions=agent_desc,
            ) + op_suffix + EVENT_INSTRUCTION + flag_hint

            # Direct agent invocation: if classification is known, only pass the
            # relevant specialist agent to reduce coordinator overhead.
            act_agents = agents
            if classified_category and mission_key == "ctf":
                direct = self._pick_direct_agent(classified_category, agents)
                if direct:
                    act_agents = direct

            act_output = await self._run_coordinator(
                act_prompt, mission, act_agents, blackboard, phase_label="ACT"
            )

            for extracted in extract_events_from_output(act_output, mission):
                yield extracted
                blackboard.apply(extracted)

            # ── REFLECT ───────────────────────────────────────────
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

            logger.info("▶ REFLECT — %s", self._PHASE_DESC["REFLECT"])
            reflect_prompt = _get_phase_prompt(mission_key, "REFLECT").format(
                blackboard_context=blackboard.to_context_prompt(),
                mission_description=mission_desc,
                act_output=act_output[:4000],
                previous_insights=previous_insights or "(first iteration)",
            ) + op_suffix
            reflect_output = await self._run_coordinator(
                reflect_prompt, mission, agents, blackboard, phase_label="REFLECT"
            )

            decision = self._parse_reflection(reflect_output)
            previous_insights = decision.get("next_focus", "") or decision.get("insights", "")
            d = decision.get("decision", "continue")
            _DECISION_ICONS = {"complete": "✓", "pivot": "↻", "continue": "⟳"}
            logger.info(
                "%s %s — %s",
                _DECISION_ICONS.get(d, "?"), d.upper(),
                (decision.get("assessment", "") or decision.get("insights", ""))[:120],
            )

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
            # Loop exhausted without explicit completion
            logger.warning(
                f"OODA loop exhausted after {self._max_iterations} iterations "
                f"without explicit completion"
            )

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
    ) -> str:
        """Run the coordinator agent with a prompt and collect text output."""
        all_mcp_names: set[str] = set()
        for handle in agents.values():
            all_mcp_names.update(handle.mcp_servers)

        agent_defs = {
            name: handle.to_agent_definition()
            for name, handle in agents.items()
        }

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

        for match in pattern.finditer(output):
            key = match.group(1).upper().strip()
            val = match.group(2).strip()
            if key == "DECISION":
                # Extract first valid decision word
                val_lower = val.lower()
                for d in ("complete", "pivot", "continue"):
                    if d in val_lower:
                        result["decision"] = d
                        break
            else:
                result[key.lower()] = val

        # Heuristic fallback: if output mentions "objective achieved" / "flag found"
        # but no DECISION field was parsed, treat as complete
        if result["decision"] == "continue":
            lower = output.lower()
            if any(phrase in lower for phrase in (
                "objective achieved", "mission complete", "flag found",
                "flag{", "ctf{", "successfully exploited", "root access obtained",
            )):
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

        logger.info("▶ CLASSIFY — exploring and classifying challenge")
        try:
            output = await self._run_coordinator(
                classify_prompt, mission, agents, blackboard,
                phase_label="CLASSIFY",
                max_turns=5,  # slightly more turns to allow actual exploration
            )
        except Exception:
            logger.debug("Auto-classify failed, skipping", exc_info=True)
            return "", ""

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
