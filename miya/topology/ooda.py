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

import logging
from typing import Any, AsyncIterator

from miya.shared.blackboard import Blackboard
from miya.shared.events import (
    DomainEvent,
    MissionStarted,
    MissionCompleted,
    MissionFailed,
    PhaseTransition,
    ReflectionCompleted,
)
from miya.shared.ports import CoordinatorPort, EventStorePort
from miya.shared.types import Mission, OODAPhase, MissionType
from miya.topology.base import (
    Topology, TopologyRegistry, AgentHandle,
    extract_events_from_output, _sdk_env, EVENT_INSTRUCTION,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
#  Phase prompts — what the coordinator does in each OODA phase
# ═══════════════════════════════════════════════════════════════════

_OBSERVE_PROMPT = """## Phase: OBSERVE (Information Gathering)

You are in the OBSERVE phase of the OODA loop.

**Current Blackboard State:**
{blackboard_context}

**Mission:** {mission_description}

**Your task:** Gather information about the target. Use the appropriate reconnaissance
agents to discover assets, entry points, or challenge details.

Delegate to the right agent(s) based on the mission type:
{agent_descriptions}

Focus on breadth — discover as much about the target as possible.
"""

_ORIENT_PROMPT = """## Phase: ORIENT (Analysis & Pattern Recognition)

You are in the ORIENT phase of the OODA loop.

**Current Blackboard State:**
{blackboard_context}

**Mission:** {mission_description}

**Observations from previous phase:**
{observe_output}

**Your task:** Analyze the gathered information. Identify:
1. Attack vectors and vulnerabilities
2. Patterns and anomalies
3. Priority targets (highest impact, lowest effort)
4. Missing information that needs further investigation

Do NOT execute attacks yet. Analyze and prioritize.
Output a ranked list of opportunities with rationale.
"""

_DECIDE_PROMPT = """## Phase: DECIDE (Action Planning)

You are in the DECIDE phase of the OODA loop.

**Current Blackboard State:**
{blackboard_context}

**Mission:** {mission_description}

**Analysis from ORIENT phase:**
{orient_output}

**Your task:** Create a concrete action plan:
1. What specific attack/analysis to attempt next
2. Which agent(s) to use
3. What parameters/payloads to try
4. Success criteria — how do we know if it worked?
5. Fallback plan if the primary attempt fails

Be specific. The ACT phase will execute your plan.
"""

_ACT_PROMPT = """## Phase: ACT (Execution)

You are in the ACT phase of the OODA loop.

**Current Blackboard State:**
{blackboard_context}

**Mission:** {mission_description}

**Action Plan from DECIDE phase:**
{decide_output}

**Your task:** Execute the plan. Delegate to the appropriate specialized agent(s):
{agent_descriptions}

Execute the planned actions and report results with evidence.
"""

_REFLECT_PROMPT = """## Phase: REFLECT (Evaluation Gate)

You are at the REFLECTION GATE of the OODA loop.

**Current Blackboard State:**
{blackboard_context}

**Mission:** {mission_description}

**Actions taken and results:**
{act_output}

**Previous reflection insights (if any):**
{previous_insights}

**Your task:** Evaluate the results and make ONE of these decisions:

1. **CONTINUE** — Progress was made, continue the OODA loop to deepen the attack
2. **PIVOT** — Current approach isn't working, try a different strategy in the next loop
3. **COMPLETE** — Mission objective achieved, generate final report

Respond EXACTLY in this format (each field on its own line):
DECISION: <continue|pivot|complete>
ASSESSMENT: <what happened and why>
INSIGHTS: <what we learned>
NEXT_FOCUS: <what to focus on in the next loop iteration, if continuing>
"""


class OODATopology:
    """OODA loop orchestration with reflection gate."""

    def __init__(
        self,
        max_iterations: int = 10,
        coordinator: CoordinatorPort | None = None,
    ) -> None:
        self._max_iterations = max_iterations
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
    ) -> AsyncIterator[DomainEvent]:
        """Run the OODA loop until completion or max iterations."""

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

        observe_output = ""
        orient_output = ""
        decide_output = ""
        act_output = ""
        previous_insights = ""

        for iteration in range(1, self._max_iterations + 1):
            logger.info(f"OODA iteration {iteration}/{self._max_iterations}")

            # ── OBSERVE ───────────────────────────────────────────
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

            observe_prompt = _OBSERVE_PROMPT.format(
                blackboard_context=blackboard.to_context_prompt(),
                mission_description=mission_desc,
                agent_descriptions=agent_desc,
            ) + EVENT_INSTRUCTION

            observe_output = await self._run_coordinator(
                observe_prompt, mission, agents, blackboard
            )

            for extracted in extract_events_from_output(observe_output, mission):
                yield extracted
                blackboard.apply(extracted)

            # ── ORIENT ────────────────────────────────────────────
            yield PhaseTransition(
                from_phase=OODAPhase.OBSERVE.value,
                to_phase=OODAPhase.ORIENT.value,
                aggregate_id=mission.id,
                mission=mission.mission_type.value,
            )

            orient_prompt = _ORIENT_PROMPT.format(
                blackboard_context=blackboard.to_context_prompt(),
                mission_description=mission_desc,
                observe_output=observe_output[:4000],
            ) + EVENT_INSTRUCTION
            orient_output = await self._run_coordinator(
                orient_prompt, mission, agents, blackboard
            )

            for extracted in extract_events_from_output(orient_output, mission):
                yield extracted
                blackboard.apply(extracted)

            # ── DECIDE ────────────────────────────────────────────
            yield PhaseTransition(
                from_phase=OODAPhase.ORIENT.value,
                to_phase=OODAPhase.DECIDE.value,
                aggregate_id=mission.id,
                mission=mission.mission_type.value,
            )

            decide_prompt = _DECIDE_PROMPT.format(
                blackboard_context=blackboard.to_context_prompt(),
                mission_description=mission_desc,
                orient_output=orient_output[:4000],
            )
            decide_output = await self._run_coordinator(
                decide_prompt, mission, agents, blackboard
            )

            # ── ACT ───────────────────────────────────────────────
            yield PhaseTransition(
                from_phase=OODAPhase.DECIDE.value,
                to_phase=OODAPhase.ACT.value,
                aggregate_id=mission.id,
                mission=mission.mission_type.value,
            )

            act_prompt = _ACT_PROMPT.format(
                blackboard_context=blackboard.to_context_prompt(),
                mission_description=mission_desc,
                decide_output=decide_output[:4000],
                agent_descriptions=agent_desc,
            ) + EVENT_INSTRUCTION
            act_output = await self._run_coordinator(
                act_prompt, mission, agents, blackboard
            )

            for extracted in extract_events_from_output(act_output, mission):
                yield extracted
                blackboard.apply(extracted)

            # ── REFLECT ───────────────────────────────────────────
            yield PhaseTransition(
                from_phase=OODAPhase.ACT.value,
                to_phase=OODAPhase.REFLECT.value,
                aggregate_id=mission.id,
                mission=mission.mission_type.value,
            )

            reflect_prompt = _REFLECT_PROMPT.format(
                blackboard_context=blackboard.to_context_prompt(),
                mission_description=mission_desc,
                act_output=act_output[:4000],
                previous_insights=previous_insights or "(first iteration)",
            )
            reflect_output = await self._run_coordinator(
                reflect_prompt, mission, agents, blackboard
            )

            decision = self._parse_reflection(reflect_output)
            previous_insights = decision.get("next_focus", "") or decision.get("insights", "")

            reflection_event = ReflectionCompleted(
                aggregate_id=mission.id,
                assessment=decision.get("assessment", ""),
                decision=decision.get("decision", "continue"),
                insights=decision.get("insights", ""),
                mission=mission.mission_type.value,
            )
            yield reflection_event
            blackboard.apply(reflection_event)

            if decision.get("decision") == "complete":
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

        # Fallback: use Claude Agent SDK directly
        return await self._run_sdk_coordinator(
            prompt, agent_defs, list(all_mcp_names)
        )

    async def _run_sdk_coordinator(
        self,
        prompt: str,
        agent_defs: dict[str, Any],
        mcp_names: list[str],
    ) -> str:
        """Run coordinator via Claude Agent SDK (production path)."""
        from claude_agent_sdk import query, ClaudeAgentOptions, AgentDefinition
        from miya.infra.mcp_registry import MCPRegistry

        registry = MCPRegistry()
        sdk_agents = {
            name: AgentDefinition(**defn)
            for name, defn in agent_defs.items()
        }
        mcp_configs = registry.get_configs_for_agent(mcp_names)

        options = ClaudeAgentOptions(
            agents=sdk_agents,
            mcp_servers=mcp_configs,
            allowed_tools=[
                "Read", "Write", "Edit", "Bash", "Grep", "Glob",
                "WebSearch", "WebFetch", "Agent",
            ] + [f"mcp__{name}__*" for name in mcp_names],
            permission_mode="acceptEdits",
            max_turns=30,
            env=_sdk_env(),
        )

        output_parts: list[str] = []
        async for message in query(prompt=prompt, options=options):
            if hasattr(message, "content"):
                for block in message.content:
                    if hasattr(block, "text"):
                        output_parts.append(block.text)

        return "\n".join(output_parts)

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


# ── Register ──────────────────────────────────────────────────────

TopologyRegistry.register("ooda", OODATopology)
