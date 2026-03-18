"""AttackGraph Topology — DAG-based strategic planning and tactical execution.

This topology models the penetration test as a graph problem:
1. Build an attack graph from reconnaissance data
2. Plan the optimal attack path (lowest cost, highest probability)
3. Execute each step with the appropriate agent
4. After each step, update the graph and re-plan if topology changed

Inspired by MITRE ATT&CK framework and automated attack planning research.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, AsyncIterator

from miya.shared.attack_graph import AttackGraph, GraphNode, GraphEdge
from miya.shared.blackboard import Blackboard
from miya.shared.events import (
    DomainEvent,
    MissionStarted,
    MissionCompleted,
    MissionFailed,
    OperatorMessage,
    PhaseTransition,
)
from miya.shared.ports import CoordinatorPort, EventStorePort
from miya.shared.types import Mission
from miya.topology.base import (
    Topology, TopologyRegistry, AgentHandle,
    extract_events_from_output, _sdk_env, EVENT_INSTRUCTION,
    run_sdk_coordinator, _get_topology_config,
)

logger = logging.getLogger(__name__)


_PLAN_PROMPT = """## Strategic Planner — Attack Path Selection

You are the strategic planner for a penetration test.

**Current Attack Graph:**
{graph_summary}

**Exploited Nodes:**
{exploited_nodes}

**Available Edges (unexplored attack paths):**
{unexplored_edges}

**Shortest Path to Objective:**
{shortest_path}

**All Available Paths:**
{all_paths}

**Mission:** {mission_description}

**Your task:** Select the next attack step to execute.

Consider:
1. Expected success probability
2. Cost (complexity, noise level, time)
3. Information gain (even failed attempts reveal information)
4. Prerequisites (do we have the access needed?)

Output format:
SELECTED_EDGE: <edge_id>
AGENT: <agent_name_to_use>
RATIONALE: <why this step>
PREPARATION: <any preparation needed before execution>
"""

_EXECUTE_PROMPT = """## Tactical Executor — Step Execution

You are executing a specific attack step.

**Step Details:**
- Technique: {technique}
- Source: {source_node}
- Target: {target_node}
- Agent: {agent_name}

**Current Blackboard:**
{blackboard_context}

**Preparation Instructions:**
{preparation}

**Your task:** Execute this attack step using the designated agent.

At the END of your response, report the overall result on a single line:
RESULT: SUCCESS <what was gained>
or
RESULT: FAILURE <why it failed>
"""

_REBUILD_PROMPT = """## Graph Update — Post-Execution Analysis

The following attack step was just executed:
**Technique:** {technique}
**Result:** {result}

**Current Attack Graph:**
{graph_summary}

**Current Blackboard:**
{blackboard_context}

**Your task:** Based on the execution result, identify:
1. New nodes to add (newly discovered assets, services, access levels)
2. New edges to add (newly discovered attack paths)
3. Nodes/edges to update (status changes)
4. Whether the objective has been reached

Output in structured format:
NEW_NODES: <list of new nodes with properties>
NEW_EDGES: <list of new edges with source→target>
STATUS_UPDATES: <list of node/edge status changes>
OBJECTIVE_REACHED: <yes/no>
"""


class AttackGraphTopology:
    """Graph-based attack planning and execution topology."""

    def __init__(
        self,
        max_steps: int | None = None,
        coordinator: CoordinatorPort | None = None,
    ) -> None:
        cfg = _get_topology_config()
        self._max_steps = max_steps if max_steps is not None else cfg["ag_max_steps"]
        self._coordinator = coordinator

    @property
    def name(self) -> str:
        return "attack_graph"

    @property
    def description(self) -> str:
        return (
            "Attack Graph topology — models the pentest as a DAG. "
            "Strategic planner selects optimal paths, tactical executor carries them out. "
            "Graph updates dynamically as new information is discovered."
        )

    async def execute(
        self,
        mission: Mission,
        blackboard: Blackboard,
        agents: dict[str, AgentHandle],
        event_store: EventStorePort,
        operator_queue: asyncio.Queue[str] | None = None,
    ) -> AsyncIterator[DomainEvent]:
        """Execute the mission using attack graph planning."""

        # ── Mission Start ─────────────────────────────────────────
        start_event = MissionStarted(
            aggregate_id=mission.id,
            mission_type=mission.mission_type.value,
            target_uri=mission.target.uri,
            topology=self.name,
            mission=mission.mission_type.value,
        )
        yield start_event
        blackboard.apply(start_event)

        graph = blackboard.attack_graph
        mission_desc = f"{mission.mission_type.value}: {mission.target}"

        # ── Operator initial prompt ───────────────────────────────
        operator_prompt = ""
        if mission.prompt:
            operator_prompt = (
                f"\n\n## Operator Instructions\n{mission.prompt}\n"
            )
            logger.info("📋 Operator prompt: %s", mission.prompt[:120])

        # ── Phase 1: Initial Recon to Build Graph ─────────────────
        yield PhaseTransition(
            to_phase="recon",
            reason="Build initial attack graph",
            aggregate_id=mission.id,
            mission=mission.mission_type.value,
        )

        # Initialize graph with root node (attacker) and objective
        if not graph.root_id:
            root = graph.add_node(GraphNode(
                label="Attacker",
                node_type="access",
                properties={"level": "external"},
                status="exploited",
            ))
            graph.set_root(root.id)

            objective = graph.add_node(GraphNode(
                label="Objective",
                node_type="objective",
                properties={"type": mission.mission_type.value},
            ))
            graph.add_objective(objective.id)

        # Run recon agent to discover initial attack surface
        recon_agents = {k: v for k, v in agents.items()
                       if v.context_name in ("recon", "entrypoint", "web", "pwn", "crypto", "reverse", "misc")}
        if recon_agents:
            recon_prompt = (
                f"Reconnaissance phase. Target: {mission.target}\n"
                f"Discover the attack surface. Report all assets, services, "
                f"entry points, and potential vulnerabilities found.\n"
                f"Blackboard:\n{blackboard.to_context_prompt()}\n"
                + operator_prompt + EVENT_INSTRUCTION
            )
            recon_output = await self._run_agent(recon_prompt, mission, agents, blackboard)

            for extracted in extract_events_from_output(recon_output, mission):
                yield extracted
                blackboard.apply(extracted)

        # ── Phase 2: Plan-Execute Loop ────────────────────────────
        for step in range(1, self._max_steps + 1):
            logger.info("━━━━ AG step %d/%d ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", step, self._max_steps)

            # ── Drain HITL queue ──────────────────────────────────
            hitl_extra = ""
            if operator_queue is not None:
                hitl_msgs: list[str] = []
                while not operator_queue.empty():
                    try:
                        hitl_msgs.append(operator_queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                if hitl_msgs:
                    for m in hitl_msgs:
                        logger.info("📨 Operator HITL: %s", m[:120])
                        ev = OperatorMessage(
                            aggregate_id=mission.id, content=m,
                            mission=mission.mission_type.value,
                        )
                        yield ev
                        blackboard.apply(ev)
                    hitl_extra = (
                        "\n\n## Operator Live Directives\n"
                        + "\n".join(f"- {m}" for m in hitl_msgs) + "\n"
                    )

            # Check if we have unexplored edges
            unexplored = graph.get_unexplored_edges()
            if not unexplored and step > 1:
                # Try to discover more edges
                yield PhaseTransition(
                    from_phase="execute",
                    to_phase="recon",
                    reason="No unexplored edges, gathering more intel",
                    aggregate_id=mission.id,
                    mission=mission.mission_type.value,
                )
                await self._run_agent(
                    f"Additional recon needed. Current graph: {graph.summary()}\n"
                    f"Blackboard:\n{blackboard.to_context_prompt()}",
                    mission, agents, blackboard,
                )
                unexplored = graph.get_unexplored_edges()
                if not unexplored:
                    break  # No more paths to try

            # ── PLAN ──────────────────────────────────────────────
            yield PhaseTransition(
                from_phase="recon" if step == 1 else "execute",
                to_phase="plan",
                reason=f"Step {step}: selecting attack path",
                aggregate_id=mission.id,
                mission=mission.mission_type.value,
            )

            shortest = graph.find_shortest_path()
            all_paths = graph.find_all_paths(max_depth=5)

            plan_prompt = _PLAN_PROMPT.format(
                graph_summary=graph.summary(),
                exploited_nodes="\n".join(
                    f"- {n.label} ({n.node_type})" for n in graph.get_exploited_nodes()
                ) or "None yet",
                unexplored_edges="\n".join(
                    f"- [{e.id[:8]}] {e.label} (cost={e.cost:.1f}, p={e.probability:.1%})"
                    for e in unexplored[:10]
                ),
                shortest_path=" → ".join(e.label for e in shortest) if shortest else "No path found",
                all_paths="\n".join(
                    f"- Path {i+1}: {' → '.join(e.label for e in p)} "
                    f"(cost={sum(e.expected_cost for e in p):.1f})"
                    for i, p in enumerate(all_paths[:5])
                ) or "No paths available",
                mission_description=mission_desc,
            ) + operator_prompt + hitl_extra

            plan_output = await self._run_agent(plan_prompt, mission, agents, blackboard)

            # Parse plan output: extract SELECTED_EDGE and AGENT
            selected_edge, selected_agent = self._parse_plan(
                plan_output, unexplored, agents,
            )
            if not selected_edge:
                selected_edge = unexplored[0] if unexplored else None
            if not selected_edge:
                break

            # ── EXECUTE ───────────────────────────────────────────
            yield PhaseTransition(
                from_phase="plan",
                to_phase="execute",
                reason=f"Step {step}: {selected_edge.label}",
                aggregate_id=mission.id,
                mission=mission.mission_type.value,
            )

            source_node = graph.nodes.get(selected_edge.source_id)
            target_node = graph.nodes.get(selected_edge.target_id)

            exec_prompt = _EXECUTE_PROMPT.format(
                technique=selected_edge.label,
                source_node=f"{source_node.label}" if source_node else "unknown",
                target_node=f"{target_node.label}" if target_node else "unknown",
                agent_name=selected_agent or next(iter(agents), ""),
                blackboard_context=blackboard.to_context_prompt(),
                preparation=plan_output[:3000],
            ) + operator_prompt + hitl_extra + EVENT_INSTRUCTION

            exec_output = await self._run_agent(exec_prompt, mission, agents, blackboard)

            for extracted in extract_events_from_output(exec_output, mission):
                yield extracted
                blackboard.apply(extracted)

            # Determine success via RESULT: line, with fallback heuristics
            succeeded = self._detect_success(exec_output)

            if succeeded:
                graph.update_edge_status(selected_edge.id, "succeeded")
                if target_node:
                    graph.update_node_status(target_node.id, "exploited")
            else:
                graph.update_edge_status(selected_edge.id, "failed")

            # ── REBUILD — analyze result and update graph ─────────
            rebuild_prompt = _REBUILD_PROMPT.format(
                technique=selected_edge.label,
                result=exec_output[:3000],
                graph_summary=graph.summary(),
                blackboard_context=blackboard.to_context_prompt(),
            )
            rebuild_output = await self._run_agent(rebuild_prompt, mission, agents, blackboard)

            # Extract events from rebuild analysis
            for extracted in extract_events_from_output(rebuild_output, mission):
                yield extracted
                blackboard.apply(extracted)

            # Check if objective reached (via OBJECTIVE_REACHED or graph state)
            obj_reached = bool(re.search(
                r"OBJECTIVE_REACHED\s*:\s*yes", rebuild_output, re.IGNORECASE
            ))
            if obj_reached:
                yield MissionCompleted(
                    aggregate_id=mission.id,
                    findings_count=len(blackboard.findings),
                    mission=mission.mission_type.value,
                )
                return

            for obj_id in graph.objective_ids:
                obj_node = graph.nodes.get(obj_id)
                if obj_node and obj_node.status == "exploited":
                    yield MissionCompleted(
                        aggregate_id=mission.id,
                        findings_count=len(blackboard.findings),
                        mission=mission.mission_type.value,
                    )
                    return

        # ── Mission Complete ──────────────────────────────────────
        yield MissionCompleted(
            aggregate_id=mission.id,
            findings_count=len(blackboard.findings),
            mission=mission.mission_type.value,
        )

    @staticmethod
    def _parse_plan(
        plan_output: str,
        available_edges: list[GraphEdge],
        available_agents: dict[str, Any],
    ) -> tuple[GraphEdge | None, str]:
        """Extract SELECTED_EDGE and AGENT from planner output.

        Returns (edge, agent_name). agent_name may be empty if not parsed.
        """
        # Parse agent name
        agent_name = ""
        agent_match = re.search(r"AGENT\s*:\s*(\S+)", plan_output, re.IGNORECASE)
        if agent_match:
            candidate = agent_match.group(1).strip().lower()
            # Match against available agents (case-insensitive)
            for name in available_agents:
                if name.lower() == candidate:
                    agent_name = name
                    break

        # Parse edge
        edge_match = re.search(r"SELECTED_EDGE\s*:\s*(\S+)", plan_output, re.IGNORECASE)
        if not edge_match:
            # Fallback: try matching by label
            for edge in available_edges:
                if edge.label.lower() in plan_output.lower():
                    return edge, agent_name
            return None, agent_name

        edge_id_prefix = edge_match.group(1).strip().lower()
        for edge in available_edges:
            if edge.id.lower().startswith(edge_id_prefix):
                return edge, agent_name
        # Fallback: try matching by label
        for edge in available_edges:
            if edge.label.lower() in plan_output.lower():
                return edge, agent_name
        return None, agent_name

    @staticmethod
    def _detect_success(exec_output: str) -> bool:
        """Detect whether an execution step succeeded.

        Uses RESULT: line if present, falls back to heuristics.
        """
        # Primary: look for RESULT: SUCCESS / RESULT: FAILURE
        match = re.search(r"RESULT\s*:\s*(SUCCESS|FAILURE)", exec_output, re.IGNORECASE)
        if match:
            return match.group(1).upper() == "SUCCESS"

        # Check for ExploitSucceeded events (most reliable signal)
        if "[EVENT:ExploitSucceeded" in exec_output or "[EVENT:ChallengeSolved" in exec_output:
            return True
        if "[EVENT:ExploitFailed" in exec_output:
            return False

        # Heuristic fallback: explicit success/failure phrases
        lower = exec_output.lower()
        success_phrases = (
            "successfully exploited", "access gained", "shell obtained",
            "flag found", "flag{", "root access", "session opened",
        )
        failure_phrases = (
            "exploit failed", "not vulnerable", "connection refused",
            "access denied", "timed out", "no session",
        )
        success_score = sum(1 for p in success_phrases if p in lower)
        failure_score = sum(1 for p in failure_phrases if p in lower)
        return success_score > failure_score

    async def _run_agent(
        self,
        prompt: str,
        mission: Mission,
        agents: dict[str, AgentHandle],
        blackboard: Blackboard,
    ) -> str:
        """Run coordinator with prompt, return text output."""
        all_mcp_names: set[str] = set()
        for handle in agents.values():
            all_mcp_names.update(handle.mcp_servers)

        agent_defs = {
            name: handle.to_agent_definition()
            for name, handle in agents.items()
        }

        if self._coordinator is not None:
            return await self._coordinator.run(
                prompt=prompt,
                agents=agent_defs,
                mcp_servers=list(all_mcp_names),
            )

        # Fallback: shared Claude Agent SDK coordinator
        return await run_sdk_coordinator(prompt, agent_defs, list(all_mcp_names))


# ── Register ──────────────────────────────────────────────────────

TopologyRegistry.register("attack_graph", AttackGraphTopology)
