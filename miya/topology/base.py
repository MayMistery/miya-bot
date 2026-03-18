"""Topology Protocol and Registry — the strategy pattern for agent orchestration.

Each topology defines HOW agents are orchestrated. The domain contexts define
WHAT agents do. This separation allows switching orchestration strategies
without touching domain code.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, AsyncIterator, Callable, Protocol, runtime_checkable

from claude_agent_sdk.types import (
    AssistantMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)

from miya.shared.blackboard import Blackboard
from miya.shared.events import DomainEvent
from miya.shared.ports import EventStorePort
from miya.shared.types import Mission

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
#  Agent Handle
# ═══════════════════════════════════════════════════════════════════


class AgentHandle:
    """Abstract handle to a Claude sub-agent.

    Wraps the agent definition and its MCP server requirements.
    The topology uses these to invoke agents during execution.
    """

    def __init__(
        self,
        name: str,
        description: str,
        system_prompt: str,
        tools: list[str],
        mcp_servers: list[str],
        model: str = "opus",
        context_name: str = "",
        mission_type: str = "",
    ) -> None:
        self.name = name
        self.description = description
        self.system_prompt = system_prompt
        self.tools = tools
        self.mcp_servers = mcp_servers
        self.model = model
        self.context_name = context_name
        self.mission_type = mission_type

    def to_agent_definition(self) -> dict[str, Any]:
        """Convert to Claude Agent SDK AgentDefinition format."""
        return {
            "description": self.description,
            "prompt": self.system_prompt,
            "tools": self.tools,
            "model": self.model,
        }


# ═══════════════════════════════════════════════════════════════════
#  Topology Protocol
# ═══════════════════════════════════════════════════════════════════


@runtime_checkable
class Topology(Protocol):
    """Strategy interface for agent orchestration.

    Each topology defines a different way to coordinate agents:
    - OODA: Observe→Orient→Decide→Act loop with reflection
    - AttackGraph: DAG-based path planning and tactical execution
    """

    @property
    def name(self) -> str:
        """Unique topology identifier."""
        ...

    @property
    def description(self) -> str:
        """Human-readable description of this topology's approach."""
        ...

    async def execute(
        self,
        mission: Mission,
        blackboard: Blackboard,
        agents: dict[str, AgentHandle],
        event_store: EventStorePort,
    ) -> AsyncIterator[DomainEvent]:
        """Execute the mission using this topology.

        Yields DomainEvents as the mission progresses.
        The caller is responsible for persisting events to the EventStore.
        """
        ...


# ═══════════════════════════════════════════════════════════════════
#  Topology Registry
# ═══════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════
#  Event Extraction from Coordinator Output
# ═══════════════════════════════════════════════════════════════════


def extract_events_from_output(output: str, mission: Mission) -> list[DomainEvent]:
    """Extract structured domain events from coordinator/agent output.

    The coordinator can embed events in the format:
        [EVENT:EventTypeName {"field": "value", ...}]
        [EVENT:EventTypeName{"field": "value", ...}]   (no space also accepted)

    This allows topologies to yield real domain events from LLM output,
    populating the blackboard with findings, assets, CVEs, etc.
    """
    import dataclasses
    from miya.shared.events import _EVENT_REGISTRY

    # Build a name→class lookup once (cached across calls via closure)
    if not hasattr(extract_events_from_output, "_name_map"):
        extract_events_from_output._name_map = {  # type: ignore[attr-defined]
            cls.__name__: cls for cls in _EVENT_REGISTRY.values()
        }
    name_map: dict[str, type[DomainEvent]] = extract_events_from_output._name_map  # type: ignore[attr-defined]

    events: list[DomainEvent] = []
    # Accept optional whitespace between EventTypeName and the JSON brace
    pattern = r'\[EVENT:(\w+)\s*\{'

    for match in re.finditer(pattern, output):
        event_type_name = match.group(1)

        # Extract JSON with balanced braces, respecting string quoting
        # Start from the opening brace (match.end() - 1 because '{' is in the pattern)
        json_start = match.end() - 1
        depth = 0
        json_end = json_start
        in_string = False
        escape_next = False
        for i in range(json_start, len(output)):
            ch = output[i]
            if escape_next:
                escape_next = False
                continue
            if ch == '\\' and in_string:
                escape_next = True
                continue
            if ch == '"' and not escape_next:
                in_string = not in_string
                continue
            if not in_string:
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        json_end = i + 1
                        break
        if depth != 0:
            logger.warning(
                "Unbalanced braces in event %s at offset %d", event_type_name, json_start
            )
            continue
        raw_json = output[json_start:json_end]

        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse event %s JSON: %s — %s", event_type_name, exc, raw_json[:120])
            continue

        # Map class name to event class (O(1) lookup instead of linear scan)
        event_cls = name_map.get(event_type_name)
        if event_cls is None:
            logger.warning("Unknown event type: %s", event_type_name)
            continue

        # Add mission context if not present
        data.setdefault("mission", mission.mission_type.value)
        data.setdefault("aggregate_id", mission.id)

        # Handle tuple fields
        for f_name in ("ports", "services", "input_vectors", "path", "technology_stack", "target_ports"):
            if f_name in data and isinstance(data[f_name], list):
                data[f_name] = tuple(data[f_name])

        # Filter to valid fields
        valid_fields = {f.name for f in dataclasses.fields(event_cls)}
        filtered = {k: v for k, v in data.items() if k in valid_fields}

        try:
            events.append(event_cls(**filtered))
        except Exception as e:
            logger.warning("Failed to create %s: %s (data=%s)", event_type_name, e, filtered)

    return events


# ═══════════════════════════════════════════════════════════════════
#  Shared EVENT instruction — appended to topology phase prompts
# ═══════════════════════════════════════════════════════════════════

EVENT_INSTRUCTION = """
## Structured Event Output (IMPORTANT)
Throughout your response, emit structured events so findings are captured
in the system's blackboard.  Format:

    [EVENT:EventTypeName {"field": "value", ...}]

Available event types:

**Recon:**
  [EVENT:AssetDiscovered {{"host": "h", "ip": "1.2.3.4", "ports": [80], "services": ["http"], "os": "Linux", "context": "recon"}}]
  [EVENT:FingerprintCompleted {{"software": "Apache", "version": "2.4.52", "technology_stack": ["PHP 8.1"], "context": "recon"}}]

**Vulnerability:**
  [EVENT:ScanCompleted {{"target_host": "1.2.3.4", "target_ports": [80], "findings_count": 2, "scanner": "nuclei", "context": "scan"}}]
  [EVENT:VulnerabilityFound {{"vuln_id": "CVE-...", "vuln_type": "RCE", "cwe_id": "CWE-502", "severity": "critical", "location": "...", "description": "...", "context": "vuln"}}]
  [EVENT:CVEMatched {{"cve_id": "CVE-...", "cvss": 9.8, "affected_software": "...", "exploit_available": true, "context": "vuln"}}]

**Exploit:**
  [EVENT:ExploitAttempted {{"cve_id": "CVE-...", "technique": "...", "payload_summary": "...", "context": "exploit"}}]
  [EVENT:ExploitSucceeded {{"cve_id": "CVE-...", "access_gained": "root", "evidence": "uid=0(root)", "context": "exploit"}}]
  [EVENT:ExploitFailed {{"cve_id": "CVE-...", "reason": "...", "context": "exploit"}}]

**Post-exploit:**
  [EVENT:PrivilegeEscalated {{"from_level": "user", "to_level": "root", "technique": "...", "context": "post"}}]
  [EVENT:LootCollected {{"loot_type": "credentials", "description": "...", "value": "...", "context": "post"}}]

**0-day:**
  [EVENT:EntryPointDiscovered {{"location": "file:line", "input_type": "http_parameter", "input_vectors": ["param:id"], "risk_level": "high", "context": "entrypoint"}}]
  [EVENT:TaintPathTraced {{"source": "...", "sink": "...", "path": ["..."], "sanitized": false, "context": "dataflow"}}]
  [EVENT:SinkConfirmed {{"sink_type": "sql_injection", "location": "...", "confidence": "high", "impact": "...", "context": "sink"}}]
  [EVENT:PoCValidated {{"vulnerability": "...", "poc_type": "exploit_script", "success": true, "impact": "...", "context": "poc"}}]

**CTF:**
  [EVENT:ChallengeIdentified {{"challenge_name": "...", "category": "web", "difficulty": "medium", "technology_stack": ["PHP"], "context": "ctf"}}]
  [EVENT:ChallengeSolved {{"challenge_name": "...", "flag": "flag{{...}}", "technique": "...", "context": "ctf"}}]

Emit events inline in your response as you discover things. Every finding MUST have an EVENT marker.
"""


def _sdk_env() -> dict[str, str]:
    """Build env overrides for ClaudeAgentOptions from Miya config env vars.

    Supported env vars:
        ANTHROPIC_API_KEY   — Anthropic API key
        ANTHROPIC_BASE_URL  — Custom API base URL (e.g. for proxies or bedrock)
    """
    env: dict[str, str] = {}
    for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"):
        val = os.environ.get(key)
        if val:
            env[key] = val
    return env


def _get_topology_config() -> dict[str, int]:
    """Read topology tunables from environment.

    Supported env vars:
        MIYA_OODA_MAX_ITERATIONS  — max OODA loop iterations (default 10)
        MIYA_AG_MAX_STEPS         — max attack-graph steps  (default 20)
        MIYA_MAX_TURNS            — max SDK turns per coordinator call (default 30)
    """
    def _int(key: str, default: int) -> int:
        raw = os.environ.get(key, "")
        try:
            return int(raw) if raw else default
        except ValueError:
            return default

    return {
        "ooda_max_iterations": _int("MIYA_OODA_MAX_ITERATIONS", 10),
        "ag_max_steps": _int("MIYA_AG_MAX_STEPS", 20),
        "max_turns": _int("MIYA_MAX_TURNS", 30),
    }


def _truncate_for_log(text: str, max_len: int = 200) -> str:
    """Truncate text for log display."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"... ({len(text)} chars)"


async def run_sdk_coordinator(
    prompt: str,
    agent_defs: dict[str, Any],
    mcp_names: list[str],
) -> str:
    """Shared coordinator execution via Claude Agent SDK.

    Centralises the SDK call so both OODA and AttackGraph topologies
    use the same code path, reducing duplication.

    Logging behaviour (controlled via ``-v`` / ``-vv``):
        TRACE  — every tool_use call (name + input), tool_result, and text block
        DEBUG  — prompt summary and total output length
    """
    from claude_agent_sdk import query, ClaudeAgentOptions, AgentDefinition
    from miya.infra.mcp_registry import MCPRegistry
    from miya.infra.logging_config import TRACE

    registry = MCPRegistry()
    sdk_agents = {
        name: AgentDefinition(**defn)
        for name, defn in agent_defs.items()
    }
    mcp_configs = registry.get_configs_for_agent(mcp_names)
    cfg = _get_topology_config()

    options = ClaudeAgentOptions(
        agents=sdk_agents,
        mcp_servers=mcp_configs,
        allowed_tools=[
            "Read", "Write", "Edit", "Bash", "Grep", "Glob",
            "WebSearch", "WebFetch", "Agent",
        ] + [f"mcp__{name}__*" for name in mcp_names],
        permission_mode="acceptEdits",
        max_turns=cfg["max_turns"],
        env=_sdk_env(),
    )

    logger.debug("SDK coordinator prompt (%d chars): %s", len(prompt), _truncate_for_log(prompt, 300))

    output_parts: list[str] = []
    turn_count = 0
    tool_use_count = 0

    async for message in query(prompt=prompt, options=options):
        turn_count += 1

        # ── AssistantMessage: contains text, tool_use, tool_result blocks ──
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    output_parts.append(block.text)
                    if logger.isEnabledFor(TRACE):
                        logger.log(TRACE, "text_block: %s", _truncate_for_log(block.text, 500))

                elif isinstance(block, ToolUseBlock):
                    tool_use_count += 1
                    if logger.isEnabledFor(TRACE):
                        input_str = json.dumps(block.input, default=str) if isinstance(block.input, dict) else str(block.input)
                        logger.log(
                            TRACE,
                            "tool_use  #%d: %s(%s)",
                            tool_use_count, block.name, _truncate_for_log(input_str, 400),
                        )

                elif isinstance(block, ToolResultBlock):
                    if logger.isEnabledFor(TRACE):
                        content = block.content or ""
                        if isinstance(content, list):
                            content = " ".join(
                                c.get("text", str(c)) if isinstance(c, dict) else str(c)
                                for c in content
                            )
                        logger.log(
                            TRACE,
                            "tool_result: %s",
                            _truncate_for_log(str(content), 400),
                        )

        # ── UserMessage: tool results come back as UserMessage ──
        elif isinstance(message, UserMessage) and isinstance(message.content, list):
            for block in message.content:
                if isinstance(block, ToolResultBlock) and logger.isEnabledFor(TRACE):
                    content = block.content or ""
                    if isinstance(content, list):
                        content = " ".join(
                            c.get("text", str(c)) if isinstance(c, dict) else str(c)
                            for c in content
                        )
                    logger.log(
                        TRACE,
                        "tool_result: %s",
                        _truncate_for_log(str(content), 400),
                    )

    logger.debug(
        "SDK coordinator done: %d turns, %d tool calls, %d chars output",
        turn_count, tool_use_count, sum(len(p) for p in output_parts),
    )

    return "\n".join(output_parts)


TopologyFactory = Callable[..., Topology]


class TopologyRegistry:
    """Registry of available orchestration topologies.

    Usage:
        registry = TopologyRegistry()
        topology = registry.get("ooda")
        async for event in topology.execute(mission, blackboard, agents, store):
            ...

    Extension:
        registry.register("custom", CustomTopology)
    """

    _topologies: dict[str, TopologyFactory] = {}

    @classmethod
    def register(cls, name: str, factory: TopologyFactory) -> None:
        """Register a new topology strategy."""
        cls._topologies[name] = factory

    @classmethod
    def get(cls, name: str, **kwargs: Any) -> Topology:
        """Get and instantiate a topology by name."""
        factory = cls._topologies.get(name)
        if not factory:
            available = ", ".join(cls._topologies.keys())
            raise ValueError(f"Unknown topology '{name}'. Available: {available}")
        return factory(**kwargs)

    @classmethod
    def available(cls) -> list[str]:
        """List registered topology names."""
        return list(cls._topologies.keys())

    @classmethod
    def describe_all(cls) -> list[dict[str, str]]:
        """Describe all registered topologies."""
        result = []
        for name, factory in cls._topologies.items():
            topo = factory()
            result.append({"name": name, "description": topo.description})
        return result
