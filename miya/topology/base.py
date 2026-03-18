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

    This allows topologies to yield real domain events from LLM output,
    populating the blackboard with findings, assets, CVEs, etc.
    """
    import dataclasses
    from miya.shared.events import _EVENT_REGISTRY

    events: list[DomainEvent] = []
    pattern = r'\[EVENT:(\w+)\s+'

    for match in re.finditer(pattern, output):
        event_type_name = match.group(1)

        # Extract JSON with balanced braces, respecting string quoting
        json_start = match.end()
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
            continue
        raw_json = output[json_start:json_end]

        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse event data: {raw_json[:100]}")
            continue

        # Map class name to event class
        event_cls = None
        for etype, cls in _EVENT_REGISTRY.items():
            if cls.__name__ == event_type_name:
                event_cls = cls
                break

        if event_cls is None:
            logger.warning(f"Unknown event type: {event_type_name}")
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
            logger.warning(f"Failed to create {event_type_name}: {e}")

    return events


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
