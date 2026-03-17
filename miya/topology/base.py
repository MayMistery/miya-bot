"""Topology Protocol and Registry — the strategy pattern for agent orchestration.

Each topology defines HOW agents are orchestrated. The domain contexts define
WHAT agents do. This separation allows switching orchestration strategies
without touching domain code.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Callable, Protocol, runtime_checkable

from miya.shared.blackboard import Blackboard
from miya.shared.events import DomainEvent
from miya.shared.ports import EventStorePort
from miya.shared.types import Mission


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
