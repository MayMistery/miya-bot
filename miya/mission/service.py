"""MissionService — the application service that wires everything together.

Receives user requests, assembles the right topology + agents + MCP servers,
executes the mission, and produces a report.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from miya.shared.blackboard import Blackboard
from miya.shared.events import DomainEvent
from miya.shared.ports import CoordinatorPort, EventStorePort
from miya.shared.types import Finding, Mission, MissionType, Target
from miya.infra.event_store import SQLiteEventStore
from miya.infra.mcp_registry import MCPRegistry
from miya.topology.base import AgentHandle, TopologyRegistry

# Ensure topologies are registered
import miya.topology.ooda  # noqa: F401
import miya.topology.attack_graph_topo  # noqa: F401

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
#  Mission Report
# ═══════════════════════════════════════════════════════════════════


@dataclass
class MissionReport:
    """Final output of a mission execution."""

    mission_id: str = ""
    mission_type: str = ""
    target: str = ""
    topology: str = ""
    findings: list[Finding] = field(default_factory=list)
    events_count: int = 0
    duration_seconds: float = 0.0
    blackboard_summary: dict[str, Any] = field(default_factory=dict)
    status: str = "completed"

    @property
    def critical_count(self) -> int:
        return len([f for f in self.findings if f.severity.score >= 4])

    def as_text(self) -> str:
        """Render report as formatted text."""
        lines = [
            f"{'═' * 60}",
            f"  MISSION REPORT: {self.mission_type.upper()}",
            f"{'═' * 60}",
            f"  Target:   {self.target}",
            f"  Topology: {self.topology}",
            f"  Status:   {self.status}",
            f"  Duration: {self.duration_seconds:.1f}s",
            f"  Events:   {self.events_count}",
            f"",
            f"  FINDINGS ({len(self.findings)} total, {self.critical_count} critical)",
            f"{'─' * 60}",
        ]
        for f in sorted(self.findings, key=lambda x: -x.severity.score):
            lines.append(f"  {f.oneliner()}")
            if f.detail:
                lines.append(f"    {f.detail[:120]}")
            if f.evidence:
                lines.append(f"    Evidence: {f.evidence[:80]}")
            lines.append("")

        lines.append(f"{'═' * 60}")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
#  Agent Registry — maps mission types to their agents
# ═══════════════════════════════════════════════════════════════════


def _build_oneday_agents() -> dict[str, AgentHandle]:
    """Import and build 1-day kill chain agents."""
    try:
        from miya.oneday.recon.agent import create_agent as recon
        from miya.oneday.scan.agent import create_agent as scan
        from miya.oneday.vuln.agent import create_agent as vuln
        from miya.oneday.exploit.agent import create_agent as exploit
        from miya.oneday.post.agent import create_agent as post
        return {
            "recon": recon(),
            "scan": scan(),
            "vuln": vuln(),
            "exploit": exploit(),
            "post": post(),
        }
    except ImportError as e:
        logger.warning(f"Could not load oneday agents: {e}")
        return {}


def _build_zeroday_agents() -> dict[str, AgentHandle]:
    """Import and build 0-day API chain agents."""
    try:
        from miya.zeroday.entrypoint.agent import create_agent as entrypoint
        from miya.zeroday.dataflow.agent import create_agent as dataflow
        from miya.zeroday.sink.agent import create_agent as sink
        from miya.zeroday.poc.agent import create_agent as poc
        return {
            "entrypoint": entrypoint(),
            "dataflow": dataflow(),
            "sink": sink(),
            "poc": poc(),
        }
    except ImportError as e:
        logger.warning(f"Could not load zeroday agents: {e}")
        return {}


def _build_ctf_agents() -> dict[str, AgentHandle]:
    """Import and build CTF agents."""
    try:
        from miya.ctf.web.agent import create_agent as web
        from miya.ctf.pwn.agent import create_agent as pwn
        from miya.ctf.crypto.agent import create_agent as crypto
        from miya.ctf.reverse.agent import create_agent as reverse
        from miya.ctf.misc.agent import create_agent as misc
        return {
            "web": web(),
            "pwn": pwn(),
            "crypto": crypto(),
            "reverse": reverse(),
            "misc": misc(),
        }
    except ImportError as e:
        logger.warning(f"Could not load ctf agents: {e}")
        return {}


AGENT_BUILDERS = {
    MissionType.ONEDAY: _build_oneday_agents,
    MissionType.ZERODAY: _build_zeroday_agents,
    MissionType.CTF: _build_ctf_agents,
}


# ═══════════════════════════════════════════════════════════════════
#  Mission Service
# ═══════════════════════════════════════════════════════════════════


class MissionService:
    """Application service: receives user intent, executes missions."""

    def __init__(
        self,
        event_store: EventStorePort | None = None,
        mcp_registry: MCPRegistry | None = None,
        coordinator: CoordinatorPort | None = None,
        db_path: str | Path = "miya_events.db",
    ) -> None:
        self._event_store = event_store
        self._mcp_registry = mcp_registry or MCPRegistry()
        self._coordinator = coordinator
        self._db_path = db_path
        self._owns_store = event_store is None

    @classmethod
    async def create(cls, db_path: str | Path = "miya_events.db") -> MissionService:
        """Factory: create with initialized SQLite store."""
        store = SQLiteEventStore(db_path)
        await store.initialize()
        service = cls(event_store=store, db_path=db_path)
        service._owns_store = True
        return service

    async def execute(
        self,
        mission_type: str | MissionType,
        target_uri: str,
        target_kind: str = "service",
        topology: str = "ooda",
        **options: Any,
    ) -> MissionReport:
        """Execute a mission and return a report."""

        if isinstance(mission_type, str):
            mission_type = MissionType(mission_type)

        target = Target(uri=target_uri, kind=target_kind)
        mission = Mission(
            mission_type=mission_type,
            target=target,
            topology=topology,
            options=options,
        )
        mission.start()

        # Ensure event store
        if self._event_store is None:
            store = SQLiteEventStore(self._db_path)
            await store.initialize()
            self._event_store = store

        # Build blackboard from existing events
        blackboard = Blackboard()
        existing_events = await self._event_store.load_all()
        blackboard.apply_all(existing_events)

        # Build agents for this mission type
        builder = AGENT_BUILDERS.get(mission_type)
        if not builder:
            raise ValueError(f"No agents registered for mission type: {mission_type}")
        agents = builder()
        if not agents:
            raise ValueError(f"Failed to build agents for: {mission_type}")

        # Get topology (pass coordinator for testability)
        topo = TopologyRegistry.get(topology, coordinator=self._coordinator)

        # Execute
        start_time = datetime.now(timezone.utc)
        collected_events: list[DomainEvent] = []

        try:
            async for event in topo.execute(
                mission, blackboard, agents, self._event_store
            ):
                collected_events.append(event)
                await self._event_store.append([event])
                # Note: blackboard.apply() is handled by the topology itself
                # to ensure state is up-to-date for prompt generation between phases.

            mission.complete()
        except Exception as e:
            logger.error(f"Mission failed: {e}")
            mission.fail()
            raise

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        return MissionReport(
            mission_id=mission.id,
            mission_type=mission_type.value,
            target=target_uri,
            topology=topology,
            findings=list(blackboard.findings),
            events_count=len(collected_events),
            duration_seconds=duration,
            blackboard_summary=blackboard.summary(),
            status=mission.status,
        )

    async def list_topologies(self) -> list[dict[str, str]]:
        return TopologyRegistry.describe_all()

    async def list_mcp_servers(self) -> list[dict[str, str]]:
        return self._mcp_registry.describe()

    async def close(self) -> None:
        if self._owns_store and self._event_store and hasattr(self._event_store, "close"):
            await self._event_store.close()
