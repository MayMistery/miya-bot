"""MissionService — the application service that wires everything together.

Receives user requests, assembles the right topology + agents + MCP servers,
executes the mission, and produces a report.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from miya.shared.blackboard import Blackboard
from miya.shared.campaign import Campaign
from miya.shared.events import DomainEvent, MissionFailed, ChallengeSolved
from miya.shared.ports import CoordinatorPort, EventStorePort
from miya.shared.types import Finding, Mission, MissionType, Target
from miya.infra.event_store import SQLiteEventStore
from miya.infra.mcp_registry import MCPRegistry
from miya.topology.base import AgentHandle, TopologyRegistry

# Ensure topologies are registered
import miya.topology.ooda  # noqa: F401
import miya.topology.attack_graph_topo  # noqa: F401
import miya.topology.fanout_topo  # noqa: F401

logger = logging.getLogger(__name__)


def _write_challenge_writeup(
    challenge_name: str,
    flag: str,
    approach: str,
    target: str,
    output_dir: Path | str | None = None,
    events: list[Any] | None = None,
) -> Path | None:
    """Auto-generate a detailed writeup for a solved CTF challenge.

    Includes full event timeline with payloads and analysis.

    Args:
        output_dir: Directory to write into. If None, writeup is skipped.
        events: All DomainEvents collected during this challenge's OODA loop.
    """
    if output_dir is None:
        return None

    import re
    safe_name = re.sub(r'[^\w\-]', '_', challenge_name)
    m = re.match(r'[A-Za-z0-9_]+\{(.+)\}', flag)
    flag_part = m.group(1) if m else flag
    safe_flag = re.sub(r'[^\w\-]', '_', flag_part)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    filepath = out / f"{safe_name}_{safe_flag}.md"

    # ── Build detailed writeup ────────────────────────────
    sections: list[str] = []
    sections.append(f"# {challenge_name}\n")
    sections.append(f"**Target:** `{target}`")
    sections.append(f"**Flag:** `{flag}`")
    sections.append(f"**Approach:** {approach or 'Automated'}\n")
    sections.append("---\n")

    # Detailed timeline from events
    if events:
        sections.append("## Timeline\n")
        for ev in events:
            etype = type(ev).__name__

            if etype == "PhaseTransition":
                to_phase = getattr(ev, "to_phase", "")
                reason = getattr(ev, "reason", "")
                sections.append(f"### Phase: {to_phase.upper()}\n")
                if reason:
                    sections.append(f"_{reason}_\n")

            elif etype == "ChallengeIdentified":
                cat = getattr(ev, "category", "")
                diff = getattr(ev, "difficulty", "")
                tech = getattr(ev, "technology_stack", ())
                sections.append(f"**Identified:** category={cat}, difficulty={diff}")
                if tech:
                    sections.append(f"  Tech stack: {', '.join(tech)}\n")

            elif etype == "ChallengeClassified":
                cat = getattr(ev, "category", "")
                conf = getattr(ev, "confidence", 0)
                reasoning = getattr(ev, "reasoning", "")
                sections.append(f"**Classified:** {cat} (confidence {conf:.0%})")
                if reasoning:
                    sections.append(f"  {reasoning}\n")

            elif etype == "AssetDiscovered":
                host = getattr(ev, "host", "")
                ports = getattr(ev, "ports", ())
                services = getattr(ev, "services", ())
                sections.append(f"**Asset:** {host}")
                if ports:
                    sections.append(f"  Ports: {', '.join(str(p) for p in ports)}")
                if services:
                    sections.append(f"  Services: {', '.join(services)}\n")

            elif etype == "VulnerabilityFound":
                vuln = getattr(ev, "vulnerability", "")
                sev = getattr(ev, "severity", "")
                detail = getattr(ev, "detail", "")
                sections.append(f"**Vulnerability:** {vuln} [{sev}]")
                if detail:
                    sections.append(f"```\n{detail}\n```\n")

            elif etype == "ExploitAttempted":
                technique = getattr(ev, "technique", "")
                payload = getattr(ev, "payload", "")
                target_desc = getattr(ev, "target", "")
                sections.append(f"**Exploit Attempt:** {technique}")
                if target_desc:
                    sections.append(f"  Target: {target_desc}")
                if payload:
                    sections.append(f"  Payload:\n```\n{payload}\n```\n")

            elif etype == "ExploitSucceeded":
                technique = getattr(ev, "technique", "")
                result = getattr(ev, "result", "")
                sections.append(f"**Exploit Succeeded:** {technique}")
                if result:
                    sections.append(f"```\n{result}\n```\n")

            elif etype == "ExploitFailed":
                technique = getattr(ev, "technique", "")
                reason = getattr(ev, "reason", "")
                sections.append(f"**Exploit Failed:** {technique}")
                if reason:
                    sections.append(f"  Reason: {reason}\n")

            elif etype == "FlagSubmitted":
                accepted = getattr(ev, "accepted", False)
                response = getattr(ev, "response", "")
                sections.append(
                    f"**Flag Submitted:** `{flag}` "
                    f"{'ACCEPTED' if accepted else 'REJECTED'}"
                )
                if response:
                    sections.append(f"  Response: {response}\n")

            elif etype == "ReflectionCompleted":
                decision = getattr(ev, "decision", "")
                assessment = getattr(ev, "assessment", "")
                insights = getattr(ev, "insights", "")
                if assessment:
                    sections.append(f"**Reflection:** {assessment}")
                if insights:
                    sections.append(f"  Insights: {insights}")
                sections.append(f"  Decision: {decision}\n")

            elif etype == "OperatorMessage":
                content = getattr(ev, "content", "")
                sections.append(f"> **Operator:** {content}\n")

            elif etype == "ChallengeSolved":
                sections.append("\n## Flag Captured\n")
                sections.append(f"```\n{flag}\n```\n")
                if approach:
                    sections.append(f"**Method:** {approach}\n")
    else:
        sections.append("## Solution\n")
        sections.append(f"{approach or '*(Automated solution by Miya)*'}\n")

    sections.append("---\n")
    sections.append("*Solved by Miya DDD Pentest Agent*\n")

    filepath.write_text("\n".join(sections), encoding="utf-8")
    logger.info("Writeup generated: %s", filepath)
    return filepath


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
    error: str = ""

    # ── Cost tracking ──────────────────────────────────────────────
    cost_usd: float = 0.0
    api_turns: int = 0
    api_calls: int = 0

    # ── Original parameters for replay ─────────────────────────────
    target_kind: str = ""
    model: str = ""
    prompt: str = ""
    options: dict[str, Any] = field(default_factory=dict)

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
            "",
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


def _build_oneday_agents(model: str = "opus") -> dict[str, AgentHandle]:
    """Import and build 1-day kill chain agents."""
    try:
        from miya.oneday.recon.agent import create_agent as recon
        from miya.oneday.scan.agent import create_agent as scan
        from miya.oneday.vuln.agent import create_agent as vuln
        from miya.oneday.exploit.agent import create_agent as exploit
        from miya.oneday.post.agent import create_agent as post
        return {
            "recon": recon(model=model),
            "scan": scan(model=model),
            "vuln": vuln(model=model),
            "exploit": exploit(model=model),
            "post": post(model=model),
        }
    except ImportError as e:
        logger.warning(f"Could not load oneday agents: {e}")
        return {}


def _build_zeroday_agents(model: str = "opus") -> dict[str, AgentHandle]:
    """Import and build 0-day API chain agents."""
    try:
        from miya.zeroday.entrypoint.agent import create_agent as entrypoint
        from miya.zeroday.dataflow.agent import create_agent as dataflow
        from miya.zeroday.sink.agent import create_agent as sink
        from miya.zeroday.poc.agent import create_agent as poc
        return {
            "entrypoint": entrypoint(model=model),
            "dataflow": dataflow(model=model),
            "sink": sink(model=model),
            "poc": poc(model=model),
        }
    except ImportError as e:
        logger.warning(f"Could not load zeroday agents: {e}")
        return {}


def _build_ctf_agents(model: str = "opus") -> dict[str, AgentHandle]:
    """Import and build CTF agents."""
    try:
        from miya.ctf.web.agent import create_agent as web
        from miya.ctf.pwn.agent import create_agent as pwn
        from miya.ctf.crypto.agent import create_agent as crypto
        from miya.ctf.reverse.agent import create_agent as reverse
        from miya.ctf.misc.agent import create_agent as misc
        return {
            "web": web(model=model),
            "pwn": pwn(model=model),
            "crypto": crypto(model=model),
            "reverse": reverse(model=model),
            "misc": misc(model=model),
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
        campaign: Campaign | None = None,
        writeup_dir: Path | str | None = None,
    ) -> None:
        self._event_store = event_store
        self._mcp_registry = mcp_registry or MCPRegistry()
        self._coordinator = coordinator
        self._db_path = db_path
        self._owns_store = event_store is None
        self._writeup_dir = Path(writeup_dir) if writeup_dir is not None else None
        self.campaign = campaign or Campaign.load(
            Path(str(db_path)).with_suffix(".campaign.json")
        )

    @classmethod
    async def create(
        cls,
        db_path: str | Path = "miya_events.db",
        writeup_dir: Path | str | None = ".",
    ) -> MissionService:
        """Factory: create with initialized SQLite store."""
        store = SQLiteEventStore(db_path)
        await store.initialize()
        service = cls(event_store=store, db_path=db_path, writeup_dir=writeup_dir)
        service._owns_store = True
        return service

    async def execute(
        self,
        mission_type: str | MissionType,
        target_uri: str,
        target_kind: str = "service",
        topology: str = "ooda",
        model: str = "opus",
        prompt: str = "",
        on_event: Callable[[DomainEvent], None] | None = None,
        operator_queue: asyncio.Queue[str] | None = None,
        **options: Any,
    ) -> MissionReport:
        """Execute a mission and return a report.

        Args:
            prompt: Operator instructions passed at launch — included
                    in every phase prompt as additional context.
            on_event: Optional callback invoked for each domain event as it
                      is produced.  Used by the interactive REPL to render
                      a live event feed.
            operator_queue: Optional async queue for HITL messages injected
                            during execution.  The topology drains it between
                            phases.
        """

        if isinstance(mission_type, str):
            mission_type = MissionType(mission_type)

        target = Target(uri=target_uri, kind=target_kind)  # type: ignore[arg-type]
        mission = Mission(
            mission_type=mission_type,
            target=target,
            topology=topology,
            prompt=prompt,
            options=options,
        )
        mission.start()

        # Ensure event store
        if self._event_store is None:
            store = SQLiteEventStore(self._db_path)
            await store.initialize()
            self._event_store = store

        # Fresh blackboard per mission — each mission starts from zero.
        # Historical findings live in the event store and can be queried
        # via REPL commands (events, blackboard), but don't pollute the
        # new mission's context with stale state from prior runs.
        blackboard = Blackboard()

        # Build agents for this mission type
        builder = AGENT_BUILDERS.get(mission_type)
        if not builder:
            raise ValueError(f"No agents registered for mission type: {mission_type}")
        agents = builder(model=model)
        if not agents:
            raise ValueError(f"Failed to build agents for: {mission_type}")

        # ── MCP server health check ──────────────────────────
        all_mcp: set[str] = set()
        for handle in agents.values():
            all_mcp.update(handle.mcp_servers)
        if all_mcp:
            ok, missing = self._mcp_registry.probe(list(all_mcp))
            if missing:
                logger.warning(
                    "MCP servers unavailable (command not on PATH): %s",
                    ", ".join(missing),
                )
            if ok:
                logger.debug("MCP servers OK: %s", ", ".join(ok))

        # Get topology (pass coordinator for testability + runtime tunables)
        topo_kwargs: dict[str, Any] = {"coordinator": self._coordinator}
        if topology == "fanout":
            if "max_parallel" in options:
                topo_kwargs["max_parallel"] = int(options.pop("max_parallel"))
            if "per_challenge_timeout" in options:
                topo_kwargs["per_challenge_timeout"] = float(options.pop("per_challenge_timeout"))
        topo = TopologyRegistry.get(topology, **topo_kwargs)

        # Execute — reset cost tracker for this mission
        from miya.topology.base import _cost_tracker
        _cost_tracker.reset()

        start_time = datetime.now(timezone.utc)
        collected_events: list[DomainEvent] = []

        try:
            async for event in topo.execute(
                mission, blackboard, agents, self._event_store,
                operator_queue=operator_queue,
                campaign=self.campaign,
            ):
                collected_events.append(event)
                await self._event_store.append([event])
                # Record solved challenges in campaign + generate writeup
                if isinstance(event, ChallengeSolved):
                    try:
                        self.campaign.record_solved(
                            event.challenge_name,
                            event.flag,
                            event.approach,
                            mission_id=mission.id,
                        )
                    except Exception:
                        logger.warning("Failed to record solved challenge in campaign", exc_info=True)
                    # Auto-generate writeup file
                    if event.flag and mission_type == MissionType.CTF:
                        # Collect events for this challenge's writeup.
                        # Include challenge-specific events + general events
                        # that share the same aggregate_id (sub-mission).
                        ch_agg_id = event.aggregate_id
                        ch_events = [
                            e for e in collected_events
                            if getattr(e, "challenge_name", "") == event.challenge_name
                            or (
                                e.aggregate_id == ch_agg_id
                                and ch_agg_id
                                and type(e).__name__ in (
                                    "PhaseTransition", "ReflectionCompleted",
                                    "OperatorMessage", "ExploitAttempted",
                                    "ExploitSucceeded", "ExploitFailed",
                                    "VulnerabilityFound", "AssetDiscovered",
                                )
                            )
                        ]
                        try:
                            _write_challenge_writeup(
                                event.challenge_name, event.flag,
                                event.approach, target_uri,
                                output_dir=self._writeup_dir,
                                events=ch_events,
                            )
                        except Exception:
                            logger.warning("Failed to generate writeup", exc_info=True)
                if on_event is not None:
                    try:
                        on_event(event)
                    except Exception:
                        logger.warning("on_event callback error", exc_info=True)

            mission.complete()
        except Exception as e:
            logger.error(f"Mission failed: {e}")
            mission.fail()
            # Persist a MissionFailed terminal event
            fail_event = MissionFailed(
                aggregate_id=mission.id,
                reason=str(e),
                mission=mission_type.value,
            )
            collected_events.append(fail_event)
            try:
                await self._event_store.append([fail_event])
            except Exception:
                logger.warning("Could not persist MissionFailed event", exc_info=True)
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            cost_snap = _cost_tracker.snapshot()
            return MissionReport(
                mission_id=mission.id,
                mission_type=mission_type.value,
                target=target_uri,
                topology=topology,
                findings=list(blackboard.findings),
                events_count=len(collected_events),
                duration_seconds=duration,
                blackboard_summary=blackboard.summary(),
                status="failed",
                error=str(e),
                cost_usd=float(cost_snap["cost_usd"]),
                api_turns=int(cost_snap["turns"]),
                api_calls=int(cost_snap["calls"]),
                target_kind=target_kind,
                model=model,
                prompt=prompt,
                options=dict(options),
            )

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        cost_snap = _cost_tracker.snapshot()

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
            cost_usd=cost_snap["cost_usd"],
            api_turns=cost_snap["turns"],
            api_calls=cost_snap["calls"],
            target_kind=target_kind,
            model=model,
            prompt=prompt,
            options=dict(options),
        )

    async def get_last_mission(self) -> MissionReport | None:
        """Retrieve the last mission's parameters from the event store.

        Scans for the most recent MissionStarted event and reconstructs
        enough info to allow resume.
        """
        if not self._event_store:
            return None
        all_events = await self._event_store.load_all()
        if not all_events:
            return None

        # Find last MissionStarted
        from miya.shared.events import MissionStarted as _MS
        last_start = None
        for ev in reversed(all_events):
            if isinstance(ev, _MS):
                last_start = ev
                break
        if not last_start:
            return None

        # Rebuild blackboard from all events after this mission start
        bb = Blackboard()
        mission_events = [
            e for e in all_events
            if e.aggregate_id == last_start.aggregate_id
        ]
        bb.apply_all(mission_events)

        return MissionReport(
            mission_id=last_start.aggregate_id,
            mission_type=last_start.mission_type,
            target=last_start.target_uri,
            topology=last_start.topology,
            findings=list(bb.findings),
            events_count=len(mission_events),
            blackboard_summary=bb.summary(),
            status="suspended",
        )

    async def list_topologies(self) -> list[dict[str, str]]:
        return TopologyRegistry.describe_all()

    async def list_mcp_servers(self) -> list[dict[str, str]]:
        return self._mcp_registry.describe()

    async def close(self) -> None:
        if self._owns_store and self._event_store:
            await self._event_store.close()
