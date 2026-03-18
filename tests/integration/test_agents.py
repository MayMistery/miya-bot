"""Integration tests for agent builders — verify all agents load and configure correctly."""

from __future__ import annotations

import pytest
from miya.topology.base import AgentHandle, TopologyRegistry
from miya.infra.mcp_registry import MCPRegistry
from miya.mission.service import (
    _build_oneday_agents,
    _build_zeroday_agents,
    _build_ctf_agents,
    AGENT_BUILDERS,
    MissionReport,
)
from miya.shared.types import MissionType


class TestAgentBuilders:
    def test_oneday_agents(self):
        agents = _build_oneday_agents()
        assert set(agents.keys()) == {"recon", "scan", "vuln", "exploit", "post"}
        for name, handle in agents.items():
            assert isinstance(handle, AgentHandle)
            assert handle.name
            assert handle.system_prompt
            assert handle.mission_type == "oneday"

    def test_zeroday_agents(self):
        agents = _build_zeroday_agents()
        assert set(agents.keys()) == {"entrypoint", "dataflow", "sink", "poc"}
        for name, handle in agents.items():
            assert isinstance(handle, AgentHandle)
            assert handle.mission_type == "zeroday"

    def test_ctf_agents(self):
        agents = _build_ctf_agents()
        assert set(agents.keys()) == {"web", "pwn", "crypto", "reverse", "misc"}
        for name, handle in agents.items():
            assert isinstance(handle, AgentHandle)
            assert handle.mission_type == "ctf"

    def test_all_mission_types_have_builders(self):
        for mt in MissionType:
            assert mt in AGENT_BUILDERS

    def test_agent_definitions_are_valid(self):
        """Verify all agents produce valid AgentDefinition dicts."""
        for builder in AGENT_BUILDERS.values():
            agents = builder()
            for name, handle in agents.items():
                ad = handle.to_agent_definition()
                assert "description" in ad
                assert "prompt" in ad


class TestTopologyRegistry:
    def test_ooda_registered(self):
        topo = TopologyRegistry.get("ooda")
        assert topo is not None
        assert topo.name == "ooda"

    def test_attack_graph_registered(self):
        topo = TopologyRegistry.get("attack_graph")
        assert topo is not None
        assert topo.name == "attack_graph"

    def test_available(self):
        available = TopologyRegistry.available()
        assert "ooda" in available
        assert "attack_graph" in available

    def test_describe_all(self):
        descriptions = TopologyRegistry.describe_all()
        assert len(descriptions) >= 2
        for desc in descriptions:
            assert "name" in desc
            assert "description" in desc

    def test_unknown_topology_raises(self):
        with pytest.raises(ValueError):
            TopologyRegistry.get("nonexistent")


class TestMCPRegistry:
    def test_all_servers_available(self):
        registry = MCPRegistry()
        expected = {"semgrep", "nmap", "nuclei", "shodan", "metasploit",
                    "sqlmap", "exploitdb", "ghidra", "gdb",
                    "sage", "factordb", "cyberchef", "binwalk", "exiftool",
                    "event_bus"}
        assert set(registry.available()) == expected

    def test_get_configs_for_agent(self):
        registry = MCPRegistry()
        configs = registry.get_configs_for_agent(["nmap", "shodan"])
        assert len(configs) == 2

    def test_describe(self):
        registry = MCPRegistry()
        descriptions = registry.describe()
        assert len(descriptions) == 15
        for desc in descriptions:
            assert "name" in desc
            assert "description" in desc


class TestMissionReport:
    def test_as_text(self):
        from miya.shared.types import Finding, Severity
        report = MissionReport(
            mission_id="m-1",
            mission_type="oneday",
            target="10.0.0.5",
            topology="ooda",
            findings=[
                Finding(title="SQL Injection", severity=Severity.CRITICAL,
                        detail="In /api/users", context="vuln"),
                Finding(title="Info Disclosure", severity=Severity.LOW,
                        detail="Server header", context="scan"),
            ],
            events_count=42,
            duration_seconds=123.4,
            status="completed",
        )
        text = report.as_text()
        assert "ONEDAY" in text
        assert "10.0.0.5" in text
        assert "SQL Injection" in text
        assert "123.4s" in text

    def test_critical_count(self):
        from miya.shared.types import Finding, Severity
        report = MissionReport(
            findings=[
                Finding(severity=Severity.CRITICAL),
                Finding(severity=Severity.HIGH),
                Finding(severity=Severity.MEDIUM),
            ],
        )
        assert report.critical_count == 2  # CRITICAL (5) + HIGH (4) >= 4
