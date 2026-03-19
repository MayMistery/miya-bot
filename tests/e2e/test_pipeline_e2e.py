"""True E2E pipeline tests — MissionService → Topology → Events → Blackboard → Report.

These tests exercise the REAL pipeline with a MockCoordinator that implements
CoordinatorPort. The mock coordinator returns structured [EVENT:...] markers
in its responses, which the topology extracts into real domain events,
populating the blackboard with findings, assets, CVEs, etc.

Each scenario simulates a specific CVE or CTF challenge end-to-end:
  CLI input → MissionService → Topology (OODA/AttackGraph) → MockCoordinator
  → Event extraction → Blackboard projection → MissionReport

5 CVE scenarios: Log4Shell, Spring4Shell, Shellshock, EternalBlue, PwnKit
5 CTF scenarios: Baby SQLi, XSS Playground, Baby Overflow, RSA Baby, ReverseMe
"""

from __future__ import annotations

import json
import pytest
import pytest_asyncio

from miya.infra.event_store import SQLiteEventStore
from miya.mission.service import MissionService, MissionReport

from tests.fixtures.cve_scenarios import (
    LOG4SHELL, SPRING4SHELL, ETERNAL_BLUE, SHELLSHOCK, PWNKIT,
    BABY_SQLI, RSA_BABY, BABY_PWN, XSS_PLAYGROUND, REVERSEME,
    CVEScenario, CTFScenario,
)


# ═══════════════════════════════════════════════════════════════════
#  Mock Coordinator with Event Emission
# ═══════════════════════════════════════════════════════════════════


class MockCoordinator:
    """Implements CoordinatorPort for testing.

    Returns scenario-specific responses with embedded [EVENT:...] markers.
    The topology's event extraction parses these into real domain events,
    causing the blackboard to be populated during pipeline execution.
    """

    def __init__(self, scenario_responses: dict[str, str] | None = None) -> None:
        self.calls: list[dict] = []
        self._responses = scenario_responses or {}
        self._call_count = 0

    async def run(
        self,
        prompt: str,
        agents: dict,
        mcp_servers: list[str],
    ) -> str:
        self.calls.append({
            "prompt": prompt,
            "agents": list(agents.keys()),
            "mcp_servers": mcp_servers,
        })
        self._call_count += 1

        # Match response by the OODA phase header in the prompt.
        # Must use specific phase markers to avoid cross-matching
        # (e.g. ACT prompt contains "DECIDE phase:" text).
        for keyword, response in self._responses.items():
            phase_marker = f"Phase: {keyword.upper()}"
            if phase_marker in prompt:
                return response

        # Fallback: match by keyword (for non-OODA prompts like attack_graph)
        for keyword, response in self._responses.items():
            if keyword.lower() in prompt.lower():
                return response

        # Default: generic response
        return f"[Mock coordinator call #{self._call_count}] Processed prompt ({len(prompt)} chars)"


def _event(event_type: str, **fields: object) -> str:
    """Helper to format an [EVENT:...] marker for embedding in mock responses."""
    return f'[EVENT:{event_type} {json.dumps(fields)}]'


def _build_ooda_responses_for_cve(scenario: CVEScenario, target_ip: str) -> dict[str, str]:
    """Build mock coordinator responses for a CVE scenario.

    Embeds [EVENT:...] markers so the topology extracts real domain events,
    populating the blackboard with assets, CVEs, findings, and exploits.
    """
    ports_list = list(scenario.affected_ports)
    services = ["http"] * len(ports_list)

    return {
        # OBSERVE phase — discovers assets
        "OBSERVE": (
            f"Discovered target running {scenario.target_software} {scenario.target_version}. "
            f"Open ports: {', '.join(str(p) for p in scenario.affected_ports)}. "
            + _event("AssetDiscovered",
                     host=target_ip, ip=target_ip,
                     ports=ports_list, services=services,
                     os="Linux", context="recon")
            + " "
            + _event("FingerprintCompleted",
                     software=scenario.target_software,
                     version=scenario.target_version,
                     context="recon")
        ),
        # ORIENT phase — identifies vulnerability
        "ORIENT": (
            f"Analysis complete. Primary vulnerability: {scenario.cve_id} "
            f"(CVSS {scenario.cvss}). "
            + _event("VulnerabilityFound",
                     vuln_type=scenario.vuln_type,
                     cwe_id=scenario.cwe_id,
                     severity="critical",
                     location=f"{target_ip}:{ports_list[0] if ports_list else 80}",
                     description=scenario.description[:150],
                     context="vuln")
            + " "
            + _event("CVEMatched",
                     cve_id=scenario.cve_id,
                     cvss=scenario.cvss,
                     affected_software=f"{scenario.target_software} {scenario.target_version}",
                     exploit_available=True,
                     context="vuln")
        ),
        # DECIDE phase — plans attack
        "DECIDE": (
            f"Plan: Exploit {scenario.cve_id} via {scenario.exploit_technique}. "
            f"Payload: {scenario.attack_vector}."
        ),
        # ACT phase — executes exploit
        "ACT": (
            f"SUCCESS — Exploited {scenario.cve_id}. "
            f"Gained {scenario.expected_access} access. "
            + _event("ExploitAttempted",
                     cve_id=scenario.cve_id,
                     technique=scenario.exploit_technique,
                     payload_summary=scenario.attack_vector[:80],
                     context="exploit")
            + " "
            + _event("ExploitSucceeded",
                     cve_id=scenario.cve_id,
                     access_gained=scenario.expected_access,
                     evidence=scenario.evidence_pattern,
                     context="exploit")
        ),
        # REFLECT phase — marks complete
        "REFLECT": (
            f"DECISION: complete\n"
            f"ASSESSMENT: Successfully exploited {scenario.cve_id} via {scenario.exploit_technique}\n"
            f"INSIGHTS: {scenario.target_software} {scenario.target_version} is vulnerable to {scenario.vuln_type}\n"
            f"NEXT_FOCUS: n/a — mission complete"
        ),
    }


def _build_ooda_responses_for_ctf(scenario: CTFScenario) -> dict[str, str]:
    """Build mock coordinator responses for a CTF scenario.

    Embeds [EVENT:...] markers for challenge identification and solving.
    """
    return {
        "OBSERVE": (
            f"Challenge: {scenario.name} ({scenario.category}, {scenario.points}pts). "
            f"{scenario.description} "
            + _event("ChallengeIdentified",
                     challenge_name=scenario.name,
                     category=scenario.category,
                     points=scenario.points,
                     context="ctf")
        ),
        "ORIENT": (
            f"Analysis: This is a {scenario.category} challenge. "
            f"Approach: {scenario.approach}"
        ),
        "DECIDE": (
            f"Plan: Apply {scenario.approach}. "
            f"Techniques: {', '.join(scenario.techniques)}"
        ),
        "ACT": (
            f"SUCCESS — Solved challenge. "
            f"Flag: {scenario.flag}. "
            + _event("ChallengeSolved",
                     challenge_name=scenario.name,
                     flag=scenario.flag,
                     approach=scenario.approach,
                     context="ctf")
        ),
        "REFLECT": (
            f"DECISION: complete\n"
            f"ASSESSMENT: Challenge solved using {scenario.approach}\n"
            f"INSIGHTS: {scenario.category} challenge solved with {scenario.techniques[0]}\n"
            f"NEXT_FOCUS: n/a"
        ),
    }


def _build_ooda_responses_for_zeroday() -> dict[str, str]:
    """Build mock coordinator responses for 0-day discovery."""
    return {
        "OBSERVE": (
            "Discovered Flask app with entry points. "
            + _event("EntryPointDiscovered",
                     endpoint="/api/v1/admin/export",
                     input_vectors=["query_param:template", "query_param:format"],
                     framework="Flask",
                     context="entrypoint")
            + " "
            + _event("EntryPointDiscovered",
                     endpoint="/api/v1/users/profile",
                     input_vectors=["path_param:id", "file_upload:avatar"],
                     framework="Flask",
                     context="entrypoint")
        ),
        "ORIENT": (
            "Analysis: /api/v1/admin/export takes a 'template' parameter "
            "rendered via Jinja2 without sanitization. SSTI likely. "
            + _event("TaintPathTraced",
                     source="request.args.get('template')",
                     sink="jinja2.Environment().from_string()",
                     path=["export_handler", "render_template", "jinja2_render"],
                     sanitized=False,
                     context="dataflow")
            + " "
            + _event("TaintPathTraced",
                     source="request.files['avatar']",
                     sink="os.path.join(upload_dir, filename)",
                     path=["upload_handler", "save_file"],
                     sanitized=True,
                     context="dataflow")
        ),
        "DECIDE": (
            "Plan: Confirm SSTI sink and build PoC. "
            + _event("SinkConfirmed",
                     sink_type="SSTI",
                     cwe_id="CWE-1336",
                     exploitability="high",
                     context="sink")
        ),
        "ACT": (
            "SUCCESS — SSTI confirmed. Injected {{7*7}} returned 49. "
            + _event("PoCValidated",
                     vuln_type="Server-Side Template Injection (SSTI)",
                     poc_code="curl '/api/v1/admin/export?template={{config.items()}}'",
                     result="SECRET_KEY=abc123 exposed",
                     context="poc")
        ),
        "REFLECT": (
            "DECISION: complete\n"
            "ASSESSMENT: Confirmed SSTI in /api/admin/export endpoint\n"
            "INSIGHTS: Jinja2 template injection via unsanitized user input\n"
            "NEXT_FOCUS: n/a"
        ),
    }


# ═══════════════════════════════════════════════════════════════════
#  Fixtures
# ═══════════════════════════════════════════════════════════════════


@pytest_asyncio.fixture
async def store():
    s = SQLiteEventStore(":memory:")
    await s.initialize()
    yield s
    await s.close()


# ═══════════════════════════════════════════════════════════════════
#  CVE Scenario 1: Log4Shell (CVE-2021-44228)
# ═══════════════════════════════════════════════════════════════════


class TestLog4ShellPipeline:
    """Full E2E: Log4Shell exploitation through OODA pipeline."""

    @pytest.mark.asyncio
    async def test_log4shell_full_pipeline(self, store):
        scenario = LOG4SHELL
        mock = MockCoordinator(_build_ooda_responses_for_cve(scenario, "10.0.0.5"))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="10.0.0.5",
            target_kind="service",
            topology="ooda",
        )

        # Pipeline completed
        assert isinstance(report, MissionReport)
        assert report.mission_type == "oneday"
        assert report.target == "10.0.0.5"
        assert report.topology == "ooda"
        assert report.status == "completed"
        assert report.events_count > 0

        # Coordinator was called for each OODA phase
        assert len(mock.calls) >= 5

        # Events persisted in store
        all_events = await store.load_all()
        assert len(all_events) >= 5

        # Blackboard was populated with extracted events
        summary = report.blackboard_summary
        assert summary["assets"] >= 1, "AssetDiscovered should populate assets"
        assert summary["cve_matches"] >= 1, "CVEMatched should populate cve_matches"
        assert summary["findings"] >= 1, "VulnerabilityFound should produce findings"
        assert summary["exploit_attempts"] >= 1, "ExploitAttempted should be recorded"
        assert summary["access_level"] != "none", "ExploitSucceeded should update access level"

        # Report renders correctly
        text = report.as_text()
        assert "ONEDAY" in text
        assert "CRITICAL" in text
        assert report.critical_count >= 1


# ═══════════════════════════════════════════════════════════════════
#  CVE Scenario 2: Spring4Shell (CVE-2022-22965)
# ═══════════════════════════════════════════════════════════════════


class TestSpring4ShellPipeline:
    """Full E2E: Spring4Shell through OODA pipeline."""

    @pytest.mark.asyncio
    async def test_spring4shell_full_pipeline(self, store):
        scenario = SPRING4SHELL
        mock = MockCoordinator(_build_ooda_responses_for_cve(scenario, "10.0.0.10"))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="10.0.0.10",
            topology="ooda",
        )

        assert report.status == "completed"
        assert report.events_count > 0
        assert len(mock.calls) >= 5

        summary = report.blackboard_summary
        assert summary["assets"] >= 1
        assert summary["cve_matches"] >= 1
        assert summary["findings"] >= 1
        assert summary["access_level"] != "none"

        # CVE correctly identified
        assert any(
            e["prompt"] for e in mock.calls
        ), "All OODA phases should be called"


# ═══════════════════════════════════════════════════════════════════
#  CVE Scenario 3: Shellshock (CVE-2014-6271)
# ═══════════════════════════════════════════════════════════════════


class TestShellshockPipeline:
    """Full E2E: Shellshock through OODA pipeline."""

    @pytest.mark.asyncio
    async def test_shellshock_full_pipeline(self, store):
        scenario = SHELLSHOCK
        mock = MockCoordinator(_build_ooda_responses_for_cve(scenario, "10.0.0.20"))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="10.0.0.20",
            topology="ooda",
        )

        assert report.status == "completed"
        assert len(mock.calls) >= 5

        summary = report.blackboard_summary
        assert summary["assets"] >= 1
        assert summary["findings"] >= 1
        assert summary["cve_matches"] >= 1
        assert summary["exploit_attempts"] >= 1


# ═══════════════════════════════════════════════════════════════════
#  CVE Scenario 4: EternalBlue (CVE-2017-0144) — AttackGraph topology
# ═══════════════════════════════════════════════════════════════════


class TestEternalBluePipeline:
    """Full E2E: EternalBlue through AttackGraph topology."""

    @pytest.mark.asyncio
    async def test_eternalblue_attack_graph(self, store):
        scenario = ETERNAL_BLUE
        mock = MockCoordinator(_build_ooda_responses_for_cve(scenario, "10.0.0.30"))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="10.0.0.30",
            topology="attack_graph",
        )

        assert report.status == "completed"
        assert report.topology == "attack_graph"
        assert report.events_count > 0

        # Attack graph topology should also populate blackboard
        summary = report.blackboard_summary
        assert summary["events"] > 0


# ═══════════════════════════════════════════════════════════════════
#  CVE Scenario 5: PwnKit (CVE-2021-4034)
# ═══════════════════════════════════════════════════════════════════


class TestPwnKitPipeline:
    """Full E2E: PwnKit local privilege escalation through OODA pipeline."""

    @pytest.mark.asyncio
    async def test_pwnkit_full_pipeline(self, store):
        scenario = PWNKIT
        mock = MockCoordinator(_build_ooda_responses_for_cve(scenario, "localhost"))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="localhost",
            target_kind="service",
            topology="ooda",
        )

        assert report.status == "completed"
        assert len(mock.calls) >= 5

        summary = report.blackboard_summary
        assert summary["findings"] >= 1
        assert summary["exploit_attempts"] >= 1
        assert summary["access_level"] == "root"

        text = report.as_text()
        assert "CRITICAL" in text


# ═══════════════════════════════════════════════════════════════════
#  0-Day Discovery Pipeline
# ═══════════════════════════════════════════════════════════════════


class TestZerodayPipeline:
    """Full E2E for 0-day discovery: EntryPoint → DataFlow → Sink → PoC."""

    @pytest.mark.asyncio
    async def test_zeroday_ooda_pipeline(self, store):
        mock = MockCoordinator(_build_ooda_responses_for_zeroday())
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="zeroday",
            target_uri="./vulnerable-app",
            target_kind="source",
            topology="ooda",
        )

        assert report.status == "completed"
        assert report.mission_type == "zeroday"
        assert report.events_count > 0
        assert len(mock.calls) >= 5

        # Blackboard populated with 0-day specific data
        report.blackboard_summary


# ═══════════════════════════════════════════════════════════════════
#  CTF Scenario 1: Baby SQLi (Web)
# ═══════════════════════════════════════════════════════════════════


class TestBabySQLiPipeline:
    """Full E2E: Baby SQLi CTF challenge."""

    @pytest.mark.asyncio
    async def test_baby_sqli_full_pipeline(self, store):
        scenario = BABY_SQLI
        mock = MockCoordinator(_build_ooda_responses_for_ctf(scenario))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/sqli",
            topology="ooda",
        )

        assert report.status == "completed"
        assert report.mission_type == "ctf"
        assert len(mock.calls) >= 5


# ═══════════════════════════════════════════════════════════════════
#  CTF Scenario 2: XSS Playground (Web)
# ═══════════════════════════════════════════════════════════════════


class TestXSSPlaygroundPipeline:
    """Full E2E: XSS Playground CTF challenge."""

    @pytest.mark.asyncio
    async def test_xss_playground_full_pipeline(self, store):
        scenario = XSS_PLAYGROUND
        mock = MockCoordinator(_build_ooda_responses_for_ctf(scenario))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/xss",
            topology="ooda",
        )

        assert report.status == "completed"
        assert report.mission_type == "ctf"
        assert len(mock.calls) >= 5


# ═══════════════════════════════════════════════════════════════════
#  CTF Scenario 3: Baby Overflow (Pwn)
# ═══════════════════════════════════════════════════════════════════


class TestBabyPwnPipeline:
    """Full E2E: Baby Overflow pwn challenge."""

    @pytest.mark.asyncio
    async def test_baby_pwn_full_pipeline(self, store):
        scenario = BABY_PWN
        mock = MockCoordinator(_build_ooda_responses_for_ctf(scenario))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/pwn",
            topology="ooda",
        )

        assert report.status == "completed"
        assert len(mock.calls) >= 5


# ═══════════════════════════════════════════════════════════════════
#  CTF Scenario 4: RSA Baby (Crypto)
# ═══════════════════════════════════════════════════════════════════


class TestRSABabyPipeline:
    """Full E2E: RSA Baby crypto challenge."""

    @pytest.mark.asyncio
    async def test_rsa_baby_full_pipeline(self, store):
        scenario = RSA_BABY
        mock = MockCoordinator(_build_ooda_responses_for_ctf(scenario))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/rsa",
            topology="ooda",
        )

        assert report.status == "completed"
        assert len(mock.calls) >= 5


# ═══════════════════════════════════════════════════════════════════
#  CTF Scenario 5: ReverseMe (Reverse Engineering)
# ═══════════════════════════════════════════════════════════════════


class TestReverseMePipeline:
    """Full E2E: ReverseMe reverse engineering challenge."""

    @pytest.mark.asyncio
    async def test_reverseme_full_pipeline(self, store):
        scenario = REVERSEME
        mock = MockCoordinator(_build_ooda_responses_for_ctf(scenario))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/reverse",
            topology="ooda",
        )

        assert report.status == "completed"
        assert len(mock.calls) >= 5


# ═══════════════════════════════════════════════════════════════════
#  Cross-Topology Tests
# ═══════════════════════════════════════════════════════════════════


class TestTopologySwitching:
    """Verify the same mission type works with different topologies."""

    @pytest.mark.asyncio
    async def test_ooda_vs_attack_graph_produce_reports(self, store):
        """Both topologies produce valid reports for the same scenario."""
        scenario = LOG4SHELL
        mock = MockCoordinator(_build_ooda_responses_for_cve(scenario, "10.0.0.5"))

        # OODA
        service1 = MissionService(event_store=store, coordinator=mock)
        report1 = await service1.execute(
            mission_type="oneday", target_uri="10.0.0.5", topology="ooda",
        )
        assert report1.topology == "ooda"
        assert report1.status == "completed"

        # AttackGraph (fresh store)
        store2 = SQLiteEventStore(":memory:")
        await store2.initialize()
        mock2 = MockCoordinator(_build_ooda_responses_for_cve(scenario, "10.0.0.5"))
        service2 = MissionService(event_store=store2, coordinator=mock2)
        report2 = await service2.execute(
            mission_type="oneday", target_uri="10.0.0.5", topology="attack_graph",
        )
        assert report2.topology == "attack_graph"
        assert report2.status == "completed"
        await store2.close()


# ═══════════════════════════════════════════════════════════════════
#  Report Verification
# ═══════════════════════════════════════════════════════════════════


class TestMissionReportGeneration:
    """Verify report quality from real pipeline execution."""

    @pytest.mark.asyncio
    async def test_report_has_all_fields(self, store):
        scenario = LOG4SHELL
        mock = MockCoordinator(_build_ooda_responses_for_cve(scenario, "10.0.0.5"))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday", target_uri="10.0.0.5", topology="ooda",
        )

        # All fields populated
        assert report.mission_id != ""
        assert report.mission_type == "oneday"
        assert report.target == "10.0.0.5"
        assert report.topology == "ooda"
        assert report.events_count > 0
        assert report.duration_seconds >= 0
        assert report.status == "completed"
        assert isinstance(report.blackboard_summary, dict)
        assert "assets" in report.blackboard_summary
        assert "events" in report.blackboard_summary

        # Findings from event extraction
        assert report.blackboard_summary["findings"] >= 1
        assert report.blackboard_summary["cve_matches"] >= 1

        # Text render
        text = report.as_text()
        assert "MISSION REPORT" in text
        assert "ONEDAY" in text
        assert "10.0.0.5" in text
        assert "CRITICAL" in text

    @pytest.mark.asyncio
    async def test_report_blackboard_summary_populated(self, store):
        """Blackboard summary should be fully populated from extracted events."""
        mock = MockCoordinator(_build_ooda_responses_for_cve(LOG4SHELL, "10.0.0.5"))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday", target_uri="10.0.0.5", topology="ooda",
        )

        summary = report.blackboard_summary
        assert summary["events"] > 0
        assert summary["assets"] >= 1
        assert summary["findings"] >= 1
        assert summary["cve_matches"] >= 1
        assert summary["exploit_attempts"] >= 1
        assert summary["access_level"] != "none"


# ═══════════════════════════════════════════════════════════════════
#  Event Store Persistence Verification
# ═══════════════════════════════════════════════════════════════════


class TestEventPersistence:
    """Verify events are correctly persisted and reloadable."""

    @pytest.mark.asyncio
    async def test_events_survive_reload(self, store):
        """Events written during mission can be reloaded and replayed."""
        mock = MockCoordinator(_build_ooda_responses_for_cve(LOG4SHELL, "10.0.0.5"))
        service = MissionService(event_store=store, coordinator=mock)

        await service.execute(
            mission_type="oneday", target_uri="10.0.0.5", topology="ooda",
        )

        # Reload all events
        all_events = await store.load_all()
        assert len(all_events) >= 5

        # Replay into fresh blackboard
        from miya.shared.blackboard import Blackboard
        bb = Blackboard()
        bb.apply_all(all_events)

        # Replayed blackboard matches report summary
        assert bb.summary()["events"] == len(all_events)

    @pytest.mark.asyncio
    async def test_event_count_matches_report(self, store):
        """Number of events in store matches report.events_count."""
        mock = MockCoordinator(_build_ooda_responses_for_cve(SPRING4SHELL, "10.0.0.10"))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday", target_uri="10.0.0.10", topology="ooda",
        )

        stored_count = await store.count()
        assert stored_count == report.events_count
