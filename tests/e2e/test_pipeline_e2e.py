"""True E2E pipeline tests — MissionService → Topology → Events → Blackboard → Report.

These tests exercise the REAL pipeline with a MockCoordinator that implements
CoordinatorPort. Unlike the event-projection-only tests in test_mission_e2e.py,
these drive the actual MissionService.execute() through real topology execution.

Each scenario simulates a specific CVE or CTF challenge with the mock coordinator
returning scenario-appropriate responses that the topology parses.
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from miya.shared.ports import CoordinatorPort
from miya.shared.types import MissionType
from miya.infra.event_store import SQLiteEventStore
from miya.mission.service import MissionService, MissionReport
from miya.topology.base import TopologyRegistry

from tests.fixtures.cve_scenarios import (
    LOG4SHELL, SPRING4SHELL, ETERNAL_BLUE, SHELLSHOCK, PWNKIT,
    BABY_SQLI, RSA_BABY, BABY_PWN, XSS_PLAYGROUND, REVERSEME,
    CVEScenario, CTFScenario,
)


# ═══════════════════════════════════════════════════════════════════
#  Mock Coordinator
# ═══════════════════════════════════════════════════════════════════


class MockCoordinator:
    """Implements CoordinatorPort for testing.

    Returns scenario-specific responses based on prompt keywords,
    simulating what the real Claude Agent SDK would produce.
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

        # Match response by keyword in prompt
        for keyword, response in self._responses.items():
            if keyword.lower() in prompt.lower():
                return response

        # Default: generic response
        return f"[Mock coordinator call #{self._call_count}] Processed prompt ({len(prompt)} chars)"


def _build_ooda_responses_for_cve(scenario: CVEScenario) -> dict[str, str]:
    """Build mock coordinator responses for a CVE scenario through OODA loop."""
    return {
        # OBSERVE phase
        "OBSERVE": (
            f"Discovered target running {scenario.target_software} {scenario.target_version}. "
            f"Open ports: {', '.join(str(p) for p in scenario.affected_ports)}. "
            f"Identified potential {scenario.vuln_type} vulnerability."
        ),
        # ORIENT phase
        "ORIENT": (
            f"Analysis complete. Primary vulnerability: {scenario.cve_id} "
            f"(CVSS {scenario.cvss}). {scenario.description[:100]}. "
            f"Attack vector: {scenario.attack_vector}. Priority: CRITICAL."
        ),
        # DECIDE phase
        "DECIDE": (
            f"Plan: Exploit {scenario.cve_id} via {scenario.exploit_technique}. "
            f"Agent: exploit. Payload: {scenario.attack_vector}. "
            f"Success criteria: {scenario.evidence_pattern}"
        ),
        # ACT phase
        "ACT": (
            f"SUCCESS — Exploited {scenario.cve_id}. "
            f"Gained {scenario.expected_access} access. "
            f"Evidence: {scenario.evidence_pattern}. "
            f"Session established on target."
        ),
        # REFLECT phase
        "REFLECT": (
            f"DECISION: complete\n"
            f"ASSESSMENT: Successfully exploited {scenario.cve_id} via {scenario.exploit_technique}\n"
            f"INSIGHTS: {scenario.target_software} {scenario.target_version} is vulnerable to {scenario.vuln_type}\n"
            f"NEXT_FOCUS: n/a — mission complete"
        ),
    }


def _build_ooda_responses_for_ctf(scenario: CTFScenario) -> dict[str, str]:
    """Build mock coordinator responses for a CTF scenario through OODA loop."""
    return {
        "OBSERVE": (
            f"Challenge: {scenario.name} ({scenario.category}, {scenario.points}pts). "
            f"{scenario.description} "
            f"Techniques to try: {', '.join(scenario.techniques)}"
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
            f"Used approach: {scenario.approach}"
        ),
        "REFLECT": (
            f"DECISION: complete\n"
            f"ASSESSMENT: Challenge solved using {scenario.approach}\n"
            f"INSIGHTS: {scenario.category} challenge solved with {scenario.techniques[0]}\n"
            f"NEXT_FOCUS: n/a"
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
#  CVE Scenario Tests — Full Pipeline
# ═══════════════════════════════════════════════════════════════════


class TestOnedayPipeline:
    """True E2E: MissionService.execute() → OODATopology → MockCoordinator → Report."""

    @pytest.mark.asyncio
    async def test_log4shell_full_pipeline(self, store):
        """Log4Shell (CVE-2021-44228) through complete OODA pipeline."""
        scenario = LOG4SHELL
        mock = MockCoordinator(_build_ooda_responses_for_cve(scenario))
        service = MissionService(
            event_store=store, coordinator=mock,
        )

        report = await service.execute(
            mission_type="oneday",
            target_uri="10.0.0.5",
            target_kind="service",
            topology="ooda",
        )

        # Pipeline executed
        assert isinstance(report, MissionReport)
        assert report.mission_type == "oneday"
        assert report.target == "10.0.0.5"
        assert report.topology == "ooda"
        assert report.status == "completed"
        assert report.events_count > 0
        assert report.duration_seconds >= 0

        # Coordinator was called for each OODA phase
        assert len(mock.calls) >= 5  # observe, orient, decide, act, reflect

        # Events persisted
        all_events = await store.load_all()
        assert len(all_events) >= 5

        # Report renders
        text = report.as_text()
        assert "ONEDAY" in text

    @pytest.mark.asyncio
    async def test_spring4shell_full_pipeline(self, store):
        """Spring4Shell (CVE-2022-22965) through OODA pipeline."""
        scenario = SPRING4SHELL
        mock = MockCoordinator(_build_ooda_responses_for_cve(scenario))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="10.0.0.10",
            topology="ooda",
        )

        assert report.status == "completed"
        assert report.events_count > 0
        assert len(mock.calls) >= 5

    @pytest.mark.asyncio
    async def test_shellshock_full_pipeline(self, store):
        """Shellshock (CVE-2014-6271) through OODA pipeline."""
        scenario = SHELLSHOCK
        mock = MockCoordinator(_build_ooda_responses_for_cve(scenario))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="10.0.0.20",
            topology="ooda",
        )

        assert report.status == "completed"
        assert len(mock.calls) >= 5

    @pytest.mark.asyncio
    async def test_eternalblue_attack_graph(self, store):
        """EternalBlue (CVE-2017-0144) through AttackGraph topology."""
        scenario = ETERNAL_BLUE
        mock = MockCoordinator(_build_ooda_responses_for_cve(scenario))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="10.0.0.30",
            topology="attack_graph",
        )

        assert report.status == "completed"
        assert report.topology == "attack_graph"
        assert report.events_count > 0

    @pytest.mark.asyncio
    async def test_pwnkit_local_privesc(self, store):
        """PwnKit (CVE-2021-4034) through OODA pipeline."""
        scenario = PWNKIT
        mock = MockCoordinator(_build_ooda_responses_for_cve(scenario))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="localhost",
            target_kind="service",
            topology="ooda",
        )

        assert report.status == "completed"
        assert len(mock.calls) >= 5


class TestZerodayPipeline:
    """True E2E for 0-day discovery missions."""

    @pytest.mark.asyncio
    async def test_zeroday_ooda_pipeline(self, store):
        """0-day discovery through OODA pipeline with mock coordinator."""
        responses = {
            "OBSERVE": (
                "Discovered Flask app with 3 entry points: "
                "POST /api/users, GET /api/search, POST /api/admin/export. "
                "Input vectors: query params, form data, file uploads."
            ),
            "ORIENT": (
                "Analysis: /api/admin/export takes a 'template' parameter "
                "that's rendered via Jinja2 without sanitization. "
                "Potential SSTI (CWE-1336). Priority: CRITICAL."
            ),
            "DECIDE": (
                "Plan: Trace taint from request.args.get('template') to "
                "jinja2.Environment().from_string(). Confirm sink. "
                "Build PoC with {{config.items()}} payload."
            ),
            "ACT": (
                "SUCCESS — SSTI confirmed. Injected {{7*7}} returned 49 in response. "
                "PoC: curl '/api/admin/export?template={{config.items()}}' "
                "Result: SECRET_KEY=abc123 exposed."
            ),
            "REFLECT": (
                "DECISION: complete\n"
                "ASSESSMENT: Confirmed SSTI in /api/admin/export endpoint\n"
                "INSIGHTS: Jinja2 template injection via unsanitized user input\n"
                "NEXT_FOCUS: n/a"
            ),
        }
        mock = MockCoordinator(responses)
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


class TestCTFPipeline:
    """True E2E for CTF solving missions."""

    @pytest.mark.asyncio
    async def test_baby_sqli_ctf(self, store):
        """Baby SQLi CTF challenge through full pipeline."""
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

    @pytest.mark.asyncio
    async def test_rsa_baby_ctf(self, store):
        """RSA Baby crypto challenge through full pipeline."""
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

    @pytest.mark.asyncio
    async def test_baby_pwn_ctf(self, store):
        """Baby Overflow pwn challenge through full pipeline."""
        scenario = BABY_PWN
        mock = MockCoordinator(_build_ooda_responses_for_ctf(scenario))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/pwn",
            topology="ooda",
        )

        assert report.status == "completed"


# ═══════════════════════════════════════════════════════════════════
#  Cross-Topology Tests
# ═══════════════════════════════════════════════════════════════════


class TestTopologySwitching:
    """Verify the same mission type works with different topologies."""

    @pytest.mark.asyncio
    async def test_ooda_vs_attack_graph_produce_reports(self, store):
        """Both topologies produce valid reports for the same scenario."""
        scenario = LOG4SHELL
        mock = MockCoordinator(_build_ooda_responses_for_cve(scenario))

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
        mock2 = MockCoordinator(_build_ooda_responses_for_cve(scenario))
        service2 = MissionService(event_store=store2, coordinator=mock2)
        report2 = await service2.execute(
            mission_type="oneday", target_uri="10.0.0.5", topology="attack_graph",
        )
        assert report2.topology == "attack_graph"
        assert report2.status == "completed"
        await store2.close()


class TestMissionReportGeneration:
    """Verify report quality from real pipeline execution."""

    @pytest.mark.asyncio
    async def test_report_has_all_fields(self, store):
        scenario = LOG4SHELL
        mock = MockCoordinator(_build_ooda_responses_for_cve(scenario))
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

        # Text render
        text = report.as_text()
        assert "MISSION REPORT" in text
        assert "ONEDAY" in text
        assert "10.0.0.5" in text

    @pytest.mark.asyncio
    async def test_report_blackboard_summary(self, store):
        mock = MockCoordinator(_build_ooda_responses_for_cve(LOG4SHELL))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday", target_uri="10.0.0.5", topology="ooda",
        )

        summary = report.blackboard_summary
        assert summary["events"] > 0
