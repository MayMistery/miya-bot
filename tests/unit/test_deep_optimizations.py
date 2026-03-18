"""Tests for deep optimization fixes — edge cases, error recovery, robustness.

Covers:
1. Blackboard: ScanCompleted, ExploitFailed finding, CVE dedup, loot handling
2. Attack graph: _parse_plan with agent extraction, objective detection
3. OODA: reflection parsing edge cases
4. MissionService: partial report on error, on_event safety
"""

from __future__ import annotations

import json
import pytest
import pytest_asyncio

from miya.shared.blackboard import Blackboard
from miya.shared.events import (
    ScanCompleted,
    CVEMatched,
    ExploitAttempted,
    ExploitSucceeded,
    ExploitFailed,
    LootCollected,
    AssetDiscovered,
)
from miya.shared.attack_graph import GraphEdge
from miya.shared.types import Severity
from miya.topology.ooda import OODATopology
from miya.topology.attack_graph_topo import AttackGraphTopology
from miya.infra.event_store import SQLiteEventStore
from miya.mission.service import MissionService


# ═══════════════════════════════════════════════════════════════════
#  Blackboard projection tests
# ═══════════════════════════════════════════════════════════════════


@pytest.fixture
def bb():
    return Blackboard()


class TestScanCompletedProjection:
    def test_scan_completed_creates_finding(self, bb):
        bb.apply(ScanCompleted(
            target_host="10.0.0.1",
            target_ports=(80, 443),
            findings_count=3,
            scanner="nuclei",
        ))
        assert len(bb.findings) == 1
        assert bb.findings[0].severity == Severity.INFO
        assert "nuclei" in bb.findings[0].detail
        assert "3" in bb.findings[0].detail


class TestExploitFailedProjection:
    def test_exploit_failed_creates_info_finding(self, bb):
        bb.apply(ExploitFailed(
            cve_id="CVE-2023-1234",
            reason="Target patched to latest version",
        ))
        assert len(bb.findings) == 1
        assert bb.findings[0].severity == Severity.INFO
        assert "CVE-2023-1234" in bb.findings[0].title
        assert "patched" in bb.findings[0].detail.lower()

    def test_exploit_attempt_status_tracking(self, bb):
        bb.apply(ExploitAttempted(
            cve_id="CVE-2023-1234",
            technique="RCE",
        ))
        assert bb.exploit_attempts[0]["status"] == "attempted"

        bb.apply(ExploitFailed(
            cve_id="CVE-2023-1234",
            reason="Patched",
        ))
        assert bb.exploit_attempts[0]["status"] == "failed"

    def test_exploit_success_status_tracking(self, bb):
        bb.apply(ExploitAttempted(
            cve_id="CVE-2023-5678",
            technique="SQLi",
        ))
        bb.apply(ExploitSucceeded(
            cve_id="CVE-2023-5678",
            access_gained="user",
            evidence="uid=1000",
        ))
        assert bb.exploit_attempts[0]["status"] == "succeeded"


class TestCVEDeduplication:
    def test_duplicate_cve_not_added_twice(self, bb):
        bb.apply(CVEMatched(
            cve_id="CVE-2021-44228",
            cvss=10.0,
            affected_software="Log4j 2.14",
            exploit_available=False,
        ))
        bb.apply(CVEMatched(
            cve_id="CVE-2021-44228",
            cvss=10.0,
            affected_software="Log4j 2.14",
            exploit_available=True,
        ))
        assert len(bb.cve_matches) == 1
        # exploit_available should be updated to True
        assert bb.cve_matches[0]["exploit_available"] is True

    def test_different_cves_both_kept(self, bb):
        bb.apply(CVEMatched(cve_id="CVE-2021-44228", cvss=10.0))
        bb.apply(CVEMatched(cve_id="CVE-2021-45046", cvss=9.0))
        assert len(bb.cve_matches) == 2

    def test_higher_cvss_updates(self, bb):
        bb.apply(CVEMatched(cve_id="CVE-2021-44228", cvss=7.5))
        bb.apply(CVEMatched(cve_id="CVE-2021-44228", cvss=10.0))
        assert bb.cve_matches[0]["cvss"] == 10.0


class TestLootProjection:
    def test_loot_always_creates_finding(self, bb):
        bb.apply(LootCollected(
            loot_type="config",
            description="/etc/shadow contents",
        ))
        assert len(bb.findings) == 1
        assert bb.findings[0].severity == Severity.HIGH
        assert "config" in bb.findings[0].title.lower()
        # Non-credential loot should NOT add to credentials
        assert len(bb.credentials) == 0

    def test_credential_loot_adds_credential(self, bb):
        bb.apply(LootCollected(
            loot_type="credential",
            description="admin:P@ssw0rd",
            value="P@ssw0rd",
        ))
        assert len(bb.credentials) == 1
        assert bb.credentials[0].secret == "P@ssw0rd"
        # Also creates a finding
        assert len(bb.findings) == 1

    def test_credentials_plural_type(self, bb):
        bb.apply(LootCollected(
            loot_type="credentials",
            description="root:toor",
            value="toor",
        ))
        assert len(bb.credentials) == 1


# ═══════════════════════════════════════════════════════════════════
#  Attack graph plan parsing tests
# ═══════════════════════════════════════════════════════════════════


class TestParsePlan:
    def _edges(self):
        return [
            GraphEdge(id="edge-abc-123", source_id="a", target_id="b",
                      label="SQL Injection", technique_id="T1190"),
            GraphEdge(id="edge-def-456", source_id="b", target_id="c",
                      label="Privilege Escalation", technique_id="T1068"),
        ]

    def test_parses_edge_and_agent(self):
        plan = "SELECTED_EDGE: edge-abc\nAGENT: exploit\nRATIONALE: test"
        agents = {"recon": {}, "exploit": {}, "post": {}}
        edge, agent = AttackGraphTopology._parse_plan(
            plan, self._edges(), agents,
        )
        assert edge is not None
        assert edge.id == "edge-abc-123"
        assert agent == "exploit"

    def test_agent_case_insensitive(self):
        plan = "SELECTED_EDGE: edge-def\nAGENT: EXPLOIT"
        agents = {"exploit": {}}
        edge, agent = AttackGraphTopology._parse_plan(
            plan, self._edges(), agents,
        )
        assert agent == "exploit"

    def test_unknown_agent_returns_empty(self):
        plan = "SELECTED_EDGE: edge-abc\nAGENT: nonexistent"
        agents = {"exploit": {}}
        edge, agent = AttackGraphTopology._parse_plan(
            plan, self._edges(), agents,
        )
        assert edge is not None
        assert agent == ""

    def test_fallback_to_label_match(self):
        plan = "Try SQL Injection on the target"
        agents = {"exploit": {}}
        edge, agent = AttackGraphTopology._parse_plan(
            plan, self._edges(), agents,
        )
        assert edge is not None
        assert edge.label == "SQL Injection"

    def test_no_match_returns_none(self):
        plan = "Nothing useful here"
        agents = {}
        edge, agent = AttackGraphTopology._parse_plan(
            plan, self._edges(), agents,
        )
        assert edge is None
        assert agent == ""


# ═══════════════════════════════════════════════════════════════════
#  Success detection tests
# ═══════════════════════════════════════════════════════════════════


class TestDetectSuccess:
    def test_explicit_success(self):
        assert AttackGraphTopology._detect_success("RESULT: SUCCESS got root") is True

    def test_explicit_failure(self):
        assert AttackGraphTopology._detect_success("RESULT: FAILURE patched") is False

    def test_event_marker_success(self):
        assert AttackGraphTopology._detect_success(
            'Some output [EVENT:ExploitSucceeded {"cve_id": "x"}] more text'
        ) is True

    def test_event_marker_failure(self):
        assert AttackGraphTopology._detect_success(
            'Some output [EVENT:ExploitFailed {"cve_id": "x"}] more text'
        ) is False

    def test_heuristic_success(self):
        assert AttackGraphTopology._detect_success(
            "We successfully exploited the target and gained root access"
        ) is True

    def test_heuristic_failure(self):
        assert AttackGraphTopology._detect_success(
            "Exploit failed. Connection refused. Access denied."
        ) is False

    def test_neutral_defaults_to_false(self):
        assert AttackGraphTopology._detect_success(
            "Some neutral output with no clear signal"
        ) is False


# ═══════════════════════════════════════════════════════════════════
#  OODA reflection parsing edge cases
# ═══════════════════════════════════════════════════════════════════


class TestReflectionParsing:
    def test_multiline_assessment(self):
        output = (
            "DECISION: continue\n"
            "ASSESSMENT: The exploit partially worked.\n"
            "We got a low-privilege shell but need escalation.\n"
            "INSIGHTS: SUID binaries found\n"
            "NEXT_FOCUS: privesc"
        )
        result = OODATopology._parse_reflection(output)
        assert result["decision"] == "continue"
        assert "low-privilege" in result["assessment"]
        assert "escalation" in result["assessment"]

    def test_case_insensitive_fields(self):
        output = (
            "decision: Complete\n"
            "assessment: All done\n"
            "insights: Everything worked\n"
            "next_focus: none"
        )
        result = OODATopology._parse_reflection(output)
        assert result["decision"] == "complete"

    def test_heuristic_fallback_flag_found(self):
        # "flag{" alone no longer triggers complete (false positive risk).
        # But "flag found" still works as a completion heuristic.
        output = "We found the flag. Flag found after SQL injection in login form."
        result = OODATopology._parse_reflection(output)
        assert result["decision"] == "complete"

    def test_flag_brace_alone_does_not_complete(self):
        # Regression: "flag{" in discussion should NOT trigger completion
        output = "The challenge uses flag{...} format. Let me try another approach."
        result = OODATopology._parse_reflection(output)
        assert result["decision"] == "continue"

    def test_heuristic_fallback_objective_achieved(self):
        output = "We have achieved our objective. Root access obtained via kernel exploit."
        result = OODATopology._parse_reflection(output)
        assert result["decision"] == "complete"

    def test_no_signal_defaults_to_continue(self):
        output = "Some analysis text without any clear decision markers."
        result = OODATopology._parse_reflection(output)
        assert result["decision"] == "continue"

    def test_pivot_decision(self):
        output = (
            "DECISION: pivot\n"
            "ASSESSMENT: SQL injection failed, try SSTI\n"
            "INSIGHTS: Input is template-rendered\n"
            "NEXT_FOCUS: Server-Side Template Injection"
        )
        result = OODATopology._parse_reflection(output)
        assert result["decision"] == "pivot"
        assert "Template Injection" in result["next_focus"]


# ═══════════════════════════════════════════════════════════════════
#  MissionService error recovery tests
# ═══════════════════════════════════════════════════════════════════


class FailingCoordinator:
    """Coordinator that fails after N calls."""

    def __init__(self, fail_after: int = 2):
        self._call_count = 0
        self._fail_after = fail_after

    async def run(self, prompt: str, agents: dict, mcp_servers: list[str]) -> str:
        self._call_count += 1
        if self._call_count >= self._fail_after:
            raise RuntimeError("Simulated coordinator failure")
        # Return a simple observe output for first call
        if "OBSERVE" in prompt:
            return (
                "Target discovered. "
                '[EVENT:AssetDiscovered {"host": "test.com", "ip": "1.2.3.4", '
                '"ports": [80], "services": ["http"], "os": "Linux", "context": "recon"}]'
            )
        return "DECISION: complete\nASSESSMENT: done\nINSIGHTS: n/a\nNEXT_FOCUS: n/a"


@pytest_asyncio.fixture
async def store():
    s = SQLiteEventStore(":memory:")
    await s.initialize()
    yield s
    await s.close()


class TestMissionServiceErrorRecovery:
    @pytest.mark.asyncio
    async def test_partial_report_on_failure(self, store):
        mock = FailingCoordinator(fail_after=3)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="test.com",
            topology="ooda",
        )

        assert report.status == "failed"
        assert report.error != ""
        assert "Simulated" in report.error
        # Should have partial findings from before failure
        assert report.events_count > 0

    @pytest.mark.asyncio
    async def test_on_event_callback_exception_safe(self, store):
        """on_event callback exceptions should not crash the mission."""

        def bad_callback(event):
            raise ValueError("callback error")

        class QuickCoordinator:
            async def run(self, prompt, agents, mcp_servers):
                if "OBSERVE" in prompt:
                    return "Nothing found."
                if "ORIENT" in prompt:
                    return "No opportunities."
                if "DECIDE" in prompt:
                    return "No actions."
                if "ACT" in prompt:
                    return "Nothing to do."
                if "REFLECT" in prompt:
                    return "DECISION: complete\nASSESSMENT: done"
                return ""

        service = MissionService(event_store=store, coordinator=QuickCoordinator())

        # Should complete without raising despite bad callback
        report = await service.execute(
            mission_type="oneday",
            target_uri="test.com",
            topology="ooda",
            on_event=bad_callback,
        )
        assert report.status == "completed"


# ═══════════════════════════════════════════════════════════════════
#  MissionReport error field test
# ═══════════════════════════════════════════════════════════════════


class TestMissionReport:
    def test_error_field_default_empty(self):
        from miya.mission.service import MissionReport
        report = MissionReport()
        assert report.error == ""

    def test_error_field_set(self):
        from miya.mission.service import MissionReport
        report = MissionReport(error="Something went wrong", status="failed")
        assert report.error == "Something went wrong"
        assert report.status == "failed"


# ═══════════════════════════════════════════════════════════════════
#  Severity parsing robustness
# ═══════════════════════════════════════════════════════════════════


class TestSeverityParsing:
    def test_valid_severity(self, bb):
        from miya.shared.events import VulnerabilityFound
        bb.apply(VulnerabilityFound(severity="critical", vuln_type="RCE", cwe_id="CWE-78"))
        assert bb.findings[0].severity == Severity.CRITICAL

    def test_unknown_severity_defaults_to_medium(self, bb):
        from miya.shared.events import VulnerabilityFound
        bb.apply(VulnerabilityFound(severity="unknown_value", vuln_type="Test", cwe_id="CWE-0"))
        assert bb.findings[0].severity == Severity.MEDIUM

    def test_empty_severity_defaults_to_medium(self, bb):
        from miya.shared.events import VulnerabilityFound
        bb.apply(VulnerabilityFound(severity="", vuln_type="Test", cwe_id="CWE-0"))
        assert bb.findings[0].severity == Severity.MEDIUM

    def test_uppercase_severity(self, bb):
        from miya.shared.events import VulnerabilityFound
        bb.apply(VulnerabilityFound(severity="HIGH", vuln_type="Test", cwe_id="CWE-0"))
        assert bb.findings[0].severity == Severity.HIGH
