"""Advanced E2E pipeline tests — high-difficulty multi-stage CVE chains & CTF challenges.

These tests go beyond single-pass OODA loops to exercise:
  1. Multi-iteration OODA with pivot/retry decisions
  2. Multi-stage exploit chains (initial access → privesc → lateral movement → loot)
  3. Deep blackboard assertions at every phase boundary
  4. Event store replay + projection verification
  5. AttackGraph topology with multi-node graph traversal
  6. Post-exploitation with credential harvesting and lateral movement

5 Advanced CVE scenarios:
  - ProxyShell (3-CVE chain on Exchange)
  - Log4Shell → Dirty Pipe (initial access + kernel LPE)
  - MOVEit SQLi → Deserialization RCE
  - CitrixBleed → Kerberoast → Domain Admin
  - Confluence OGNL → Container Escape

5 Advanced CTF scenarios:
  - Heap Maze (tcache poison → __free_hook, 500pts)
  - XML Fortress (blind XXE + WAF bypass, 400pts)
  - Curve Breaker (ECC invalid curve attack, 500pts)
  - Ring Zero (kernel ROP + SMEP bypass, 600pts)
  - Web Labyrinth (SSRF → SSTI → RCE chain, 500pts)
"""

from __future__ import annotations

import json
import pytest
import pytest_asyncio

from miya.shared.blackboard import Blackboard
from miya.shared.events import (
    VulnerabilityFound,
    CVEMatched,
    PrivilegeEscalated,
    LootCollected,
    ChallengeIdentified,
    ChallengeSolved,
    PhaseTransition,
    ReflectionCompleted,
    MissionStarted,
    MissionCompleted,
)
from miya.infra.event_store import SQLiteEventStore
from miya.mission.service import MissionService

from tests.fixtures.cve_scenarios import (
    PROXYSHELL, DIRTY_PIPE, MOVEIT_CHAIN, CITRIX_BLEED, CONFLUENCE_RCE,
    HEAP_TCACHE, BLIND_XXE, ECC_INVALID_CURVE, KERNEL_ROP, WEB_CHAIN,
    AdvancedCVEScenario, AdvancedCTFScenario,
)


# ═══════════════════════════════════════════════════════════════════
#  Multi-Iteration Mock Coordinator
# ═══════════════════════════════════════════════════════════════════


def _ev(event_type: str, **fields: object) -> str:
    """Format an [EVENT:...] marker for embedding in mock responses."""
    return f'[EVENT:{event_type} {json.dumps(fields)}]'


class MultiStageCoordinator:
    """Mock coordinator that simulates multi-iteration OODA loops.

    Unlike the simple MockCoordinator, this one:
    - Tracks iteration count and returns different responses per iteration
    - Supports pivot/retry decisions before completing
    - Emits events incrementally across OODA iterations
    - Simulates realistic multi-stage exploitation chains
    """

    def __init__(self, iteration_responses: list[dict[str, str]]) -> None:
        """
        Args:
            iteration_responses: List of {phase: response} dicts, one per OODA iteration.
                The REFLECT phase in each iteration determines continue/pivot/complete.
        """
        self.calls: list[dict] = []
        self._iterations = iteration_responses
        self._call_count = 0
        self._current_iteration = 0
        self._phase_counts: dict[str, int] = {}

    async def run(
        self,
        prompt: str,
        agents: dict,
        mcp_servers: list[str],
    ) -> str:
        self.calls.append({
            "prompt": prompt[:200],
            "agents": list(agents.keys()),
            "mcp_servers": mcp_servers,
        })
        self._call_count += 1

        # Detect which OODA phase this prompt is for
        phase = self._detect_phase(prompt)
        if phase:
            self._phase_counts[phase] = self._phase_counts.get(phase, 0) + 1

        # Track REFLECT to advance iteration counter
        if phase == "REFLECT":
            idx = min(self._current_iteration, len(self._iterations) - 1)
            response = self._iterations[idx].get("REFLECT", "DECISION: complete")
            self._current_iteration += 1
            return response

        # Get response for current iteration + phase
        idx = min(self._current_iteration, len(self._iterations) - 1)
        if phase and phase in self._iterations[idx]:
            return self._iterations[idx][phase]

        return f"[Mock call #{self._call_count}] phase={phase} iter={self._current_iteration}"

    def _detect_phase(self, prompt: str) -> str | None:
        for phase in ("OBSERVE", "ORIENT", "DECIDE", "ACT", "REFLECT"):
            if f"## {phase}" in prompt or f"Phase: {phase}" in prompt:
                return phase
        # AttackGraph prompts
        if "Strategic Planner" in prompt:
            return "PLAN"
        if "Tactical Executor" in prompt:
            return "EXECUTE"
        if "Reconnaissance phase" in prompt:
            return "RECON"
        if "Graph Update" in prompt:
            return "REBUILD"
        return None

    @property
    def iteration_count(self) -> int:
        return self._current_iteration


def _build_multistage_cve_responses(
    scenario: AdvancedCVEScenario,
    target_ip: str,
) -> list[dict[str, str]]:
    """Build multi-iteration OODA responses for an advanced CVE scenario.

    Each stage of the exploit chain becomes one OODA iteration.
    Intermediate stages return DECISION: continue, final stage returns complete.
    """
    iterations: list[dict[str, str]] = []

    for i, stage in enumerate(scenario.stages):
        is_last = (i == len(scenario.stages) - 1)
        is_first = (i == 0)

        ports_list = list(stage.affected_ports) or [443]
        services = ["https"] * len(ports_list)

        observe_events = ""
        if is_first:
            # First iteration: discover the asset
            observe_events = (
                _ev("AssetDiscovered",
                    aggregate_id=f"asset-{target_ip}",
                    host=target_ip, ip=target_ip,
                    ports=ports_list, services=services,
                    os="Linux" if "Linux" in stage.target_software else "Windows Server 2019",
                    context="recon")
                + " "
                + _ev("FingerprintCompleted",
                      asset_id=f"asset-{target_ip}",
                      software=stage.target_software,
                      version=stage.target_version,
                      context="recon")
            )

        orient_events = (
            _ev("VulnerabilityFound",
                vuln_type=stage.vuln_type,
                cwe_id=stage.cwe_id,
                severity="critical",
                location=f"{target_ip}:{ports_list[0]}",
                description=stage.description[:150],
                context="vuln")
            + " "
            + _ev("CVEMatched",
                  cve_id=stage.cve_id,
                  cvss=stage.cvss,
                  affected_software=f"{stage.target_software} {stage.target_version}",
                  exploit_available=True,
                  context="vuln")
        )

        act_events = (
            _ev("ExploitAttempted",
                cve_id=stage.cve_id,
                technique=stage.exploit_technique,
                payload_summary=stage.attack_vector[:80],
                context="exploit")
            + " "
            + _ev("ExploitSucceeded",
                  cve_id=stage.cve_id,
                  access_gained=stage.expected_access,
                  evidence=stage.evidence_pattern,
                  context="exploit")
        )

        # Add privilege escalation event if access changes
        if i > 0:
            prev_access = scenario.stages[i - 1].expected_access
            act_events += " " + _ev("PrivilegeEscalated",
                                     from_level=prev_access,
                                     to_level=stage.expected_access,
                                     technique=f"{stage.cve_id} ({stage.exploit_technique})",
                                     context="post")

        # Add loot collection on final stage
        loot_events = ""
        if is_last and scenario.loot:
            for loot in scenario.loot:
                loot_events += " " + _ev("LootCollected",
                                          loot_type=loot["type"],
                                          description=loot["desc"],
                                          context="post")

        # Add lateral movement asset discovery
        lateral_events = ""
        if is_last and scenario.lateral_targets:
            for j, lat_target in enumerate(scenario.lateral_targets):
                lateral_events += " " + _ev("AssetDiscovered",
                                             aggregate_id=f"asset-lateral-{j}",
                                             host=lat_target,
                                             ip=f"10.10.0.{10+j}",
                                             ports=[445, 389, 3389],
                                             services=["smb", "ldap", "rdp"],
                                             os="Windows Server 2019",
                                             context="recon")

        # Build REFLECT decision
        if is_last:
            reflect = (
                f"DECISION: complete\n"
                f"ASSESSMENT: Full chain exploited: {' → '.join(s.name for s in scenario.stages)}\n"
                f"INSIGHTS: {scenario.description}\n"
                f"NEXT_FOCUS: n/a"
            )
        else:
            next_stage = scenario.stages[i + 1]
            reflect = (
                f"DECISION: continue\n"
                f"ASSESSMENT: Stage {i+1} succeeded — gained {stage.expected_access} access\n"
                f"INSIGHTS: Now targeting {next_stage.cve_id} for next stage\n"
                f"NEXT_FOCUS: {next_stage.exploit_technique}"
            )

        iterations.append({
            "OBSERVE": (
                f"Iteration {i+1}: Scanning for {stage.target_software}. "
                + observe_events
            ),
            "ORIENT": (
                f"Analysis: {stage.cve_id} ({stage.vuln_type}) present. "
                + orient_events
            ),
            "DECIDE": (
                f"Plan: Exploit {stage.cve_id} via {stage.exploit_technique}. "
                f"Attack vector: {stage.attack_vector[:60]}"
            ),
            "ACT": (
                f"SUCCESS — {stage.name} exploited. Gained {stage.expected_access}. "
                + act_events + loot_events + lateral_events
            ),
            "REFLECT": reflect,
        })

    return iterations


def _build_multistage_ctf_responses(
    scenario: AdvancedCTFScenario,
) -> list[dict[str, str]]:
    """Build multi-iteration OODA responses for an advanced CTF scenario.

    Each step becomes one OODA iteration. Steps before the last use
    DECISION: continue. The final step solves the challenge.
    """
    iterations: list[dict[str, str]] = []
    num_steps = len(scenario.steps)

    for i, step in enumerate(scenario.steps):
        is_first = (i == 0)
        is_last = (i == num_steps - 1)

        observe_events = ""
        if is_first:
            observe_events = _ev("ChallengeIdentified",
                                  challenge_name=scenario.name,
                                  category=scenario.category,
                                  points=scenario.points,
                                  context="ctf")

        act_text = f"Step {i+1}/{num_steps}: {step['technique']} — {step['result']}"
        act_events = ""
        if is_last:
            act_events = " " + _ev("ChallengeSolved",
                                    challenge_name=scenario.name,
                                    flag=scenario.flag,
                                    approach=scenario.final_approach,
                                    context="ctf")

        if is_last:
            reflect = (
                f"DECISION: complete\n"
                f"ASSESSMENT: Challenge solved! Flag: {scenario.flag}\n"
                f"INSIGHTS: {scenario.final_approach}\n"
                f"NEXT_FOCUS: n/a"
            )
        else:
            next_step = scenario.steps[i + 1]
            reflect = (
                f"DECISION: continue\n"
                f"ASSESSMENT: Step {i+1} complete: {step['technique']}\n"
                f"INSIGHTS: {step['result']}\n"
                f"NEXT_FOCUS: {next_step['technique']}"
            )

        iterations.append({
            "OBSERVE": (
                f"Observing challenge state after step {i}. "
                + observe_events
                + f" Current progress: {i}/{num_steps} steps complete."
            ),
            "ORIENT": (
                f"Analysis: Next technique needed is {step['technique']}. "
                f"Challenge: {scenario.description[:100]}"
            ),
            "DECIDE": (
                f"Plan: Apply {step['technique']}. "
                f"Expected outcome: {step['result'][:80]}"
            ),
            "ACT": act_text + act_events,
            "REFLECT": reflect,
        })

    return iterations


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
#  Advanced CVE 1: ProxyShell (3-stage Exchange chain)
# ═══════════════════════════════════════════════════════════════════


class TestProxyShellChain:
    """Full E2E: ProxyShell 3-CVE chain on Microsoft Exchange.

    SSRF (CVE-2021-34473) → Elevation (CVE-2021-34523) → Webshell RCE (CVE-2021-31207)
    with lateral movement discovery and credential harvesting.
    """

    @pytest.mark.asyncio
    async def test_proxyshell_full_chain(self, store):
        scenario = PROXYSHELL
        responses = _build_multistage_cve_responses(scenario, "exchange.corp.local")
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="exchange.corp.local",
            target_kind="service",
            topology="ooda",
        )

        # Pipeline completed with multi-iteration
        assert report.status == "completed"
        assert report.topology == "ooda"
        assert report.events_count > 0

        # 3 OODA iterations (one per stage)
        assert mock.iteration_count == 3, (
            f"ProxyShell requires 3 iterations, got {mock.iteration_count}"
        )

        # At least 5 calls per iteration (OBSERVE+ORIENT+DECIDE+ACT+REFLECT)
        assert len(mock.calls) >= 15, (
            f"Expected ≥15 coordinator calls for 3 iterations, got {len(mock.calls)}"
        )

        # Blackboard deep assertions
        summary = report.blackboard_summary
        assert summary["assets"] >= 1, "Exchange server should be discovered"
        assert summary["cve_matches"] >= 3, "All 3 CVEs should be matched"
        assert summary["findings"] >= 3, "At least 3 findings (one per vuln + exploit successes)"
        assert summary["exploit_attempts"] >= 3, "One exploit attempt per stage"

        # Access level should be 'system' (final stage)
        assert summary["access_level"] == "system", (
            f"Final access should be system, got {summary['access_level']}"
        )

        # Loot collected
        assert summary["credentials"] >= 1, "Credential loot should be harvested"

        # Lateral movement targets discovered
        assert summary["assets"] >= 3, (
            "Exchange + 2 lateral targets should be in assets"
        )

        # Event store verification
        all_events = await store.load_all()
        assert len(all_events) == report.events_count

        # Verify event types present
        event_types = {type(e).__name__ for e in all_events}
        assert "AssetDiscovered" in event_types
        assert "CVEMatched" in event_types
        assert "ExploitAttempted" in event_types
        assert "ExploitSucceeded" in event_types
        assert "PrivilegeEscalated" in event_types
        assert "LootCollected" in event_types

        # Report quality
        text = report.as_text()
        assert "CRITICAL" in text
        assert report.critical_count >= 3

    @pytest.mark.asyncio
    async def test_proxyshell_event_replay(self, store):
        """Verify events can be replayed into fresh blackboard with identical state."""
        scenario = PROXYSHELL
        responses = _build_multistage_cve_responses(scenario, "exchange.corp.local")
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="exchange.corp.local",
            topology="ooda",
        )

        # Replay into fresh blackboard
        all_events = await store.load_all()
        replayed_bb = Blackboard()
        replayed_bb.apply_all(all_events)

        # Replayed state matches original report
        replayed_summary = replayed_bb.summary()
        assert replayed_summary["assets"] == report.blackboard_summary["assets"]
        assert replayed_summary["cve_matches"] == report.blackboard_summary["cve_matches"]
        assert replayed_summary["access_level"] == report.blackboard_summary["access_level"]
        assert replayed_summary["credentials"] == report.blackboard_summary["credentials"]
        assert replayed_summary["events"] == len(all_events)


# ═══════════════════════════════════════════════════════════════════
#  Advanced CVE 2: Log4Shell → Dirty Pipe
# ═══════════════════════════════════════════════════════════════════


class TestDirtyPipeChain:
    """Full E2E: Log4Shell initial access → Dirty Pipe kernel LPE.

    Tests two-stage chain: remote RCE for foothold, then local privesc to root.
    """

    @pytest.mark.asyncio
    async def test_dirty_pipe_full_chain(self, store):
        scenario = DIRTY_PIPE
        responses = _build_multistage_cve_responses(scenario, "10.0.0.50")
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="10.0.0.50",
            topology="ooda",
        )

        assert report.status == "completed"
        assert mock.iteration_count == 2, "Two stages: Log4Shell + Dirty Pipe"

        summary = report.blackboard_summary

        # Two CVEs matched
        assert summary["cve_matches"] >= 2

        # Access escalated from user → root
        assert summary["access_level"] == "root"

        # Two exploit attempts
        assert summary["exploit_attempts"] >= 2

        # Loot: shadow hash + SSH key
        assert summary["credentials"] >= 1

        # Verify escalation path in events
        all_events = await store.load_all()
        privesc_events = [e for e in all_events if isinstance(e, PrivilegeEscalated)]
        assert len(privesc_events) >= 1
        assert any(e.to_level == "root" for e in privesc_events)

        # Verify reflection decisions: first "continue", then "complete"
        reflection_events = [e for e in all_events if isinstance(e, ReflectionCompleted)]
        assert len(reflection_events) >= 2
        decisions = [e.decision for e in reflection_events]
        assert "continue" in decisions, "First iteration should continue"
        assert "complete" in decisions, "Final iteration should complete"

    @pytest.mark.asyncio
    async def test_dirty_pipe_context_prompt_progression(self, store):
        """Verify blackboard context prompt grows between iterations."""
        scenario = DIRTY_PIPE
        responses = _build_multistage_cve_responses(scenario, "10.0.0.50")
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        await service.execute(
            mission_type="oneday",
            target_uri="10.0.0.50",
            topology="ooda",
        )

        # The final context prompt should contain data from both iterations
        all_events = await store.load_all()
        bb = Blackboard()
        bb.apply_all(all_events)
        prompt = bb.to_context_prompt()

        assert "CVE-2021-44228" in prompt, "Log4Shell CVE should be in context"
        assert "CVE-2022-0847" in prompt, "Dirty Pipe CVE should be in context"
        assert "root" in prompt.lower(), "Root access should appear in context"
        assert "[EXPLOIT]" in prompt


# ═══════════════════════════════════════════════════════════════════
#  Advanced CVE 3: MOVEit SQLi → Deserialization RCE
# ═══════════════════════════════════════════════════════════════════


class TestMOVEitChain:
    """Full E2E: MOVEit Transfer SQLi → deserialization webshell → data exfil."""

    @pytest.mark.asyncio
    async def test_moveit_full_chain(self, store):
        scenario = MOVEIT_CHAIN
        responses = _build_multistage_cve_responses(scenario, "moveit.corp.com")
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="moveit.corp.com",
            topology="ooda",
        )

        assert report.status == "completed"
        assert mock.iteration_count == 2

        summary = report.blackboard_summary
        assert summary["access_level"] == "system"
        # Both stages use same CVE-2023-34362, so dedup yields 1
        assert summary["cve_matches"] >= 1

        # Both SQL injection and deserialization findings
        all_events = await store.load_all()
        vuln_events = [e for e in all_events if isinstance(e, VulnerabilityFound)]
        vuln_types = {e.vuln_type for e in vuln_events}
        assert "SQL Injection" in vuln_types
        assert "Deserialization RCE" in vuln_types

        # Loot: DB dump + Azure credentials
        assert summary["credentials"] >= 1

    @pytest.mark.asyncio
    async def test_moveit_attack_graph_topology(self, store):
        """Run MOVEit chain through AttackGraph topology."""
        scenario = MOVEIT_CHAIN
        responses = _build_multistage_cve_responses(scenario, "moveit.corp.com")
        # For attack_graph, responses are matched by keyword not phase header
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="moveit.corp.com",
            topology="attack_graph",
        )

        assert report.status == "completed"
        assert report.topology == "attack_graph"
        assert report.events_count > 0

        # AttackGraph should still populate blackboard
        summary = report.blackboard_summary
        assert summary["events"] > 0


# ═══════════════════════════════════════════════════════════════════
#  Advanced CVE 4: CitrixBleed → Kerberoast → Domain Admin
# ═══════════════════════════════════════════════════════════════════


class TestCitrixBleedChain:
    """Full E2E: CitrixBleed session hijack → Kerberoast → Domain Admin."""

    @pytest.mark.asyncio
    async def test_citrix_bleed_full_chain(self, store):
        scenario = CITRIX_BLEED
        responses = _build_multistage_cve_responses(scenario, "vpn.corp.com")
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="vpn.corp.com",
            topology="ooda",
        )

        assert report.status == "completed"
        assert mock.iteration_count == 2

        summary = report.blackboard_summary

        # Escalation path: vpn_session → domain_admin
        assert summary["access_level"] == "domain_admin"

        # Lateral targets discovered (dc01, fileserver, sql01)
        assert summary["assets"] >= 4, (
            "VPN gateway + 3 lateral targets"
        )

        # Multiple credential loot
        assert summary["credentials"] >= 1

        # Verify complete CVE chain in events
        all_events = await store.load_all()
        cve_events = [e for e in all_events if isinstance(e, CVEMatched)]
        cve_ids = {e.cve_id for e in cve_events}
        assert "CVE-2023-4966" in cve_ids

        # Verify escalation events
        privesc = [e for e in all_events if isinstance(e, PrivilegeEscalated)]
        assert len(privesc) >= 1
        assert any(e.to_level == "domain_admin" for e in privesc)

    @pytest.mark.asyncio
    async def test_citrix_bleed_lateral_movement_in_blackboard(self, store):
        """Verify lateral movement targets appear in blackboard context prompt."""
        scenario = CITRIX_BLEED
        responses = _build_multistage_cve_responses(scenario, "vpn.corp.com")
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        await service.execute(
            mission_type="oneday",
            target_uri="vpn.corp.com",
            topology="ooda",
        )

        all_events = await store.load_all()
        bb = Blackboard()
        bb.apply_all(all_events)
        prompt = bb.to_context_prompt()

        # Lateral targets may appear by IP or hostname depending on Asset.address
        assert len(bb.assets) >= 4, "VPN + 3 lateral targets"
        # Verify lateral target IPs present
        assert "10.10.0.10" in prompt
        assert "10.10.0.11" in prompt
        assert "10.10.0.12" in prompt
        assert "domain_admin" in prompt.lower() or "domain_admin" in bb.current_access_level


# ═══════════════════════════════════════════════════════════════════
#  Advanced CVE 5: Confluence OGNL → Container Escape
# ═══════════════════════════════════════════════════════════════════


class TestConfluenceContainerEscape:
    """Full E2E: Confluence OGNL injection → container escape → host root."""

    @pytest.mark.asyncio
    async def test_confluence_escape_full_chain(self, store):
        scenario = CONFLUENCE_RCE
        responses = _build_multistage_cve_responses(scenario, "confluence.internal")
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri="confluence.internal",
            topology="ooda",
        )

        assert report.status == "completed"
        assert mock.iteration_count == 2

        summary = report.blackboard_summary

        # container user → root (via container escape)
        assert summary["access_level"] == "root"
        assert summary["cve_matches"] >= 2

        # Both CVEs present
        all_events = await store.load_all()
        cve_events = [e for e in all_events if isinstance(e, CVEMatched)]
        cve_ids = {e.cve_id for e in cve_events}
        assert "CVE-2022-26134" in cve_ids, "Confluence OGNL CVE"
        assert "CVE-2022-0185" in cve_ids, "Container escape CVE"

        # Loot: DB creds + k8s token + shadow
        loot_events = [e for e in all_events if isinstance(e, LootCollected)]
        assert len(loot_events) >= 3
        loot_types = {e.loot_type for e in loot_events}
        assert "credential" in loot_types
        assert "key" in loot_types
        assert "data" in loot_types

        # Verify multi-CWE findings
        vuln_events = [e for e in all_events if isinstance(e, VulnerabilityFound)]
        cwes = {e.cwe_id for e in vuln_events}
        assert "CWE-917" in cwes, "OGNL injection CWE"
        assert "CWE-190" in cwes, "Container escape CWE"

    @pytest.mark.asyncio
    async def test_confluence_escape_event_store_queries(self, store):
        """Verify event store queries work correctly across multi-stage chain."""
        scenario = CONFLUENCE_RCE
        responses = _build_multistage_cve_responses(scenario, "confluence.internal")
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        await service.execute(
            mission_type="oneday",
            target_uri="confluence.internal",
            topology="ooda",
        )

        # Query by context
        exploit_events = await store.load_by_context("exploit")
        assert len(exploit_events) >= 2, "At least 2 exploit context events"

        recon_events = await store.load_by_context("recon")
        assert len(recon_events) >= 1, "At least 1 recon context event"

        vuln_events = await store.load_by_context("vuln")
        assert len(vuln_events) >= 2, "At least 2 vuln context events"

        post_events = await store.load_by_context("post")
        assert len(post_events) >= 1, "At least 1 post-exploitation event"

        # Total event count
        total = await store.count()
        all_events = await store.load_all()
        assert total == len(all_events)


# ═══════════════════════════════════════════════════════════════════
#  Advanced CTF 1: Heap Maze (tcache poisoning, 500pts)
# ═══════════════════════════════════════════════════════════════════


class TestHeapMazeCTF:
    """Full E2E: Heap exploitation with 4-step tcache poisoning chain."""

    @pytest.mark.asyncio
    async def test_heap_maze_full_pipeline(self, store):
        scenario = HEAP_TCACHE
        responses = _build_multistage_ctf_responses(scenario)
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/heap",
            topology="ooda",
        )

        assert report.status == "completed"
        assert report.mission_type == "ctf"

        # 4 iterations (one per step)
        assert mock.iteration_count == 4, (
            f"Heap Maze needs 4 iterations, got {mock.iteration_count}"
        )

        # Challenge identified and solved
        all_events = await store.load_all()

        challenge_events = [e for e in all_events if isinstance(e, ChallengeIdentified)]
        assert len(challenge_events) >= 1
        assert challenge_events[0].challenge_name == "Heap Maze"
        assert challenge_events[0].points == 500

        solved_events = [e for e in all_events if isinstance(e, ChallengeSolved)]
        assert len(solved_events) >= 1
        assert solved_events[0].flag == "flag{tc4ch3_p01s0n_4nd_fr33_h00k}"
        assert "tcache" in solved_events[0].approach.lower() or "free_hook" in solved_events[0].approach.lower()

        # Reflections show step-by-step progression
        reflections = [e for e in all_events if isinstance(e, ReflectionCompleted)]
        assert len(reflections) >= 4
        decisions = [e.decision for e in reflections]
        # First 3 should be "continue", last should be "complete"
        assert decisions.count("continue") >= 3
        assert decisions[-1] == "complete"

    @pytest.mark.asyncio
    async def test_heap_maze_event_replay_matches(self, store):
        """Verify replay produces identical blackboard state."""
        scenario = HEAP_TCACHE
        responses = _build_multistage_ctf_responses(scenario)
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        await service.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/heap",
            topology="ooda",
        )

        all_events = await store.load_all()
        bb = Blackboard()
        bb.apply_all(all_events)

        assert len(bb.challenges) >= 1
        assert len(bb.solved_flags) >= 1
        assert bb.solved_flags[0].flag == scenario.flag

        prompt = bb.to_context_prompt()
        assert "DONE" in prompt
        assert "Heap Maze" in prompt


# ═══════════════════════════════════════════════════════════════════
#  Advanced CTF 2: XML Fortress (blind XXE, 400pts)
# ═══════════════════════════════════════════════════════════════════


class TestBlindXXECTF:
    """Full E2E: Blind XXE with WAF bypass through 4-step chain."""

    @pytest.mark.asyncio
    async def test_blind_xxe_full_pipeline(self, store):
        scenario = BLIND_XXE
        responses = _build_multistage_ctf_responses(scenario)
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/xxe",
            topology="ooda",
        )

        assert report.status == "completed"
        assert mock.iteration_count == 4

        all_events = await store.load_all()

        # Challenge solved with correct flag
        solved = [e for e in all_events if isinstance(e, ChallengeSolved)]
        assert len(solved) >= 1
        assert solved[0].flag == "flag{00b_xxe_utf16_byp4ss}"
        assert "UTF-16" in solved[0].approach or "exfiltration" in solved[0].approach

        # Verify progression of REFLECT decisions
        reflections = [e for e in all_events if isinstance(e, ReflectionCompleted)]
        insights = [e.insights for e in reflections]
        # Insights should mention the WAF bypass progression
        assert any("WAF" in i or "waf" in i.lower() or "encoding" in i.lower()
                   for i in insights[:3]), "Early insights should mention WAF/encoding"


# ═══════════════════════════════════════════════════════════════════
#  Advanced CTF 3: Curve Breaker (ECC invalid curve, 500pts)
# ═══════════════════════════════════════════════════════════════════


class TestECCInvalidCurveCTF:
    """Full E2E: ECC invalid curve attack with CRT key recovery."""

    @pytest.mark.asyncio
    async def test_ecc_invalid_curve_full_pipeline(self, store):
        scenario = ECC_INVALID_CURVE
        responses = _build_multistage_ctf_responses(scenario)
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/ecc",
            topology="ooda",
        )

        assert report.status == "completed"
        assert mock.iteration_count == 4, "4 steps: recon, subgroup, oracle, CRT"

        all_events = await store.load_all()
        solved = [e for e in all_events if isinstance(e, ChallengeSolved)]
        assert len(solved) >= 1
        assert solved[0].flag == "flag{1nv4l1d_curv3_crt_4tt4ck}"

        # Verify 500pts challenge
        identified = [e for e in all_events if isinstance(e, ChallengeIdentified)]
        assert identified[0].points == 500
        assert identified[0].category == "crypto"

    @pytest.mark.asyncio
    async def test_ecc_coordinator_call_count(self, store):
        """Verify coordinator is called exactly right number of times."""
        scenario = ECC_INVALID_CURVE
        responses = _build_multistage_ctf_responses(scenario)
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        await service.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/ecc",
            topology="ooda",
        )

        # 4 iterations × 3 phases (observe, act, reflect) + 1 classify = 13 calls
        assert len(mock.calls) >= 13, (
            f"Expected ≥13 calls for 4 iterations, got {len(mock.calls)}"
        )


# ═══════════════════════════════════════════════════════════════════
#  Advanced CTF 4: Ring Zero (kernel ROP, 600pts)
# ═══════════════════════════════════════════════════════════════════


class TestKernelROPCTF:
    """Full E2E: Kernel exploitation with SMEP/KASLR bypass."""

    @pytest.mark.asyncio
    async def test_kernel_rop_full_pipeline(self, store):
        scenario = KERNEL_ROP
        responses = _build_multistage_ctf_responses(scenario)
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/kernel",
            topology="ooda",
        )

        assert report.status == "completed"
        assert mock.iteration_count == 4

        all_events = await store.load_all()

        # Highest-difficulty challenge: 600pts
        identified = [e for e in all_events if isinstance(e, ChallengeIdentified)]
        assert identified[0].points == 600
        assert identified[0].category == "pwn"

        solved = [e for e in all_events if isinstance(e, ChallengeSolved)]
        assert solved[0].flag == "flag{k3rn3l_r0p_sm3p_byp4ss}"

        # Verify OODA iterations tracked in phase history
        phase_events = [e for e in all_events if isinstance(e, PhaseTransition)]
        # 4 iterations × 3 phase transitions (observe→act→reflect) = 12
        assert len(phase_events) >= 12

        # Report should list the challenge
        report.as_text()
        assert report.events_count > 0

    @pytest.mark.asyncio
    async def test_kernel_rop_reflection_insights(self, store):
        """Verify reflection insights capture the progressive attack steps."""
        scenario = KERNEL_ROP
        responses = _build_multistage_ctf_responses(scenario)
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        await service.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/kernel",
            topology="ooda",
        )

        all_events = await store.load_all()
        reflections = [e for e in all_events if isinstance(e, ReflectionCompleted)]

        # Each step's insights should reference the technique result
        assert len(reflections) >= 4
        # First reflection should mention KASLR leak
        assert any("kaslr" in r.insights.lower() or "kernel" in r.insights.lower()
                   for r in reflections[:2])


# ═══════════════════════════════════════════════════════════════════
#  Advanced CTF 5: Web Labyrinth (SSRF → SSTI → RCE, 500pts)
# ═══════════════════════════════════════════════════════════════════


class TestWebLabyrinthCTF:
    """Full E2E: Multi-stage web challenge with SSRF → SSTI → RCE chain."""

    @pytest.mark.asyncio
    async def test_web_labyrinth_full_pipeline(self, store):
        scenario = WEB_CHAIN
        responses = _build_multistage_ctf_responses(scenario)
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/web-chain",
            topology="ooda",
        )

        assert report.status == "completed"
        assert mock.iteration_count == 4

        all_events = await store.load_all()

        # Challenge identified as web, 500pts
        identified = [e for e in all_events if isinstance(e, ChallengeIdentified)]
        assert identified[0].points == 500
        assert identified[0].category == "web"

        # Flag captured
        solved = [e for e in all_events if isinstance(e, ChallengeSolved)]
        assert solved[0].flag == "flag{ssrf_sst1_rc3_ch41n}"
        assert "SSRF" in solved[0].approach or "SSTI" in solved[0].approach

    @pytest.mark.asyncio
    async def test_web_labyrinth_attack_graph_topology(self, store):
        """Run the web chain through AttackGraph topology."""
        scenario = WEB_CHAIN
        responses = _build_multistage_ctf_responses(scenario)
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="ctf",
            target_uri="https://ctf.example.com/chall/web-chain",
            topology="attack_graph",
        )

        assert report.status == "completed"
        assert report.topology == "attack_graph"
        assert report.events_count > 0


# ═══════════════════════════════════════════════════════════════════
#  Cross-scenario Verification Tests
# ═══════════════════════════════════════════════════════════════════


class TestAllAdvancedCVEScenarios:
    """Meta-test: verify all 5 advanced CVE scenarios run end-to-end."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("scenario,target", [
        (PROXYSHELL, "exchange.corp.local"),
        (DIRTY_PIPE, "10.0.0.50"),
        (MOVEIT_CHAIN, "moveit.corp.com"),
        (CITRIX_BLEED, "vpn.corp.com"),
        (CONFLUENCE_RCE, "confluence.internal"),
    ])
    async def test_scenario_completes_with_deep_assertions(self, store, scenario, target):
        responses = _build_multistage_cve_responses(scenario, target)
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="oneday",
            target_uri=target,
            topology="ooda",
        )

        assert report.status == "completed"
        assert mock.iteration_count == len(scenario.stages), (
            f"{scenario.name}: expected {len(scenario.stages)} iterations, "
            f"got {mock.iteration_count}"
        )

        summary = report.blackboard_summary

        # Every scenario must achieve its final access level
        assert summary["access_level"] == scenario.final_access, (
            f"{scenario.name}: expected {scenario.final_access}, got {summary['access_level']}"
        )

        # CVE matches: unique CVE IDs (stages with same CVE are deduplicated)
        unique_cves = len({s.cve_id for s in scenario.stages})
        assert summary["cve_matches"] >= unique_cves, (
            f"{scenario.name}: expected ≥{unique_cves} unique CVEs, "
            f"got {summary['cve_matches']}"
        )

        # Every stage generates exploit attempts
        assert summary["exploit_attempts"] >= len(scenario.stages)

        # Event store integrity
        stored_count = await store.count()
        assert stored_count == report.events_count


class TestAllAdvancedCTFScenarios:
    """Meta-test: verify all 5 advanced CTF scenarios run end-to-end."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("scenario,slug", [
        (HEAP_TCACHE, "heap"),
        (BLIND_XXE, "xxe"),
        (ECC_INVALID_CURVE, "ecc"),
        (KERNEL_ROP, "kernel"),
        (WEB_CHAIN, "web-chain"),
    ])
    async def test_scenario_completes_with_deep_assertions(self, store, scenario, slug):
        responses = _build_multistage_ctf_responses(scenario)
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        report = await service.execute(
            mission_type="ctf",
            target_uri=f"https://ctf.example.com/chall/{slug}",
            topology="ooda",
        )

        assert report.status == "completed"
        assert mock.iteration_count == len(scenario.steps), (
            f"{scenario.name}: expected {len(scenario.steps)} iterations, "
            f"got {mock.iteration_count}"
        )

        # Challenge must be identified and solved
        all_events = await store.load_all()
        identified = [e for e in all_events if isinstance(e, ChallengeIdentified)]
        assert len(identified) >= 1, f"{scenario.name}: challenge not identified"
        assert identified[0].challenge_name == scenario.name
        assert identified[0].points == scenario.points
        assert identified[0].category == scenario.category

        solved = [e for e in all_events if isinstance(e, ChallengeSolved)]
        assert len(solved) >= 1, f"{scenario.name}: challenge not solved"
        assert solved[0].flag == scenario.flag, (
            f"{scenario.name}: flag mismatch: {solved[0].flag} != {scenario.flag}"
        )

        # Multi-iteration reflection decisions
        reflections = [e for e in all_events if isinstance(e, ReflectionCompleted)]
        assert len(reflections) >= len(scenario.steps)
        decisions = [r.decision for r in reflections]
        assert decisions[-1] == "complete"
        assert all(d in ("continue", "complete", "pivot", "retry") for d in decisions)

        # Event count integrity
        stored = await store.count()
        assert stored == report.events_count


# ═══════════════════════════════════════════════════════════════════
#  Event Sourcing Stress Test
# ═══════════════════════════════════════════════════════════════════


class TestEventSourcingIntegrity:
    """Verify event sourcing guarantees across multi-stage pipelines."""

    @pytest.mark.asyncio
    async def test_all_events_have_mission_context(self, store):
        """Every event in a mission should carry the correct mission context."""
        scenario = PROXYSHELL
        responses = _build_multistage_cve_responses(scenario, "exchange.corp.local")
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        await service.execute(
            mission_type="oneday",
            target_uri="exchange.corp.local",
            topology="ooda",
        )

        all_events = await store.load_all()
        for event in all_events:
            assert event.mission in ("oneday", ""), (
                f"Event {type(event).__name__} has wrong mission: {event.mission}"
            )

    @pytest.mark.asyncio
    async def test_event_ordering_preserved(self, store):
        """Events must be returned in insertion order."""
        scenario = DIRTY_PIPE
        responses = _build_multistage_cve_responses(scenario, "10.0.0.50")
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        await service.execute(
            mission_type="oneday",
            target_uri="10.0.0.50",
            topology="ooda",
        )

        all_events = await store.load_all()
        # First event should be MissionStarted
        assert isinstance(all_events[0], MissionStarted)
        # Last event should be MissionCompleted
        assert isinstance(all_events[-1], MissionCompleted)

        # Timestamps should be non-decreasing
        for i in range(1, len(all_events)):
            assert all_events[i].timestamp >= all_events[i-1].timestamp

    @pytest.mark.asyncio
    async def test_blackboard_deterministic_replay(self, store):
        """Replaying the same events twice produces identical blackboard state."""
        scenario = CITRIX_BLEED
        responses = _build_multistage_cve_responses(scenario, "vpn.corp.com")
        mock = MultiStageCoordinator(responses)
        service = MissionService(event_store=store, coordinator=mock)

        await service.execute(
            mission_type="oneday",
            target_uri="vpn.corp.com",
            topology="ooda",
        )

        all_events = await store.load_all()

        bb1 = Blackboard()
        bb1.apply_all(all_events)

        bb2 = Blackboard()
        bb2.apply_all(all_events)

        assert bb1.summary() == bb2.summary()
        assert bb1.current_access_level == bb2.current_access_level
        assert len(bb1.assets) == len(bb2.assets)
        assert len(bb1.findings) == len(bb2.findings)
        assert len(bb1.cve_matches) == len(bb2.cve_matches)
        assert len(bb1.credentials) == len(bb2.credentials)
