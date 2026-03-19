"""E2E tests — simulate complete mission flows using real CVE/CTF fixtures.

These tests verify the full pipeline: Mission → Topology → Blackboard → Report,
without actually calling the Claude Agent SDK (which requires API keys).
Instead, they test the event sourcing and projection pipeline end-to-end.
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from miya.shared.types import Severity
from miya.shared.events import (
    MissionStarted,
    MissionCompleted,
    AssetDiscovered,
    FingerprintCompleted,
    ScanCompleted,
    VulnerabilityFound,
    CVEMatched,
    ExploitAttempted,
    ExploitSucceeded,
    PrivilegeEscalated,
    LootCollected,
    EntryPointDiscovered,
    TaintPathTraced,
    SinkConfirmed,
    PoCValidated,
    ChallengeIdentified,
    ChallengeSolved,
    PhaseTransition,
)
from miya.shared.blackboard import Blackboard
from miya.infra.event_store import SQLiteEventStore
from miya.mission.service import MissionReport

from tests.fixtures.cve_scenarios import (
    LOG4SHELL,
    SPRING4SHELL,
    BABY_SQLI,
)


@pytest_asyncio.fixture
async def store():
    s = SQLiteEventStore(":memory:")
    await s.initialize()
    yield s
    await s.close()


class TestOnedayE2E:
    """End-to-end test simulating a full 1-day exploitation mission."""

    @pytest.mark.asyncio
    async def test_log4shell_kill_chain(self, store):
        """Simulate a complete Log4Shell exploitation with OODA topology."""
        scenario = LOG4SHELL
        bb = Blackboard()
        mission_id = "mission-log4shell"

        # ── OBSERVE: Recon discovers target ──────────────────────
        events = [
            MissionStarted(
                aggregate_id=mission_id,
                mission_type="oneday",
                target_uri="10.0.0.5",
                topology="ooda",
                mission="oneday",
            ),
            PhaseTransition(to_phase="observe", reason="Starting recon"),
            AssetDiscovered(
                aggregate_id="asset-1",
                host="10.0.0.5",
                ip="10.0.0.5",
                ports=scenario.affected_ports,
                services=("http", "https", "elasticsearch"),
                os="Ubuntu 20.04 LTS",
                context="recon",
                mission="oneday",
            ),
            FingerprintCompleted(
                asset_id="asset-1",
                software=scenario.target_software,
                version=scenario.target_version,
                technology_stack=("Java 11", "Spring Boot 2.6.1", "Elasticsearch 7.16.1"),
                context="recon",
                mission="oneday",
            ),
        ]
        for event in events:
            await store.append([event])
            bb.apply(event)

        assert len(bb.assets) == 1
        asset = list(bb.assets.values())[0]
        assert asset.fingerprint["software"] == "Apache Log4j"

        # ── ORIENT: Scan identifies vulnerabilities ──────────────
        events = [
            PhaseTransition(from_phase="observe", to_phase="orient"),
            ScanCompleted(
                target_host="10.0.0.5",
                target_ports=scenario.affected_ports,
                findings_count=3,
                scanner="nuclei",
                context="scan",
                mission="oneday",
            ),
            VulnerabilityFound(
                vuln_id="vuln-log4shell",
                vuln_type=scenario.vuln_type,
                cwe_id=scenario.cwe_id,
                severity="critical",
                location="10.0.0.5:8080",
                description=scenario.description[:200],
                context="vuln",
                mission="oneday",
            ),
            CVEMatched(
                cve_id=scenario.cve_id,
                cvss=scenario.cvss,
                affected_software=f"{scenario.target_software} {scenario.target_version}",
                exploit_available=True,
                context="vuln",
                mission="oneday",
            ),
        ]
        for event in events:
            await store.append([event])
            bb.apply(event)

        # ScanCompleted creates INFO finding, VulnerabilityFound creates CRITICAL
        assert len(bb.findings) == 2
        critical = [f for f in bb.findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1
        assert len(bb.cve_matches) == 1
        assert bb.cve_matches[0].exploit_available is True

        # ── DECIDE + ACT: Exploit ────────────────────────────────
        events = [
            PhaseTransition(from_phase="orient", to_phase="decide"),
            PhaseTransition(from_phase="decide", to_phase="act"),
            ExploitAttempted(
                cve_id=scenario.cve_id,
                technique=scenario.exploit_technique,
                payload_summary=scenario.attack_vector,
                context="exploit",
                mission="oneday",
            ),
            ExploitSucceeded(
                cve_id=scenario.cve_id,
                access_gained=scenario.expected_access,
                evidence="uid=1000(tomcat) gid=1000(tomcat) groups=1000(tomcat)",
                context="exploit",
                mission="oneday",
            ),
        ]
        for event in events:
            await store.append([event])
            bb.apply(event)

        assert bb.current_access_level == "user"
        assert len(bb.exploit_attempts) == 1

        # ── Post-exploitation: Privilege escalation ──────────────
        events = [
            PrivilegeEscalated(
                from_level="user",
                to_level="root",
                technique="CVE-2021-4034 (PwnKit)",
                context="post",
                mission="oneday",
            ),
            LootCollected(
                loot_type="credential",
                description="root:$6$...(shadow hash)",
                context="post",
                mission="oneday",
            ),
            MissionCompleted(
                aggregate_id=mission_id,
                findings_count=len(bb.findings),
                mission="oneday",
            ),
        ]
        for event in events:
            await store.append([event])
            bb.apply(event)

        assert bb.current_access_level == "root"
        assert len(bb.credentials) == 1

        # ── Verify full event store ──────────────────────────────
        all_events = await store.load_all()
        assert len(all_events) >= 12

        # Build report
        report = MissionReport(
            mission_id=mission_id,
            mission_type="oneday",
            target="10.0.0.5",
            topology="ooda",
            findings=list(bb.findings),
            events_count=len(all_events),
            duration_seconds=42.5,
            blackboard_summary=bb.summary(),
            status="completed",
        )
        assert report.critical_count >= 1
        text = report.as_text()
        assert "ONEDAY" in text
        assert "CRITICAL" in text

    @pytest.mark.asyncio
    async def test_spring4shell_with_attack_graph(self, store):
        """Simulate Spring4Shell exploitation using attack graph topology."""
        scenario = SPRING4SHELL
        bb = Blackboard()

        events = [
            MissionStarted(
                aggregate_id="m-spring4shell",
                mission_type="oneday",
                target_uri="10.0.0.10",
                topology="attack_graph",
                mission="oneday",
            ),
            AssetDiscovered(
                host="10.0.0.10",
                ip="10.0.0.10",
                ports=scenario.affected_ports,
                services=("http", "https"),
                context="recon",
                mission="oneday",
            ),
            VulnerabilityFound(
                vuln_type=scenario.vuln_type,
                cwe_id=scenario.cwe_id,
                severity="critical",
                location="10.0.0.10:8080",
                description=scenario.description[:200],
                context="vuln",
                mission="oneday",
            ),
            CVEMatched(
                cve_id=scenario.cve_id,
                cvss=scenario.cvss,
                affected_software=f"{scenario.target_software} {scenario.target_version}",
                exploit_available=True,
            ),
            ExploitSucceeded(
                cve_id=scenario.cve_id,
                access_gained=scenario.expected_access,
                evidence="uid=1000(tomcat)",
                context="exploit",
                mission="oneday",
            ),
            MissionCompleted(aggregate_id="m-spring4shell"),
        ]

        for event in events:
            await store.append([event])
            bb.apply(event)

        assert bb.current_access_level == "user"
        assert len(bb.cve_matches) == 1
        assert bb.cve_matches[0].cve_id == "CVE-2022-22965"

        # Verify attack graph was built from events
        assert bb.attack_graph.node_count >= 2  # asset + vuln nodes


class TestZerodayE2E:
    """End-to-end test simulating a 0-day discovery mission."""

    @pytest.mark.asyncio
    async def test_zeroday_api_chain_discovery(self, store):
        """Simulate discovering a 0-day through API call chain analysis."""
        bb = Blackboard()
        mission_id = "mission-zeroday-1"

        events = [
            MissionStarted(
                aggregate_id=mission_id,
                mission_type="zeroday",
                target_uri="./vulnerable-app",
                topology="ooda",
                mission="zeroday",
            ),

            # EntryPoint discovery
            EntryPointDiscovered(
                endpoint="/api/v1/users/{id}/avatar",
                input_vectors=("path_param:id", "file_upload:avatar"),
                framework="Flask",
                context="entrypoint",
                mission="zeroday",
            ),
            EntryPointDiscovered(
                endpoint="/api/v1/admin/export",
                input_vectors=("query_param:format", "query_param:template"),
                framework="Flask",
                context="entrypoint",
                mission="zeroday",
            ),

            # DataFlow tracing
            TaintPathTraced(
                source="request.args.get('template')",
                sink="jinja2.Environment().from_string()",
                path=("export_handler", "render_template", "jinja2_render"),
                sanitized=False,
                context="dataflow",
                mission="zeroday",
            ),
            TaintPathTraced(
                source="request.files['avatar']",
                sink="os.path.join(upload_dir, filename)",
                path=("upload_handler", "save_file"),
                sanitized=True,  # This one is sanitized
                context="dataflow",
                mission="zeroday",
            ),

            # Sink confirmation
            SinkConfirmed(
                sink_type="SSTI",
                cwe_id="CWE-1336",
                exploitability="high",
                context="sink",
                mission="zeroday",
            ),

            # PoC validation
            PoCValidated(
                vuln_type="Server-Side Template Injection (SSTI)",
                poc_code="curl '/api/v1/admin/export?template={{config.items()}}'",
                result="SECRET_KEY=... revealed in response",
                context="poc",
                mission="zeroday",
            ),

            MissionCompleted(
                aggregate_id=mission_id,
                mission="zeroday",
            ),
        ]

        for event in events:
            await store.append([event])
            bb.apply(event)

        assert len(bb.entry_points) == 2
        assert len(bb.taint_paths) == 2

        # Only 1 unsanitized path
        unsanitized = [t for t in bb.taint_paths if not t.sanitized]
        assert len(unsanitized) == 1
        assert "jinja2" in unsanitized[0].sink

        assert len(bb.confirmed_sinks) == 1
        assert bb.confirmed_sinks[0].cwe_id == "CWE-1336"

        assert len(bb.validated_pocs) == 1

        # Verify context prompt contains all info
        prompt = bb.to_context_prompt()
        assert "/api/v1/admin/export" in prompt
        assert "Unsanitized" in prompt

        # Verify event store
        all_events = await store.load_all()
        assert len(all_events) == 8

        zeroday_events = await store.load_by_context("entrypoint", mission="zeroday")
        assert len(zeroday_events) == 2


class TestCTFE2E:
    """End-to-end test simulating CTF challenge solving."""

    @pytest.mark.asyncio
    async def test_web_ctf_sqli(self, store):
        """Simulate solving a SQL injection CTF challenge."""
        scenario = BABY_SQLI
        bb = Blackboard()

        events = [
            MissionStarted(
                aggregate_id="mission-ctf-1",
                mission_type="ctf",
                target_uri="https://ctf.example.com/chall/sqli",
                topology="ooda",
                mission="ctf",
            ),
            ChallengeIdentified(
                challenge_name=scenario.name,
                category=scenario.category,
                points=scenario.points,
                context="ctf",
                mission="ctf",
            ),
            ChallengeSolved(
                challenge_name=scenario.name,
                flag=scenario.flag,
                approach=scenario.approach,
                context="ctf",
                mission="ctf",
            ),
            MissionCompleted(aggregate_id="mission-ctf-1", mission="ctf"),
        ]

        for event in events:
            await store.append([event])
            bb.apply(event)

        assert len(bb.challenges) == 1
        assert len(bb.solved_flags) == 1
        assert bb.solved_flags[0].flag == scenario.flag

        # Verify context prompt shows solved status
        prompt = bb.to_context_prompt()
        assert "DONE" in prompt
        assert scenario.name in prompt

    @pytest.mark.asyncio
    async def test_multi_category_ctf(self, store):
        """Simulate solving multiple CTF challenges across categories."""
        bb = Blackboard()

        from tests.fixtures.cve_scenarios import ALL_CTF_SCENARIOS
        events = [
            MissionStarted(
                aggregate_id="ctf-multi",
                mission_type="ctf",
                target_uri="https://ctf.example.com",
                topology="ooda",
                mission="ctf",
            ),
        ]

        for scenario in ALL_CTF_SCENARIOS[:3]:  # First 3 challenges
            events.extend([
                ChallengeIdentified(
                    challenge_name=scenario.name,
                    category=scenario.category,
                    points=scenario.points,
                    context="ctf",
                    mission="ctf",
                ),
                ChallengeSolved(
                    challenge_name=scenario.name,
                    flag=scenario.flag,
                    approach=scenario.approach,
                    context="ctf",
                    mission="ctf",
                ),
            ])

        for event in events:
            await store.append([event])
            bb.apply(event)

        assert len(bb.challenges) == 3
        assert len(bb.solved_flags) == 3

        total_points = sum(c.points for c in bb.challenges)
        assert total_points == 450  # 100 + 200 + 150


class TestBlackboardContextPrompt:
    """Test that the blackboard produces useful context for LLM prompts."""

    @pytest.mark.asyncio
    async def test_full_context_prompt(self, store):
        """Build a rich blackboard and verify the context prompt is comprehensive."""
        bb = Blackboard()

        events = [
            AssetDiscovered(
                host="target.com", ip="10.0.0.5",
                ports=(22, 80, 443, 3306, 8080),
                services=("ssh", "http", "https", "mysql", "http-alt"),
                os="Ubuntu 22.04",
                context="recon", mission="oneday",
            ),
            CVEMatched(
                cve_id="CVE-2021-44228", cvss=10.0,
                affected_software="Apache Log4j 2.14.1",
                exploit_available=True,
            ),
            CVEMatched(
                cve_id="CVE-2022-22965", cvss=9.8,
                affected_software="Spring Framework 5.3.17",
                exploit_available=True,
            ),
            VulnerabilityFound(
                vuln_type="RCE", cwe_id="CWE-917", severity="critical",
                location="10.0.0.5:8080", description="Log4Shell",
            ),
            ExploitAttempted(
                cve_id="CVE-2021-44228", technique="JNDI injection",
            ),
            ExploitSucceeded(
                cve_id="CVE-2021-44228", access_gained="user",
                evidence="uid=1000(tomcat)",
            ),
        ]

        bb.apply_all(events)
        prompt = bb.to_context_prompt()

        # Verify all sections present
        assert "Assets" in prompt
        assert "10.0.0.5" in prompt
        assert "CVEs" in prompt
        assert "CVE-2021-44228" in prompt
        assert "[EXPLOIT]" in prompt
        assert "Findings" in prompt
        assert "CRITICAL" in prompt
        assert "Recent Exploits" in prompt
        assert "Access: user" in prompt
