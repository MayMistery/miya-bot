"""Unit tests for miya.shared.blackboard — event projection and knowledge base."""

from __future__ import annotations

import pytest
from miya.shared.blackboard import Blackboard
from miya.shared.types import Severity
from miya.shared.events import (
    AssetDiscovered,
    FingerprintCompleted,
    VulnerabilityFound,
    CVEMatched,
    ExploitAttempted,
    ExploitSucceeded,
    ExploitFailed,
    EntryPointDiscovered,
    TaintPathTraced,
    SinkConfirmed,
    PoCValidated,
    ChallengeIdentified,
    ChallengeSolved,
    PrivilegeEscalated,
    LootCollected,
    PhaseTransition,
    ReflectionCompleted,
)


@pytest.fixture
def bb():
    return Blackboard()


class TestBlackboardProjection:
    def test_asset_discovered(self, bb):
        event = AssetDiscovered(
            host="example.com",
            ip="10.0.0.1",
            ports=(22, 80, 443),
            services=("ssh", "http", "https"),
            os="Ubuntu 22.04",
        )
        bb.apply(event)

        assert len(bb.assets) == 1
        asset = list(bb.assets.values())[0]
        assert asset.ip == "10.0.0.1"
        assert asset.ports == (22, 80, 443)
        # Should also add to attack graph
        assert bb.attack_graph.node_count == 1

    def test_fingerprint_updates_asset(self, bb):
        ad = AssetDiscovered(
            aggregate_id="asset-1",
            host="example.com",
            ip="10.0.0.1",
            ports=(80,),
        )
        bb.apply(ad)
        asset_id = list(bb.assets.keys())[0]

        fp = FingerprintCompleted(
            asset_id=asset_id,
            software="Apache",
            version="2.4.52",
            technology_stack=("PHP 8.1",),
        )
        bb.apply(fp)

        asset = bb.assets[asset_id]
        assert asset.fingerprint["software"] == "Apache"
        assert asset.fingerprint["version"] == "2.4.52"

    def test_vulnerability_found(self, bb):
        event = VulnerabilityFound(
            vuln_id="vuln-1",
            vuln_type="SQL Injection",
            cwe_id="CWE-89",
            severity="critical",
            location="/api/users?id=1",
            description="SQL injection in user endpoint",
        )
        bb.apply(event)

        assert len(bb.findings) == 1
        assert bb.findings[0].severity == Severity.CRITICAL
        assert "CWE-89" in bb.findings[0].title
        # Should add vuln node to attack graph
        assert bb.attack_graph.node_count == 1

    def test_cve_matched(self, bb):
        event = CVEMatched(
            cve_id="CVE-2021-44228",
            cvss=10.0,
            affected_software="Apache Log4j 2.x",
            exploit_available=True,
        )
        bb.apply(event)

        assert len(bb.cve_matches) == 1
        assert bb.cve_matches[0]["cve_id"] == "CVE-2021-44228"
        assert bb.cve_matches[0]["exploit_available"] is True

    def test_exploit_lifecycle(self, bb):
        bb.apply(ExploitAttempted(cve_id="CVE-2021-44228", technique="log4shell"))
        assert len(bb.exploit_attempts) == 1

        bb.apply(ExploitSucceeded(
            cve_id="CVE-2021-44228",
            access_gained="user",
            evidence="uid=1000(tomcat)",
        ))
        assert bb.current_access_level == "user"
        assert len(bb.findings) == 1
        assert bb.findings[0].severity == Severity.CRITICAL

    def test_exploit_failed(self, bb):
        bb.apply(ExploitFailed(cve_id="CVE-2021-44228", reason="Patched"))
        assert bb.current_access_level == "none"

    def test_zeroday_pipeline(self, bb):
        bb.apply(EntryPointDiscovered(
            endpoint="/api/upload",
            input_vectors=("file", "filename"),
            framework="Flask",
        ))
        assert len(bb.entry_points) == 1

        bb.apply(TaintPathTraced(
            source="request.files",
            sink="os.system()",
            path=("upload_handler", "process_file", "run_command"),
            sanitized=False,
        ))
        assert len(bb.taint_paths) == 1
        assert bb.taint_paths[0]["sanitized"] is False

        bb.apply(SinkConfirmed(
            sink_type="command_injection",
            cwe_id="CWE-78",
            exploitability="high",
        ))
        assert len(bb.confirmed_sinks) == 1

        bb.apply(PoCValidated(
            vuln_type="command_injection",
            poc_code="curl -F 'file=;id' /api/upload",
            result="uid=0(root)",
        ))
        assert len(bb.validated_pocs) == 1

    def test_ctf_pipeline(self, bb):
        bb.apply(ChallengeIdentified(
            challenge_name="Baby SQLi",
            category="web",
            points=100,
        ))
        assert len(bb.challenges) == 1

        bb.apply(ChallengeSolved(
            challenge_name="Baby SQLi",
            flag="flag{sql_1nj3ct10n}",
            approach="Union-based SQL injection",
        ))
        assert len(bb.solved_flags) == 1
        assert bb.solved_flags[0]["flag"] == "flag{sql_1nj3ct10n}"

    def test_post_exploitation(self, bb):
        bb.apply(PrivilegeEscalated(
            from_level="user",
            to_level="root",
            technique="SUID binary",
        ))
        assert bb.current_access_level == "root"

        bb.apply(LootCollected(
            loot_type="credential",
            description="admin:P@ssw0rd",
        ))
        assert len(bb.credentials) == 1

    def test_phase_tracking(self, bb):
        bb.apply(PhaseTransition(from_phase="", to_phase="observe", reason="Start"))
        bb.apply(PhaseTransition(from_phase="observe", to_phase="orient", reason="Got data"))
        assert len(bb.phase_history) == 2

    def test_reflection(self, bb):
        bb.apply(ReflectionCompleted(
            assessment="Good progress",
            decision="continue",
            insights="Found SQL injection",
        ))
        assert len(bb.reflections) == 1
        assert bb.reflections[0]["decision"] == "continue"


class TestBlackboardQueries:
    def test_critical_findings(self, bb):
        bb.apply(VulnerabilityFound(severity="critical", vuln_type="RCE", cwe_id="CWE-78"))
        bb.apply(VulnerabilityFound(severity="low", vuln_type="Info Disclosure", cwe_id="CWE-200"))

        critical = bb.critical_findings()
        assert len(critical) == 1

    def test_summary(self, bb):
        bb.apply(AssetDiscovered(host="test", ip="1.2.3.4", ports=(80,)))
        bb.apply(VulnerabilityFound(severity="high", vuln_type="XSS", cwe_id="CWE-79"))

        summary = bb.summary()
        assert summary["assets"] == 1
        assert summary["findings"] == 1
        assert "AttackGraph" in summary["attack_graph"]

    def test_to_context_prompt(self, bb):
        bb.apply(AssetDiscovered(host="test", ip="1.2.3.4", ports=(80,)))
        bb.apply(CVEMatched(cve_id="CVE-2023-1234", cvss=9.8, exploit_available=True))

        prompt = bb.to_context_prompt()
        assert "1.2.3.4" in prompt
        assert "CVE-2023-1234" in prompt
        assert "EXPLOIT AVAILABLE" in prompt

    def test_apply_all(self, bb):
        events = [
            AssetDiscovered(host="a", ip="1.1.1.1", ports=(22,)),
            AssetDiscovered(host="b", ip="2.2.2.2", ports=(80,)),
        ]
        bb.apply_all(events)
        assert len(bb.assets) == 2
        assert len(bb.events) == 2
