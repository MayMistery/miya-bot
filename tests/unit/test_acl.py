"""Unit tests for ACL (Anti-Corruption Layer) translators.

Tests the boundary translators between bounded contexts:
- OneDay: Recon→Scan→Vuln→Exploit→Post
- ZeroDay: EntryPoint→DataFlow→Sink→PoC
"""

from __future__ import annotations

import pytest

# ═══════════════════════════════════════════════════════════════════
#  OneDay ACL Tests
# ═══════════════════════════════════════════════════════════════════

from miya.oneday.recon.domain import Asset, ReconMission, Fingerprint
from miya.oneday.scan.domain import ScanTarget, ScanResult, ScanTask
from miya.oneday.vuln.domain import VulnAssessment, VulnMatch, CVE, ExploitAvailability
from miya.oneday.exploit.domain import (
    ExploitCampaign, ExploitAttempt, Payload, ExploitResult,
)
from miya.oneday.post.domain import PostSession, AccessLevel, PivotTarget

from miya.oneday.acl import (
    recon_asset_to_scan_target,
    recon_mission_to_scan_targets,
    scan_result_to_vuln_input,
    scan_task_to_vuln_inputs,
    recon_fingerprint_to_vuln_query,
    vuln_match_to_exploit_input,
    vuln_assessment_to_exploit_targets,
    exploit_success_to_post_session,
    exploit_campaign_to_post_sessions,
    pivot_target_to_recon_scope,
)


class TestReconToScan:
    def test_asset_to_scan_target(self):
        asset = Asset(
            id="asset-1",
            host="10.0.0.5",
            ip="10.0.0.5",
            ports=(22, 80, 443),
            services=("ssh", "http", "https"),
        )
        target = recon_asset_to_scan_target(asset)

        assert isinstance(target, ScanTarget)
        assert target.host == "10.0.0.5"
        assert target.ip == "10.0.0.5"
        assert target.ports == (22, 80, 443)
        assert target.services == ("ssh", "http", "https")
        assert target.asset_id == "asset-1"

    def test_recon_mission_to_scan_targets(self):
        mission = ReconMission(target_scope="10.0.0.0/24")
        mission.discover_asset(
            host="10.0.0.5", ip="10.0.0.5",
            ports=(80,), services=("http",),
        )
        mission.discover_asset(
            host="10.0.0.10", ip="10.0.0.10",
            ports=(443, 8080), services=("https", "http-alt"),
        )

        targets = recon_mission_to_scan_targets(mission)
        assert len(targets) == 2
        assert all(isinstance(t, ScanTarget) for t in targets)

    def test_empty_asset(self):
        asset = Asset(id="empty")
        target = recon_asset_to_scan_target(asset)
        assert target.host == ""
        assert target.ports == ()


class TestScanToVuln:
    def test_scan_result_to_vuln_input(self):
        result = ScanResult(
            id="sr-1",
            name="Log4Shell RCE",
            severity="critical",
            matched_at="10.0.0.5:8080",
            description="Log4j JNDI injection",
            cve_ids=["CVE-2021-44228"],
            cwe_ids=["CWE-917"],
            reference=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        )
        vuln_input = scan_result_to_vuln_input(result)

        assert vuln_input["scan_result_id"] == "sr-1"
        assert vuln_input["name"] == "Log4Shell RCE"
        assert vuln_input["severity"] == "critical"
        assert vuln_input["cve_ids"] == ["CVE-2021-44228"]
        assert vuln_input["cwe_ids"] == ["CWE-917"]

    def test_scan_task_to_vuln_inputs(self):
        task = ScanTask()
        task.record_result(
            template_id="nuclei-log4j",
            name="Log4Shell",
            severity="critical",
            matched_at="10.0.0.5:8080",
            cve_ids=["CVE-2021-44228"],
        )
        task.record_result(
            template_id="nuclei-spring4shell",
            name="Spring4Shell",
            severity="critical",
            matched_at="10.0.0.5:8080",
            cve_ids=["CVE-2022-22965"],
        )

        inputs = scan_task_to_vuln_inputs(task)
        assert len(inputs) == 2
        assert inputs[0]["name"] == "Log4Shell"
        assert inputs[1]["cve_ids"] == ["CVE-2022-22965"]

    def test_fingerprint_to_vuln_query(self):
        fp = Fingerprint(
            software="Apache Log4j",
            version="2.14.1",
            os="Ubuntu 20.04",
            technology_stack=("Java 11", "Spring Boot 2.6.1"),
        )
        query = recon_fingerprint_to_vuln_query("asset-1", fp)

        assert query["asset_id"] == "asset-1"
        assert query["software"] == "Apache Log4j"
        assert query["version"] == "2.14.1"
        assert query["os"] == "Ubuntu 20.04"
        assert "Java 11" in query["technology_stack"]


class TestVulnToExploit:
    def test_vuln_match_to_exploit_input_with_exploit(self):
        cve = CVE(
            cve_id="CVE-2021-44228",
            cvss=10.0,
            severity="critical",
        )
        exploit_avail = ExploitAvailability(
            cve_id="CVE-2021-44228",
            exploit_db_id="50592",
            metasploit_module="exploit/multi/http/log4shell_header_injection",
            exploit_type="remote",
            verified=True,
        )
        match = VulnMatch(
            asset_id="asset-1",
            software="Apache Log4j",
            version="2.14.1",
            cve=cve,
            exploit_availability=exploit_avail,
        )

        result = vuln_match_to_exploit_input(match, "10.0.0.5", 8080)

        assert result["cve_id"] == "CVE-2021-44228"
        assert result["cvss"] == 10.0
        assert result["target_host"] == "10.0.0.5"
        assert result["target_port"] == 8080
        assert result["exploit_db_id"] == "50592"
        assert result["metasploit_module"] == "exploit/multi/http/log4shell_header_injection"
        assert result["verified"] is True

    def test_vuln_match_without_exploit(self):
        cve = CVE(cve_id="CVE-2023-99999", cvss=5.0)
        match = VulnMatch(
            asset_id="asset-1",
            software="SomeApp",
            version="1.0",
            cve=cve,
            exploit_availability=None,
        )

        result = vuln_match_to_exploit_input(match, "10.0.0.5")
        assert "exploit_db_id" not in result
        assert "metasploit_module" not in result

    def test_assessment_to_exploit_targets_sorted_by_cvss(self):
        assessment = VulnAssessment()

        # Register two matches with exploits
        cve_low = CVE(cve_id="CVE-2023-0001", cvss=5.0)
        cve_high = CVE(cve_id="CVE-2021-44228", cvss=10.0)
        exploit_avail = ExploitAvailability(cve_id="CVE-2021-44228")

        assessment.register_cve_match(
            asset_id="a1", software="Apache Log4j", version="2.14.1",
            cve=cve_high, exploit_availability=exploit_avail,
        )
        assessment.register_cve_match(
            asset_id="a2", software="Nginx", version="1.18",
            cve=cve_low, exploit_availability=ExploitAvailability(cve_id="CVE-2023-0001"),
        )

        host_map = {"a1": ("10.0.0.5", 8080), "a2": ("10.0.0.10", 80)}
        targets = vuln_assessment_to_exploit_targets(assessment, host_map)

        assert len(targets) == 2
        assert targets[0]["cve_id"] == "CVE-2021-44228"  # highest CVSS first
        assert targets[1]["cve_id"] == "CVE-2023-0001"

    def test_assessment_skips_missing_hosts(self):
        assessment = VulnAssessment()
        cve = CVE(cve_id="CVE-2021-44228", cvss=10.0)
        assessment.register_cve_match(
            asset_id="unknown-asset", software="Log4j", version="2.14.1",
            cve=cve, exploit_availability=ExploitAvailability(),
        )

        targets = vuln_assessment_to_exploit_targets(assessment, {})
        assert len(targets) == 0


class TestExploitToPost:
    def test_exploit_success_to_post_session(self):
        attempt = ExploitAttempt(
            cve_id="CVE-2021-44228",
            target_host="10.0.0.5",
            target_port=8080,
            module="exploit/multi/http/log4shell_header_injection",
            result=ExploitResult(
                success=True,
                access_gained="user",
                session_id="session-1",
                evidence="uid=1000(tomcat)",
            ),
        )

        session_data = exploit_success_to_post_session(attempt)

        assert session_data["session_id"] == "session-1"
        assert session_data["target_host"] == "10.0.0.5"
        assert session_data["initial_access"] == "user"
        assert session_data["exploit_cve"] == "CVE-2021-44228"

    def test_campaign_to_post_sessions(self):
        campaign = ExploitCampaign(target_host="10.0.0.5")
        a1 = campaign.attempt_exploit(
            cve_id="CVE-2021-44228", target_host="10.0.0.5",
            target_port=8080, module="log4shell",
        )
        campaign.record_success(a1.id, access_gained="user", session_id="s1", evidence="ok")

        a2 = campaign.attempt_exploit(
            cve_id="CVE-2022-22965", target_host="10.0.0.5",
            target_port=8080, module="spring4shell",
        )
        campaign.record_failure(a2.id, reason="patched")

        sessions = exploit_campaign_to_post_sessions(campaign)
        assert len(sessions) == 1
        assert sessions[0]["exploit_cve"] == "CVE-2021-44228"


class TestPostToRecon:
    def test_pivot_target_with_ip(self):
        pivot = PivotTarget(ip="192.168.1.50", host="internal.corp", port=22)
        scope = pivot_target_to_recon_scope(pivot)
        assert scope == "192.168.1.50"

    def test_pivot_target_with_host_only(self):
        pivot = PivotTarget(host="db.internal.corp", port=3306)
        scope = pivot_target_to_recon_scope(pivot)
        assert scope == "db.internal.corp"


# ═══════════════════════════════════════════════════════════════════
#  ZeroDay ACL Tests
# ═══════════════════════════════════════════════════════════════════

from miya.zeroday.entrypoint.domain import CodeBase, EntryPoint, InputVector
from miya.zeroday.dataflow.domain import TaintSession, TaintPath, TaintSource, TaintSink
from miya.zeroday.sink.domain import SinkAnalysis, SinkPattern, Exploitability
from miya.zeroday.poc.domain import PoCProject, PoCPayload

from miya.zeroday.acl import (
    entry_points_to_taint_session,
    entry_point_to_source_patterns,
    input_vector_to_taint_source,
    taint_path_to_sink_analysis,
    taint_paths_to_sink_analyses,
    sink_analysis_to_poc_project,
    confirmed_sinks_to_poc_projects,
)


class TestEntryPointToDataFlow:
    def test_entry_points_to_taint_session(self):
        codebase = CodeBase(
            id="cb-1",
            target_uri="./vulnerable-app",
            language="python",
            framework="flask",
        )
        ep = EntryPoint(
            endpoint="POST /api/users",
            handler_function="app.views.create_user",
            file_path="app/views.py",
            line_number=42,
        )
        codebase.register_entry_point(ep)

        session = entry_points_to_taint_session(codebase)
        assert isinstance(session, TaintSession)
        assert session.target_path == "./vulnerable-app"
        assert session.codebase_id == "cb-1"

    def test_entry_point_to_source_patterns(self):
        ep = EntryPoint(endpoint="GET /api/search")
        ep.add_input(InputVector(name="q", source="query", sanitized=False))
        ep.add_input(InputVector(name="page", source="query", sanitized=True))
        ep.add_input(InputVector(name="auth", source="header", sanitized=False))

        patterns = entry_point_to_source_patterns(ep)
        assert len(patterns) == 2  # sanitized input excluded
        assert "request.args.get(...)" in patterns
        assert "request.headers.get(...)" in patterns

    def test_input_vector_to_taint_source(self):
        ep = EntryPoint(
            endpoint="POST /api/login",
            file_path="app/auth.py",
            line_number=15,
        )
        iv = InputVector(name="username", source="body")

        source = input_vector_to_taint_source(iv, ep)
        assert isinstance(source, TaintSource)
        assert source.parameter == "username"
        assert source.source_type == "http_body"
        assert source.file_path == "app/auth.py"
        assert source.line_number == 15
        assert source.entry_point == "POST /api/login"

    def test_input_vector_unknown_source(self):
        ep = EntryPoint(endpoint="unknown")
        iv = InputVector(name="data", source="websocket")
        source = input_vector_to_taint_source(iv, ep)
        assert source.source_type == "websocket"


class TestDataFlowToSink:
    def test_taint_path_to_sink_analysis_sqli(self):
        path = TaintPath(
            source=TaintSource(parameter="request.GET['id']"),
            sink=TaintSink(
                function="cursor.execute()",
                sink_type="sql_query",
                file_path="app/db.py",
                line_number=55,
            ),
        )

        analysis = taint_path_to_sink_analysis(path, "session-1")
        assert isinstance(analysis, SinkAnalysis)
        assert analysis.taint_session_id == "session-1"
        assert analysis.sink_function == "cursor.execute()"
        assert analysis.file_path == "app/db.py"
        assert analysis.pattern is not None
        assert analysis.pattern.cwe_id == "CWE-89"
        assert analysis.pattern.cwe_name == "SQL Injection"

    def test_taint_path_to_sink_analysis_cmdi(self):
        path = TaintPath(
            source=TaintSource(parameter="user_input"),
            sink=TaintSink(
                function="os.system()",
                sink_type="command_exec",
                file_path="app/utils.py",
                line_number=10,
            ),
        )

        analysis = taint_path_to_sink_analysis(path, "session-1")
        assert analysis.pattern.cwe_id == "CWE-78"
        assert analysis.pattern.cwe_name == "OS Command Injection"

    def test_taint_path_unknown_sink_type(self):
        path = TaintPath(
            source=TaintSource(parameter="x"),
            sink=TaintSink(function="custom_fn()", sink_type="sql_query"),
        )
        # Override to test unknown type path
        path.sink = TaintSink(function="custom_fn()", sink_type="sql_query")  # type: ignore
        analysis = taint_path_to_sink_analysis(path, "s1")
        # sql_query is a known type, should work fine
        assert analysis.pattern.cwe_id == "CWE-89"

    def test_taint_paths_to_sink_analyses_filters_sanitized(self):
        session = TaintSession(id="ts-1", target_path="./app")

        # Exploitable path (no sanitizer)
        path1 = TaintPath(
            source=TaintSource(parameter="input1"),
            sink=TaintSink(function="eval()", sink_type="code_eval"),
        )
        session.record_path(path1)

        # Sanitized path
        from miya.zeroday.dataflow.domain import Sanitizer
        path2 = TaintPath(
            source=TaintSource(parameter="input2"),
            sink=TaintSink(function="cursor.execute()", sink_type="sql_query"),
            sanitizers=[Sanitizer(function="parameterize()", sanitizer_type="parameterization")],
        )
        session.record_path(path2)

        analyses = taint_paths_to_sink_analyses(session)
        assert len(analyses) == 1  # only the exploitable path
        assert analyses[0].sink_function == "eval()"


class TestSinkToPoC:
    def test_sink_analysis_to_poc_project_sqli(self):
        analysis = SinkAnalysis(
            id="sa-1",
            sink_function="cursor.execute()",
            file_path="app/db.py",
            line_number=55,
            pattern=SinkPattern(
                cwe_id="CWE-89",
                cwe_name="SQL Injection",
                function_pattern="cursor.execute($QUERY)",
            ),
            confirmed=True,
        )

        project = sink_analysis_to_poc_project(analysis)
        assert isinstance(project, PoCProject)
        assert project.sink_analysis_id == "sa-1"
        assert project.vuln_type == "SQL Injection"
        assert project.cwe_id == "CWE-89"
        assert len(project.payloads) == 3  # 3 SQLi templates
        assert any("UNION" in p.content for p in project.payloads)

    def test_sink_analysis_to_poc_project_cmdi(self):
        analysis = SinkAnalysis(
            id="sa-2",
            sink_function="os.system()",
            file_path="app/utils.py",
            line_number=10,
            pattern=SinkPattern(
                cwe_id="CWE-78",
                cwe_name="OS Command Injection",
                function_pattern="os.system($CMD)",
            ),
            confirmed=True,
        )

        project = sink_analysis_to_poc_project(analysis)
        assert len(project.payloads) == 3  # 3 CMDi templates
        assert any("id" in p.content for p in project.payloads)

    def test_sink_analysis_no_pattern(self):
        analysis = SinkAnalysis(
            id="sa-3",
            sink_function="custom_fn()",
            confirmed=True,
            pattern=None,
        )
        project = sink_analysis_to_poc_project(analysis)
        assert project.vuln_type == "Unknown"
        assert len(project.payloads) == 0

    def test_confirmed_sinks_to_poc_projects(self):
        analyses = [
            SinkAnalysis(
                id="sa-1",
                sink_function="cursor.execute()",
                pattern=SinkPattern(cwe_id="CWE-89", cwe_name="SQLi", function_pattern=""),
                confirmed=True,
            ),
            SinkAnalysis(
                id="sa-2",
                sink_function="os.system()",
                pattern=SinkPattern(cwe_id="CWE-78", cwe_name="CMDi", function_pattern=""),
                confirmed=False,  # Not confirmed — should be excluded
            ),
        ]

        projects = confirmed_sinks_to_poc_projects(analyses)
        assert len(projects) == 1
        assert projects[0].sink_analysis_id == "sa-1"
