"""Tests for 0-day discovery domain model."""

from __future__ import annotations

import pytest

from miya.shared.types import Severity
from miya.zeroday.domain import TaintFlow, Vulnerability, AuditTarget


class TestTaintFlow:
    def test_summary_direct(self):
        flow = TaintFlow(source="request.GET['id']", sink="cursor.execute()")
        assert flow.summary == "request.GET['id'] → cursor.execute()"

    def test_summary_with_path(self):
        flow = TaintFlow(
            source="request.POST['name']",
            sink="os.system(cmd)",
            path=("sanitize()", "build_cmd()"),
        )
        assert "sanitize()" in flow.summary
        assert "build_cmd()" in flow.summary


class TestVulnerability:
    def test_title(self):
        vuln = Vulnerability(
            vuln_type="SQL Injection",
            cwe_id="CWE-89",
            severity=Severity.CRITICAL,
            location="app/views.py:42",
            description="Unsanitized user input in SQL query",
            poc="' OR 1=1 --",
        )
        assert vuln.title == "CWE-89 SQL Injection in app/views.py:42"


class TestAuditTarget:
    def test_add_findings(self):
        target = AuditTarget(path="/tmp/app", language="python")
        assert target.status == "pending"
        assert len(target.findings) == 0

        vuln = Vulnerability(
            vuln_type="XSS",
            cwe_id="CWE-79",
            severity=Severity.HIGH,
            location="templates/index.html:5",
            description="Reflected XSS",
            poc="<script>alert(1)</script>",
        )
        target.add_finding(vuln)
        assert len(target.findings) == 1
        assert len(target.critical_findings) == 1

    def test_complete(self):
        target = AuditTarget(path="/tmp/app", language="go")
        target.complete()
        assert target.status == "complete"

    def test_critical_filter(self):
        target = AuditTarget(path="/tmp/app", language="c")
        target.add_finding(Vulnerability(
            vuln_type="BOF", cwe_id="CWE-120", severity=Severity.CRITICAL,
            location="main.c:10", description="Stack buffer overflow", poc="AAAA...",
        ))
        target.add_finding(Vulnerability(
            vuln_type="Info Leak", cwe_id="CWE-200", severity=Severity.LOW,
            location="debug.c:5", description="Debug info exposed", poc="curl /debug",
        ))
        assert len(target.critical_findings) == 1
        assert len(target.findings) == 2
