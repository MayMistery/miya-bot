"""Tests for 1-day exploitation domain model."""

from __future__ import annotations

import pytest

from miya.shared.types import Severity
from miya.oneday.domain import CVE, Exploit, ExploitChain, ExploitTarget, ExploitStatus


class TestCVE:
    def test_creation(self):
        cve = CVE(
            id="CVE-2024-1234",
            description="RCE in nginx",
            severity=Severity.CRITICAL,
            affected="nginx <1.25.0",
            cvss=9.8,
        )
        assert cve.year == 2024
        assert cve.severity == Severity.CRITICAL

    def test_immutable(self):
        cve = CVE(id="CVE-2024-1234", description="test", severity=Severity.LOW, affected="*")
        with pytest.raises(AttributeError):
            cve.id = "CVE-2024-9999"  # type: ignore[misc]


class TestExploitChain:
    def test_chain(self):
        cve1 = CVE(id="CVE-2024-001", description="info leak", severity=Severity.MEDIUM, affected="*")
        cve2 = CVE(id="CVE-2024-002", description="RCE", severity=Severity.CRITICAL, affected="*")

        chain = ExploitChain()
        chain.add_step(Exploit(cve=cve1, source="GitHub", payload="curl ..."))
        chain.add_step(Exploit(cve=cve2, source="ExploitDB", payload="python3 exploit.py"))

        assert chain.cves == ["CVE-2024-001", "CVE-2024-002"]
        assert len(chain.steps) == 2


class TestExploitTarget:
    def test_mark_pwned(self):
        target = ExploitTarget(name="nginx", version="1.18.0", service_type="web_server")
        assert target.status == "recon"

        cve = CVE(id="CVE-2024-001", description="RCE", severity=Severity.CRITICAL, affected="*")
        chain = ExploitChain()
        chain.add_step(Exploit(cve=cve, source="Metasploit", payload="exploit/linux/http/nginx_rce"))

        target.mark_pwned(chain)
        assert target.status == "pwned"
        assert target.chain.status == ExploitStatus.SUCCEEDED
