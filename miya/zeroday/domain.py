"""0-day discovery domain model — audit targets, vulnerabilities, and taint flows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from miya.shared.types import Severity


@dataclass(frozen=True)
class TaintFlow:
    """A data flow from untrusted source to dangerous sink."""

    source: str  # e.g., "request.GET['id']"
    sink: str  # e.g., "cursor.execute(query)"
    path: tuple[str, ...] = ()  # intermediate steps
    file: str = ""
    line: int = 0

    @property
    def summary(self) -> str:
        return f"{self.source} → {'→'.join(self.path)} → {self.sink}" if self.path else f"{self.source} → {self.sink}"


@dataclass(frozen=True)
class Vulnerability:
    """A discovered 0-day vulnerability."""

    vuln_type: str  # CWE name: "SQL Injection", "Buffer Overflow", etc.
    cwe_id: str  # CWE-89, CWE-120, etc.
    severity: Severity
    location: str  # file:line or function name
    description: str
    poc: str  # proof of concept — input, payload, or test case
    taint_flow: TaintFlow | None = None

    @property
    def title(self) -> str:
        return f"{self.cwe_id} {self.vuln_type} in {self.location}"


VulnClass = Literal[
    "injection",  # SQLi, CMDi, XSS, SSTI, LDAP, XPath
    "memory",  # BOF, heap overflow, UAF, double-free, format string
    "logic",  # auth bypass, IDOR, race condition, TOCTOU
    "crypto",  # weak algo, bad RNG, key leakage, padding oracle
    "config",  # default creds, exposed debug, permissive CORS
]


@dataclass
class AuditTarget:
    """Aggregate root — source code or binary under vulnerability research."""

    path: str  # directory, file, or repository URL
    language: str = ""  # detected programming language
    framework: str = ""  # detected framework (Django, Spring, etc.)
    findings: list[Vulnerability] = field(default_factory=list)
    status: Literal["pending", "auditing", "complete"] = "pending"

    def add_finding(self, vuln: Vulnerability) -> None:
        self.findings.append(vuln)

    @property
    def critical_findings(self) -> list[Vulnerability]:
        return [v for v in self.findings if v.severity in (Severity.CRITICAL, Severity.HIGH)]

    def complete(self) -> None:
        self.status = "complete"
