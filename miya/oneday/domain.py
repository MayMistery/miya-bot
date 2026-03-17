"""1-day exploitation domain model — CVEs, exploits, and attack chains."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from miya.shared.types import Severity


class ExploitStatus(str, Enum):
    IDENTIFIED = "identified"
    ADAPTED = "adapted"
    TESTED = "tested"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True)
class CVE:
    """A known vulnerability identifier with metadata."""

    id: str  # CVE-2024-XXXXX
    description: str
    severity: Severity
    affected: str  # software/version range
    cvss: float = 0.0
    references: tuple[str, ...] = ()

    @property
    def year(self) -> int:
        return int(self.id.split("-")[1])


@dataclass(frozen=True)
class Exploit:
    """A concrete exploit for a CVE."""

    cve: CVE
    source: str  # ExploitDB, GitHub, Metasploit, custom
    payload: str  # exploit code or module path
    requirements: tuple[str, ...] = ()  # "network access", "auth required", etc.

    @property
    def summary(self) -> str:
        return f"{self.cve.id} via {self.source}"


@dataclass
class ExploitChain:
    """Ordered multi-step exploitation — e.g., info leak → RCE → privesc."""

    steps: list[Exploit] = field(default_factory=list)
    status: ExploitStatus = ExploitStatus.IDENTIFIED

    def add_step(self, exploit: Exploit) -> None:
        self.steps.append(exploit)

    @property
    def cves(self) -> list[str]:
        return [s.cve.id for s in self.steps]


@dataclass
class ExploitTarget:
    """Aggregate root — a service or software being targeted for 1-day exploitation."""

    name: str
    version: str
    service_type: str  # "web_server", "database", "cms", etc.
    endpoint: str = ""  # URL or host:port
    fingerprint: dict[str, str] = field(default_factory=dict)
    matched_cves: list[CVE] = field(default_factory=list)
    chain: ExploitChain | None = None
    status: Literal["recon", "matching", "exploiting", "pwned", "failed"] = "recon"

    def mark_pwned(self, chain: ExploitChain) -> None:
        self.chain = chain
        self.chain.status = ExploitStatus.SUCCEEDED
        self.status = "pwned"
