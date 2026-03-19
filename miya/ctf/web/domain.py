"""Web CTF Domain — web security challenge models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from uuid import uuid4

from miya.ctf.shared.domain import (
    ChallengeCategory,
    ChallengeStatus,
    Difficulty,
    Flag,
    SolveStrategy,
    WriteUp,
    _now,
    _uuid,
)


# ═══════════════════════════════════════════════════════════════════
#  Enums
# ═══════════════════════════════════════════════════════════════════


class WebVulnType(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    SSTI = "ssti"
    SSRF = "ssrf"
    LFI = "lfi"
    RCE = "rce"
    DESERIALIZATION = "deserialization"


# ═══════════════════════════════════════════════════════════════════
#  Value Objects
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class InjectionPoint:
    """An injectable parameter on an endpoint."""

    parameter: str
    injection_type: WebVulnType
    location: str = "query"  # query, body, header, cookie, path
    confirmed: bool = False
    payload: str = ""


# ═══════════════════════════════════════════════════════════════════
#  Entities
# ═══════════════════════════════════════════════════════════════════


@dataclass
class HttpEndpoint:
    """An attackable HTTP endpoint."""

    id: str = field(default_factory=_uuid)
    url: str = ""
    method: str = "GET"
    parameters: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    response_code: int = 0
    technology: str = ""  # e.g. "Flask", "PHP", "Node.js"
    injection_points: list[InjectionPoint] = field(default_factory=list)

    def add_injection_point(self, point: InjectionPoint) -> None:
        if not any(
            p.parameter == point.parameter and p.injection_type == point.injection_type
            for p in self.injection_points
        ):
            self.injection_points.append(point)

    @property
    def is_vulnerable(self) -> bool:
        return any(p.confirmed for p in self.injection_points)


# ═══════════════════════════════════════════════════════════════════
#  Aggregate Root
# ═══════════════════════════════════════════════════════════════════


@dataclass
class WebChallenge:
    """Aggregate Root — a web security CTF challenge."""

    id: str = field(default_factory=_uuid)
    name: str = ""
    points: int = 0
    description: str = ""
    target_url: str = ""
    difficulty: Difficulty = Difficulty.MEDIUM
    status: ChallengeStatus = ChallengeStatus.IDENTIFIED
    endpoints: list[HttpEndpoint] = field(default_factory=list)
    vuln_types: list[WebVulnType] = field(default_factory=list)
    strategies: list[SolveStrategy] = field(default_factory=list)
    flag: Flag | None = None
    writeup: WriteUp | None = None

    def add_endpoint(self, endpoint: HttpEndpoint) -> None:
        if not any(e.id == endpoint.id for e in self.endpoints):
            self.endpoints.append(endpoint)

    def identify_vuln(self, vuln_type: WebVulnType) -> None:
        if vuln_type not in self.vuln_types:
            self.vuln_types.append(vuln_type)

    def get_vulnerable_endpoints(self) -> list[HttpEndpoint]:
        return [e for e in self.endpoints if e.is_vulnerable]

    def all_injection_points(self) -> list[InjectionPoint]:
        return [
            ip for endpoint in self.endpoints for ip in endpoint.injection_points
        ]

    def solve(self, flag: Flag, writeup: WriteUp | None = None) -> None:
        self.flag = flag
        self.status = ChallengeStatus.SOLVED
        if writeup:
            self.writeup = writeup

    @property
    def is_solved(self) -> bool:
        return self.status == ChallengeStatus.SOLVED and self.flag is not None
