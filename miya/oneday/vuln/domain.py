"""Vuln bounded context — domain model.

Aggregate Root: VulnAssessment
Entities: VulnMatch
Value Objects: CVE, ExploitAvailability
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from miya.shared.events import (
    DomainEvent,
    CVEMatched,
    VulnerabilityFound,
)
from miya.shared.types import new_id as _uuid


# ═══════════════════════════════════════════════════════════════════
#  Value Objects
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class CVE:
    """A CVE entry with metadata."""

    cve_id: str = ""
    cvss: float = 0.0
    severity: str = "medium"
    description: str = ""
    affected_software: str = ""
    affected_versions: str = ""
    references: tuple[str, ...] = ()
    published: str = ""


@dataclass(frozen=True)
class ExploitAvailability:
    """Information about publicly available exploits for a CVE."""

    cve_id: str = ""
    exploit_db_id: str = ""
    metasploit_module: str = ""
    github_url: str = ""
    exploit_type: str = ""  # "remote", "local", "webapps", "dos"
    verified: bool = False


# ═══════════════════════════════════════════════════════════════════
#  Entity
# ═══════════════════════════════════════════════════════════════════


@dataclass
class VulnMatch:
    """A match between a discovered asset/service and a known CVE."""

    id: str = field(default_factory=_uuid)
    asset_id: str = ""
    software: str = ""
    version: str = ""
    cve: CVE = field(default_factory=CVE)
    exploit_availability: ExploitAvailability | None = None
    confirmed: bool = False
    matched_by: str = ""  # "version_match", "nuclei_scan", "manual"


# ═══════════════════════════════════════════════════════════════════
#  Aggregate Root
# ═══════════════════════════════════════════════════════════════════


@dataclass
class VulnAssessment:
    """Aggregate root for the vuln bounded context.

    Manages CVE matching and vulnerability assessment for discovered assets.
    Cross-references fingerprints against CVE databases and exploit availability.
    """

    id: str = field(default_factory=_uuid)
    matches: list[VulnMatch] = field(default_factory=list)
    version: int = 0
    pending_events: list[DomainEvent] = field(default_factory=list)

    # ── Commands ──────────────────────────────────────────────────

    def register_cve_match(
        self,
        asset_id: str,
        software: str,
        version: str,
        cve: CVE,
        exploit_availability: ExploitAvailability | None = None,
        matched_by: str = "version_match",
        correlation_id: str = "",
    ) -> VulnMatch:
        """Register a CVE match for an asset."""
        match = VulnMatch(
            asset_id=asset_id,
            software=software,
            version=version,
            cve=cve,
            exploit_availability=exploit_availability,
            matched_by=matched_by,
        )
        self.matches.append(match)
        self.version += 1

        has_exploit = exploit_availability is not None
        event = CVEMatched(
            aggregate_id=self.id,
            aggregate_type="VulnAssessment",
            cve_id=cve.cve_id,
            cvss=cve.cvss,
            affected_software=f"{software} {version}",
            exploit_available=has_exploit,
            correlation_id=correlation_id,
            version=self.version,
            mission="oneday",
        )
        self.pending_events.append(event)
        return match

    def record_vulnerability(
        self,
        vuln_type: str,
        cwe_id: str,
        severity: str,
        location: str,
        description: str = "",
        correlation_id: str = "",
    ) -> None:
        """Record a confirmed vulnerability finding."""
        self.version += 1

        event = VulnerabilityFound(
            aggregate_id=self.id,
            aggregate_type="VulnAssessment",
            vuln_type=vuln_type,
            cwe_id=cwe_id,
            severity=severity,
            location=location,
            description=description,
            correlation_id=correlation_id,
            version=self.version,
            mission="oneday",
        )
        self.pending_events.append(event)

    def confirm_match(self, match_id: str) -> None:
        """Mark a VulnMatch as confirmed."""
        for m in self.matches:
            if m.id == match_id:
                m.confirmed = True
                return
        raise ValueError(f"Match {match_id} not found")

    # ── Queries ───────────────────────────────────────────────────

    def exploitable_matches(self) -> list[VulnMatch]:
        """Return matches that have known public exploits."""
        return [m for m in self.matches if m.exploit_availability is not None]

    def critical_matches(self) -> list[VulnMatch]:
        """Return matches with CVSS >= 9.0."""
        return [m for m in self.matches if m.cve.cvss >= 9.0]

    def matches_for_asset(self, asset_id: str) -> list[VulnMatch]:
        """Return all CVE matches for a specific asset."""
        return [m for m in self.matches if m.asset_id == asset_id]

    # ── Event Sourcing ────────────────────────────────────────────

    def apply(self, event: DomainEvent) -> None:
        """Reconstitute state from a persisted event."""
        if isinstance(event, CVEMatched):
            match = VulnMatch(
                software=event.affected_software,
                cve=CVE(
                    cve_id=event.cve_id,
                    cvss=event.cvss,
                    affected_software=event.affected_software,
                ),
                exploit_availability=(
                    ExploitAvailability(cve_id=event.cve_id)
                    if event.exploit_available
                    else None
                ),
                matched_by="event_replay",
            )
            self.matches.append(match)
            self.version = event.version

    def collect_events(self) -> list[DomainEvent]:
        """Drain pending events."""
        events = list(self.pending_events)
        self.pending_events.clear()
        return events
