"""Scan bounded context — domain model.

Aggregate Root: ScanTask
Entities: ScanResult
Value Objects: ScanTarget
"""

from __future__ import annotations

from dataclasses import dataclass, field
from miya.shared.events import DomainEvent, ScanCompleted, VulnerabilityFound
from miya.shared.types import new_id as _uuid


# ═══════════════════════════════════════════════════════════════════
#  Value Objects
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class ScanTarget:
    """What to scan — translated from Recon Asset via ACL."""

    host: str = ""
    ip: str = ""
    ports: tuple[int, ...] = ()
    services: tuple[str, ...] = ()
    asset_id: str = ""  # reference back to recon asset


# ═══════════════════════════════════════════════════════════════════
#  Entity
# ═══════════════════════════════════════════════════════════════════


@dataclass
class ScanResult:
    """A single finding from a vulnerability scan."""

    id: str = field(default_factory=_uuid)
    template_id: str = ""  # nuclei template ID
    name: str = ""
    severity: str = "info"  # critical, high, medium, low, info
    matched_at: str = ""  # URL or host:port that matched
    description: str = ""
    reference: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    extracted_results: list[str] = field(default_factory=list)
    raw_output: str = ""


# ═══════════════════════════════════════════════════════════════════
#  Aggregate Root
# ═══════════════════════════════════════════════════════════════════


@dataclass
class ScanTask:
    """Aggregate root for the scan bounded context.

    Represents a vulnerability scanning job against one or more targets.
    Tracks scan configuration, progress, and results.
    """

    id: str = field(default_factory=_uuid)
    targets: list[ScanTarget] = field(default_factory=list)
    scanner: str = "nuclei"  # scanner engine used
    templates: list[str] = field(default_factory=list)  # nuclei templates
    severity_filter: str = ""  # minimum severity to report
    results: list[ScanResult] = field(default_factory=list)
    status: str = "pending"  # pending, running, completed, failed
    version: int = 0
    pending_events: list[DomainEvent] = field(default_factory=list)

    # ── Commands ──────────────────────────────────────────────────

    def add_target(self, target: ScanTarget) -> None:
        """Add a scan target."""
        self.targets.append(target)

    def start(self) -> None:
        """Mark the scan as running."""
        self.status = "running"

    def record_result(
        self,
        template_id: str,
        name: str,
        severity: str,
        matched_at: str,
        description: str = "",
        cve_ids: list[str] | None = None,
        cwe_ids: list[str] | None = None,
        reference: list[str] | None = None,
        raw_output: str = "",
        correlation_id: str = "",
    ) -> ScanResult:
        """Record a scan finding."""
        result = ScanResult(
            template_id=template_id,
            name=name,
            severity=severity,
            matched_at=matched_at,
            description=description,
            cve_ids=cve_ids or [],
            cwe_ids=cwe_ids or [],
            reference=reference or [],
            raw_output=raw_output,
        )
        self.results.append(result)
        self.version += 1

        # Emit VulnerabilityFound for each finding
        cwe = cwe_ids[0] if cwe_ids else ""
        event = VulnerabilityFound(
            aggregate_id=self.id,
            aggregate_type="ScanTask",
            vuln_id=result.id,
            vuln_type=name,
            cwe_id=cwe,
            severity=severity,
            location=matched_at,
            description=description,
            correlation_id=correlation_id,
            version=self.version,
            mission="oneday",
            context="scan",
        )
        self.pending_events.append(event)
        return result

    def complete(self, correlation_id: str = "") -> None:
        """Mark the scan as completed."""
        self.status = "completed"
        self.version += 1

        # Collect target info for the event
        host = self.targets[0].host if self.targets else ""
        ports = self.targets[0].ports if self.targets else ()

        event = ScanCompleted(
            aggregate_id=self.id,
            aggregate_type="ScanTask",
            target_host=host,
            target_ports=ports,
            findings_count=len(self.results),
            scanner=self.scanner,
            correlation_id=correlation_id,
            version=self.version,
            mission="oneday",
        )
        self.pending_events.append(event)

    def fail(self, reason: str = "") -> None:
        """Mark the scan as failed."""
        self.status = "failed"

    # ── Event Sourcing ────────────────────────────────────────────

    def apply(self, event: DomainEvent) -> None:
        """Reconstitute state from a persisted event."""
        if isinstance(event, VulnerabilityFound):
            result = ScanResult(
                id=event.vuln_id,
                name=event.vuln_type,
                severity=event.severity,
                matched_at=event.location,
                description=event.description,
                cwe_ids=[event.cwe_id] if event.cwe_id else [],
            )
            self.results.append(result)
            self.version = event.version

        elif isinstance(event, ScanCompleted):
            self.status = "completed"
            self.version = event.version

    def collect_events(self) -> list[DomainEvent]:
        """Drain pending events."""
        events = list(self.pending_events)
        self.pending_events.clear()
        return events
