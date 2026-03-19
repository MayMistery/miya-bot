"""Sink bounded context — domain model.

Aggregate: SinkAnalysis — security analysis of a confirmed sink.
VOs: SinkPattern, Exploitability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from miya.shared.events import DomainEvent, SinkConfirmed, VulnerabilityFound
from miya.shared.types import new_id as _uuid


# ═══════════════════════════════════════════════════════════════════
#  Value Objects
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class SinkPattern:
    """A CWE pattern and its matching rule for sink identification.

    Maps a dangerous function signature to its vulnerability class.
    """

    cwe_id: str  # e.g. "CWE-89"
    cwe_name: str  # e.g. "SQL Injection"
    function_pattern: str  # e.g. "cursor.execute($QUERY)"
    language: str = ""
    rule_id: str = ""  # Semgrep rule ID
    description: str = ""


@dataclass(frozen=True)
class Exploitability:
    """CVSS-like exploitability assessment for a confirmed sink.

    Captures the factors that determine how easy it is to exploit
    a vulnerability at this sink.
    """

    attack_vector: Literal[
        "network", "adjacent", "local", "physical",
    ] = "network"
    attack_complexity: Literal["low", "high"] = "low"
    privileges_required: Literal["none", "low", "high"] = "none"
    user_interaction: Literal["none", "required"] = "none"
    impact_confidentiality: Literal["none", "low", "high"] = "high"
    impact_integrity: Literal["none", "low", "high"] = "high"
    impact_availability: Literal["none", "low", "high"] = "low"

    @property
    def score_label(self) -> str:
        """Rough exploitability label based on key factors."""
        if (
            self.attack_complexity == "low"
            and self.privileges_required == "none"
            and self.user_interaction == "none"
        ):
            return "critical"
        if self.attack_complexity == "low" and self.privileges_required == "none":
            return "high"
        if self.attack_complexity == "low":
            return "medium"
        return "low"


# ═══════════════════════════════════════════════════════════════════
#  Aggregate Root
# ═══════════════════════════════════════════════════════════════════


@dataclass
class SinkAnalysis:
    """Aggregate root — security analysis of a dangerous sink.

    Confirms whether a sink identified by taint analysis is truly
    exploitable and classifies the vulnerability.
    """

    id: str = field(default_factory=_uuid)
    taint_session_id: str = ""  # link to dataflow context
    sink_function: str = ""
    file_path: str = ""
    line_number: int = 0
    pattern: SinkPattern | None = None
    exploitability: Exploitability | None = None
    confirmed: bool = False
    false_positive_reason: str = ""
    version: int = 0

    _pending_events: list[DomainEvent] = field(
        default_factory=list, repr=False, compare=False,
    )

    # ── Commands ─────────────────────────────────────────────────

    def confirm_sink(
        self,
        pattern: SinkPattern,
        exploitability: Exploitability,
    ) -> None:
        """Confirm that this sink is exploitable and classify it."""
        self.pattern = pattern
        self.exploitability = exploitability
        self.confirmed = True
        self.version += 1

        self._pending_events.append(SinkConfirmed(
            aggregate_id=self.id,
            aggregate_type="SinkAnalysis",
            sink_type=pattern.cwe_name,
            cwe_id=pattern.cwe_id,
            exploitability=exploitability.score_label,
            version=self.version,
        ))

        # Also emit a VulnerabilityFound event for cross-context consumption
        self._pending_events.append(VulnerabilityFound(
            aggregate_id=self.id,
            aggregate_type="SinkAnalysis",
            vuln_type=pattern.cwe_name,
            cwe_id=pattern.cwe_id,
            severity=exploitability.score_label,
            location=f"{self.file_path}:{self.line_number}",
            description=(
                f"{pattern.cwe_name} at {self.sink_function} — "
                f"attack complexity: {exploitability.attack_complexity}, "
                f"privileges required: {exploitability.privileges_required}"
            ),
            version=self.version,
        ))

    def mark_false_positive(self, reason: str) -> None:
        """Mark this sink as a false positive with explanation."""
        self.confirmed = False
        self.false_positive_reason = reason
        self.version += 1

    # ── Event sourcing ───────────────────────────────────────────

    def apply(self, event: DomainEvent) -> None:
        """Rebuild state from a persisted event."""
        if isinstance(event, SinkConfirmed):
            self._apply_sink_confirmed(event)

    def _apply_sink_confirmed(self, event: SinkConfirmed) -> None:
        self.pattern = SinkPattern(
            cwe_id=event.cwe_id,
            cwe_name=event.sink_type,
            function_pattern=self.sink_function,
        )
        self.exploitability = Exploitability()  # defaults
        self.confirmed = True
        self.version = event.version

    def collect_events(self) -> list[DomainEvent]:
        """Drain and return pending events."""
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
