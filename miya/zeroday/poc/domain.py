"""PoC bounded context — domain model.

Aggregate: PoCProject — construction and validation of a proof-of-concept exploit.
Entity: PoCPayload — a specific exploit input/payload.
VO: PoCResult — execution outcome of a PoC attempt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from uuid import uuid4

from miya.shared.events import DomainEvent, PoCValidated


def _uuid() -> str:
    return str(uuid4())


# ═══════════════════════════════════════════════════════════════════
#  Value Objects
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class PoCResult:
    """Execution outcome of a PoC attempt.

    Captures stdout, stderr, exit code, and whether the exploit
    achieved its intended effect.
    """

    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    success: bool = False
    evidence: str = ""  # proof that the exploit worked (e.g., leaked data, shell output)
    duration_ms: int = 0
    error_message: str = ""


# ═══════════════════════════════════════════════════════════════════
#  Entity
# ═══════════════════════════════════════════════════════════════════


@dataclass
class PoCPayload:
    """A specific exploit payload for a confirmed vulnerability.

    Contains the actual input that triggers the vulnerability,
    along with execution parameters and results.
    """

    id: str = field(default_factory=_uuid)
    name: str = ""  # descriptive label, e.g. "sqli_union_extract"
    payload_type: Literal[
        "http_request", "cli_input", "file_content",
        "script", "network_packet", "websocket_message",
    ] = "http_request"
    content: str = ""  # the actual exploit payload
    delivery_method: str = ""  # how to deliver: curl command, python script, etc.
    target_parameter: str = ""  # which input vector to inject into
    expected_behavior: str = ""  # what should happen if exploit succeeds
    result: PoCResult | None = None

    @property
    def is_validated(self) -> bool:
        """True if this payload has been executed and succeeded."""
        return self.result is not None and self.result.success


# ═══════════════════════════════════════════════════════════════════
#  Aggregate Root
# ═══════════════════════════════════════════════════════════════════


@dataclass
class PoCProject:
    """Aggregate root — PoC construction and validation.

    Manages the lifecycle of building, testing, and validating
    a proof-of-concept exploit for a confirmed vulnerability.
    """

    id: str = field(default_factory=_uuid)
    sink_analysis_id: str = ""  # link to sink context
    vuln_type: str = ""  # CWE name
    cwe_id: str = ""
    target_endpoint: str = ""
    target_file: str = ""
    payloads: list[PoCPayload] = field(default_factory=list)
    poc_code: str = ""  # complete PoC script
    language: str = "python"  # PoC script language
    version: int = 0

    _pending_events: list[DomainEvent] = field(
        default_factory=list, repr=False, compare=False,
    )

    # ── Commands ─────────────────────────────────────────────────

    def add_payload(self, payload: PoCPayload) -> PoCPayload:
        """Add a new exploit payload to the project."""
        self.payloads.append(payload)
        return payload

    def record_result(self, payload_id: str, result: PoCResult) -> None:
        """Record execution result for a payload."""
        for payload in self.payloads:
            if payload.id == payload_id:
                payload.result = result
                break

    def validate(self, poc_code: str, result: PoCResult) -> None:
        """Mark the PoC as validated with its final code and result.

        Emits PoCValidated event if the exploit succeeded.
        """
        self.poc_code = poc_code
        self.version += 1

        if result.success:
            self._pending_events.append(PoCValidated(
                aggregate_id=self.id,
                aggregate_type="PoCProject",
                vuln_type=self.vuln_type,
                poc_code=poc_code,
                result=result.evidence or result.stdout,
                version=self.version,
            ))

    # ── Event sourcing ───────────────────────────────────────────

    def apply(self, event: DomainEvent) -> None:
        """Rebuild state from a persisted event."""
        if isinstance(event, PoCValidated):
            self._apply_poc_validated(event)

    def _apply_poc_validated(self, event: PoCValidated) -> None:
        self.vuln_type = event.vuln_type
        self.poc_code = event.poc_code
        self.version = event.version

    def collect_events(self) -> list[DomainEvent]:
        """Drain and return pending events."""
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    # ── Queries ──────────────────────────────────────────────────

    @property
    def is_validated(self) -> bool:
        """True if any payload has been validated successfully."""
        return any(p.is_validated for p in self.payloads)

    def successful_payloads(self) -> list[PoCPayload]:
        """Return all payloads that succeeded."""
        return [p for p in self.payloads if p.is_validated]

    def failed_payloads(self) -> list[PoCPayload]:
        """Return payloads that were attempted but failed."""
        return [
            p for p in self.payloads
            if p.result is not None and not p.result.success
        ]
