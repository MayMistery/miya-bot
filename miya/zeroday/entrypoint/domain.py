"""EntryPoint bounded context — domain model.

Aggregate: CodeBase — the target codebase under security audit.
Entity: EntryPoint — an externally reachable entry (HTTP handler, CLI, RPC).
VO: InputVector — a specific input parameter (name, type, source).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from miya.shared.events import DomainEvent, EntryPointDiscovered
from miya.shared.types import new_id as _uuid


# ═══════════════════════════════════════════════════════════════════
#  Value Objects
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class InputVector:
    """A specific input that an entry point accepts.

    Examples: query parameter, POST body field, path segment,
    HTTP header, cookie, file upload, CLI argument.
    """

    name: str
    source: Literal[
        "query", "body", "path", "header", "cookie",
        "file", "cli_arg", "env", "stdin", "websocket",
    ]
    data_type: str = "string"  # "string", "int", "json", "binary", etc.
    required: bool = False
    sanitized: bool = False
    notes: str = ""


# ═══════════════════════════════════════════════════════════════════
#  Entity
# ═══════════════════════════════════════════════════════════════════


@dataclass
class EntryPoint:
    """An externally reachable entry into the codebase.

    Could be an HTTP route, a CLI command handler, a gRPC method,
    a message queue consumer, a cron job entry, etc.
    """

    id: str = field(default_factory=_uuid)
    endpoint: str = ""  # e.g. "POST /api/users", "cli: import-cmd"
    handler_function: str = ""  # e.g. "app.views.create_user"
    file_path: str = ""  # source file location
    line_number: int = 0
    framework: str = ""  # "django", "flask", "express", "gin", etc.
    http_method: str = ""  # GET, POST, PUT, DELETE, etc.
    auth_required: bool = False
    input_vectors: list[InputVector] = field(default_factory=list)

    @property
    def attack_surface_size(self) -> int:
        """Number of unsanitized input vectors — proxy for attack surface."""
        return sum(1 for iv in self.input_vectors if not iv.sanitized)

    def add_input(self, vector: InputVector) -> None:
        self.input_vectors.append(vector)


# ═══════════════════════════════════════════════════════════════════
#  Aggregate Root
# ═══════════════════════════════════════════════════════════════════


@dataclass
class CodeBase:
    """Aggregate root — the target codebase under 0-day audit.

    Tracks discovered entry points and their input vectors.
    Emits EntryPointDiscovered events via event sourcing.
    """

    id: str = field(default_factory=_uuid)
    target_uri: str = ""  # path or repo URL
    language: str = ""  # primary language
    framework: str = ""  # detected framework
    entry_points: list[EntryPoint] = field(default_factory=list)
    version: int = 0

    # ── Pending events (event sourcing) ──────────────────────────
    _pending_events: list[DomainEvent] = field(
        default_factory=list, repr=False, compare=False,
    )

    # ── Commands ─────────────────────────────────────────────────

    def register_entry_point(self, entry_point: EntryPoint) -> EntryPoint:
        """Register a newly discovered entry point and emit event."""
        self.entry_points.append(entry_point)
        self.version += 1

        event = EntryPointDiscovered(
            aggregate_id=self.id,
            aggregate_type="CodeBase",
            endpoint=entry_point.endpoint,
            input_vectors=tuple(
                f"{iv.name}:{iv.source}" for iv in entry_point.input_vectors
            ),
            framework=entry_point.framework or self.framework,
            version=self.version,
        )
        self._pending_events.append(event)
        return entry_point

    # ── Event sourcing ───────────────────────────────────────────

    def apply(self, event: DomainEvent) -> None:
        """Rebuild state from a persisted event."""
        if isinstance(event, EntryPointDiscovered):
            self._apply_entry_point_discovered(event)

    def _apply_entry_point_discovered(self, event: EntryPointDiscovered) -> None:
        vectors = []
        for vec_str in event.input_vectors:
            parts = vec_str.split(":", 1)
            if len(parts) == 2:
                vectors.append(InputVector(name=parts[0], source=parts[1]))  # type: ignore[arg-type]
            else:
                vectors.append(InputVector(name=parts[0], source="query"))
        ep = EntryPoint(
            endpoint=event.endpoint,
            framework=event.framework,
            input_vectors=vectors,
        )
        self.entry_points.append(ep)
        self.version = event.version

    def collect_events(self) -> list[DomainEvent]:
        """Drain and return pending events."""
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    # ── Queries ──────────────────────────────────────────────────

    def unauthenticated_entries(self) -> list[EntryPoint]:
        """Entry points that do not require authentication — high priority."""
        return [ep for ep in self.entry_points if not ep.auth_required]

    def high_surface_entries(self, threshold: int = 2) -> list[EntryPoint]:
        """Entry points with many unsanitized inputs."""
        return [
            ep for ep in self.entry_points
            if ep.attack_surface_size >= threshold
        ]
