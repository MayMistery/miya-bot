"""DataFlow bounded context — domain model.

Aggregate: TaintSession — a taint analysis session tracking data flows.
Entity: TaintPath — a source-to-sink data flow path.
VOs: TaintSource, TaintSink, Sanitizer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from miya.shared.events import DomainEvent, TaintPathTraced
from miya.shared.types import new_id as _uuid


# ═══════════════════════════════════════════════════════════════════
#  Value Objects
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class TaintSource:
    """Where untrusted data enters the program.

    Maps to an entry point's input vector — the origin of tainted data.
    """

    parameter: str  # e.g. "request.GET['id']"
    source_type: Literal[
        "http_param", "http_body", "http_header", "cookie",
        "file_read", "db_read", "env_var", "cli_arg", "stdin",
        "websocket", "deserialization",
    ] = "http_param"
    file_path: str = ""
    line_number: int = 0
    entry_point: str = ""  # link back to entrypoint context


@dataclass(frozen=True)
class TaintSink:
    """A dangerous function call where tainted data arrives.

    If unsanitized data reaches a sink, it constitutes a vulnerability.
    """

    function: str  # e.g. "cursor.execute()", "os.system()"
    sink_type: Literal[
        "sql_query", "command_exec", "file_write", "file_read",
        "html_render", "ldap_query", "xpath_query", "xml_parse",
        "deserialization", "redirect", "crypto_key", "log_injection",
        "ssrf", "path_traversal", "code_eval", "template_render",
    ] = "sql_query"
    file_path: str = ""
    line_number: int = 0
    cwe_id: str = ""  # CWE mapping for this sink type


@dataclass(frozen=True)
class Sanitizer:
    """A filtering, encoding, or validation operation on the taint path.

    If a proper sanitizer exists between source and sink, the path
    may not be exploitable (depending on bypass potential).
    """

    function: str  # e.g. "html.escape()", "parameterize()"
    sanitizer_type: Literal[
        "encoding", "escaping", "validation", "parameterization",
        "allowlist", "denylist", "type_cast", "length_limit",
    ] = "escaping"
    file_path: str = ""
    line_number: int = 0
    bypassable: bool = False  # True if known bypass exists
    bypass_notes: str = ""


# ═══════════════════════════════════════════════════════════════════
#  Entity
# ═══════════════════════════════════════════════════════════════════


@dataclass
class TaintPath:
    """A traced data flow from source to sink.

    Represents a single taint propagation path through the codebase,
    including any sanitizers encountered along the way.
    """

    id: str = field(default_factory=_uuid)
    source: TaintSource = field(default_factory=lambda: TaintSource(parameter=""))
    sink: TaintSink = field(default_factory=lambda: TaintSink(function=""))
    intermediate_steps: list[str] = field(default_factory=list)
    sanitizers: list[Sanitizer] = field(default_factory=list)

    @property
    def is_sanitized(self) -> bool:
        """True if any non-bypassable sanitizer exists on the path."""
        return any(not s.bypassable for s in self.sanitizers)

    @property
    def is_exploitable(self) -> bool:
        """True if no effective sanitizer exists (or all are bypassable)."""
        return not self.is_sanitized

    @property
    def full_path(self) -> tuple[str, ...]:
        """Ordered path from source through intermediates to sink."""
        return (
            self.source.parameter,
            *self.intermediate_steps,
            self.sink.function,
        )


# ═══════════════════════════════════════════════════════════════════
#  Aggregate Root
# ═══════════════════════════════════════════════════════════════════


@dataclass
class TaintSession:
    """Aggregate root — a taint analysis session.

    Tracks all taint paths discovered for a given analysis run,
    linking entry point sources to dangerous sinks.
    """

    id: str = field(default_factory=_uuid)
    target_path: str = ""
    codebase_id: str = ""  # link to entrypoint context's CodeBase
    paths: list[TaintPath] = field(default_factory=list)
    version: int = 0

    _pending_events: list[DomainEvent] = field(
        default_factory=list, repr=False, compare=False,
    )

    # ── Commands ─────────────────────────────────────────────────

    def record_path(self, path: TaintPath) -> TaintPath:
        """Record a discovered taint path and emit event."""
        self.paths.append(path)
        self.version += 1

        event = TaintPathTraced(
            aggregate_id=self.id,
            aggregate_type="TaintSession",
            source=path.source.parameter,
            sink=path.sink.function,
            path=path.full_path,
            sanitized=path.is_sanitized,
            version=self.version,
        )
        self._pending_events.append(event)
        return path

    # ── Event sourcing ───────────────────────────────────────────

    def apply(self, event: DomainEvent) -> None:
        """Rebuild state from a persisted event."""
        if isinstance(event, TaintPathTraced):
            self._apply_taint_path_traced(event)

    def _apply_taint_path_traced(self, event: TaintPathTraced) -> None:
        steps = list(event.path)
        source_param = steps[0] if steps else ""
        sink_func = steps[-1] if steps else ""
        intermediates = steps[1:-1] if len(steps) > 2 else []

        path = TaintPath(
            source=TaintSource(parameter=source_param),
            sink=TaintSink(function=sink_func),
            intermediate_steps=intermediates,
        )
        self.paths.append(path)
        self.version = event.version

    def collect_events(self) -> list[DomainEvent]:
        """Drain and return pending events."""
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    # ── Queries ──────────────────────────────────────────────────

    def exploitable_paths(self) -> list[TaintPath]:
        """Paths with no effective sanitizer — prime vulnerability candidates."""
        return [p for p in self.paths if p.is_exploitable]

    def paths_by_sink_type(self, sink_type: str) -> list[TaintPath]:
        """Filter paths by their sink type (e.g., 'sql_query')."""
        return [p for p in self.paths if p.sink.sink_type == sink_type]
