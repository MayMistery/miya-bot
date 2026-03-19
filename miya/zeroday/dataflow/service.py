"""DataFlow context — domain service.

Orchestrates taint analysis using ports (never infrastructure directly).
"""

from __future__ import annotations

from miya.shared.events import DomainEvent
from miya.shared.ports import TaintEnginePort

from .domain import Sanitizer, TaintPath, TaintSession, TaintSink, TaintSource
from .ports import TaintTracerPort


# Canonical source→sink mappings for common vulnerability classes
_SINK_CWE_MAP: dict[str, str] = {
    "sql_query": "CWE-89",
    "command_exec": "CWE-78",
    "file_write": "CWE-73",
    "file_read": "CWE-22",
    "html_render": "CWE-79",
    "ldap_query": "CWE-90",
    "xpath_query": "CWE-643",
    "xml_parse": "CWE-611",
    "deserialization": "CWE-502",
    "redirect": "CWE-601",
    "ssrf": "CWE-918",
    "path_traversal": "CWE-22",
    "code_eval": "CWE-94",
    "template_render": "CWE-1336",
    "log_injection": "CWE-117",
}


class DataFlowService:
    """Domain service for taint analysis and data flow tracing.

    Uses TaintEnginePort (Semgrep taint mode) and optionally
    TaintTracerPort for deeper analysis.
    """

    def __init__(
        self,
        taint_engine: TaintEnginePort,
        tracer: TaintTracerPort | None = None,
    ) -> None:
        self._engine = taint_engine
        self._tracer = tracer

    async def trace_from_entry_points(
        self,
        session: TaintSession,
        source_patterns: list[str],
        sink_patterns: list[str],
    ) -> list[DomainEvent]:
        """Trace taint paths from entry point sources to dangerous sinks.

        Runs the taint engine for each source/sink combination and records
        all discovered paths in the session aggregate.
        """
        for source_pattern in source_patterns:
            for sink_pattern in sink_patterns:
                raw_paths = await self._engine.trace(
                    target_path=session.target_path,
                    source_pattern=source_pattern,
                    sink_pattern=sink_pattern,
                )

                for raw in raw_paths:
                    path = self._build_taint_path(raw)
                    session.record_path(path)

        return session.collect_events()

    async def deep_trace(
        self,
        session: TaintSession,
        source_pattern: str,
        sink_pattern: str,
        language: str = "",
    ) -> list[DomainEvent]:
        """Run deep taint tracing with sanitizer detection.

        Uses TaintTracerPort for more thorough analysis when available.
        """
        if self._tracer is None:
            return await self.trace_from_entry_points(
                session, [source_pattern], [sink_pattern],
            )

        raw_paths = await self._tracer.trace_paths(
            target_path=session.target_path,
            source_pattern=source_pattern,
            sink_pattern=sink_pattern,
            language=language,
        )

        for raw in raw_paths:
            path = self._build_taint_path(raw)

            # Enrich with sanitizer detection
            raw_sanitizers = await self._tracer.find_sanitizers(
                session.target_path,
                raw.get("sink_function", ""),
            )
            for san in raw_sanitizers:
                sanitizer = Sanitizer(
                    function=san.get("function", ""),
                    sanitizer_type=san.get("type", "escaping"),  # type: ignore[arg-type]
                    file_path=san.get("file", ""),
                    line_number=san.get("line", 0),
                    bypassable=san.get("bypassable", False),
                    bypass_notes=san.get("bypass_notes", ""),
                )
                path.sanitizers.append(sanitizer)

            session.record_path(path)

        return session.collect_events()

    @staticmethod
    def _build_taint_path(raw: dict) -> TaintPath:
        """Build a TaintPath from raw analysis output."""
        sink_type = raw.get("sink_type", "sql_query")
        return TaintPath(
            source=TaintSource(
                parameter=raw.get("source", ""),
                source_type=raw.get("source_type", "http_param"),  # type: ignore[arg-type]
                file_path=raw.get("source_file", ""),
                line_number=raw.get("source_line", 0),
                entry_point=raw.get("entry_point", ""),
            ),
            sink=TaintSink(
                function=raw.get("sink", ""),
                sink_type=sink_type,  # type: ignore[arg-type]
                file_path=raw.get("sink_file", ""),
                line_number=raw.get("sink_line", 0),
                cwe_id=_SINK_CWE_MAP.get(sink_type, ""),
            ),
            intermediate_steps=raw.get("intermediates", []),
        )
