"""DataFlow context — ports (driven-side interfaces).

These are consumed by the domain service and implemented by infrastructure.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class TaintTracerPort(Protocol):
    """Taint tracing engine — tracks data flow from sources to sinks.

    Implemented by Semgrep MCP adapter in taint mode.
    """

    async def trace_paths(
        self,
        target_path: str,
        source_pattern: str,
        sink_pattern: str,
        language: str = "",
    ) -> list[dict[str, Any]]:
        """Trace taint flows matching source/sink patterns.

        Returns list of paths with source, sink, intermediates, sanitizers.
        """
        ...

    async def find_sanitizers(
        self,
        target_path: str,
        function_pattern: str,
    ) -> list[dict[str, Any]]:
        """Find sanitizer/validator functions in the codebase."""
        ...
