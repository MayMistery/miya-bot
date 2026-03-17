"""Sink context — ports (driven-side interfaces).

These are consumed by the domain service and implemented by infrastructure.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SinkClassifierPort(Protocol):
    """Classifies sink functions by CWE pattern and assesses exploitability.

    Implemented by Semgrep MCP adapter with CWE-specific rules.
    """

    async def classify_sink(
        self,
        function_signature: str,
        code_context: str,
        language: str = "",
    ) -> dict[str, Any]:
        """Classify a sink function — returns CWE, pattern, exploitability."""
        ...

    async def check_exploitability(
        self,
        sink_function: str,
        source_file: str,
        taint_path: list[str],
    ) -> dict[str, Any]:
        """Assess exploitability of a confirmed sink given its taint path."""
        ...
