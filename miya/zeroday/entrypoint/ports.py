"""EntryPoint context — ports (driven-side interfaces).

These are consumed by the domain service and implemented by infrastructure.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class EntryPointScannerPort(Protocol):
    """Scans source code for externally reachable entry points.

    Implemented by Semgrep MCP adapter for framework-aware discovery.
    """

    async def discover_routes(
        self,
        target_path: str,
        framework: str = "",
    ) -> list[dict[str, Any]]:
        """Discover HTTP routes, CLI handlers, RPC methods, etc."""
        ...

    async def extract_input_vectors(
        self,
        target_path: str,
        handler_function: str,
    ) -> list[dict[str, Any]]:
        """Extract input parameters accepted by a handler function."""
        ...
