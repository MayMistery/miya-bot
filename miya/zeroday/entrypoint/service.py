"""EntryPoint context — domain service.

Orchestrates entry point discovery using ports (never infrastructure directly).
"""

from __future__ import annotations

from miya.shared.events import DomainEvent
from miya.shared.ports import CodeAnalyzerPort

from .domain import CodeBase, EntryPoint, InputVector
from .ports import EntryPointScannerPort


class EntryPointService:
    """Domain service for entry point discovery and registration.

    Uses CodeAnalyzerPort (Semgrep) for static scanning and
    EntryPointScannerPort for framework-aware route extraction.
    """

    def __init__(
        self,
        code_analyzer: CodeAnalyzerPort,
        scanner: EntryPointScannerPort | None = None,
    ) -> None:
        self._analyzer = code_analyzer
        self._scanner = scanner

    async def discover_entry_points(
        self,
        codebase: CodeBase,
        target_path: str,
    ) -> list[DomainEvent]:
        """Scan codebase for entry points and register them.

        Returns list of emitted domain events.
        """
        # Use static analysis to find route/handler definitions
        findings = await self._analyzer.scan(
            target_path=target_path,
            rules=["security-audit", "owasp-top-10"],
            language=codebase.language or None,
        )

        for finding in findings:
            entry_point = EntryPoint(
                endpoint=finding.get("endpoint", finding.get("check_id", "")),
                handler_function=finding.get("handler", ""),
                file_path=finding.get("path", ""),
                line_number=finding.get("start", {}).get("line", 0),
                framework=codebase.framework,
                http_method=finding.get("method", ""),
                auth_required=finding.get("auth_required", False),
            )

            # Extract input vectors from finding metadata
            for param in finding.get("input_vectors", []):
                vector = InputVector(
                    name=param.get("name", ""),
                    source=param.get("source", "query"),
                    data_type=param.get("type", "string"),
                    required=param.get("required", False),
                )
                entry_point.add_input(vector)

            codebase.register_entry_point(entry_point)

        return codebase.collect_events()

    async def scan_with_framework_rules(
        self,
        codebase: CodeBase,
        target_path: str,
        framework: str,
    ) -> list[DomainEvent]:
        """Run framework-specific entry point discovery.

        Uses EntryPointScannerPort for deeper framework-aware analysis.
        """
        if self._scanner is None:
            return await self.discover_entry_points(codebase, target_path)

        routes = await self._scanner.discover_routes(target_path, framework)

        for route in routes:
            entry_point = EntryPoint(
                endpoint=route.get("endpoint", ""),
                handler_function=route.get("handler", ""),
                file_path=route.get("file", ""),
                line_number=route.get("line", 0),
                framework=framework,
                http_method=route.get("method", ""),
                auth_required=route.get("auth_required", False),
            )

            # Extract input vectors via deeper analysis
            vectors = await self._scanner.extract_input_vectors(
                target_path, entry_point.handler_function,
            )
            for vec in vectors:
                entry_point.add_input(InputVector(
                    name=vec.get("name", ""),
                    source=vec.get("source", "query"),
                    data_type=vec.get("type", "string"),
                    required=vec.get("required", False),
                    sanitized=vec.get("sanitized", False),
                ))

            codebase.register_entry_point(entry_point)

        return codebase.collect_events()
