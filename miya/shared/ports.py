"""Ports — abstract interfaces that the domain depends on.

These are implemented by adapters in miya/infra/.
The domain layer NEVER imports infrastructure.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Protocol, TypeVar, runtime_checkable

from miya.shared.events import DomainEvent


# ═══════════════════════════════════════════════════════════════════
#  Event Store Port
# ═══════════════════════════════════════════════════════════════════


@runtime_checkable
class EventStorePort(Protocol):
    """Append-only event store for event sourcing."""

    async def append(
        self,
        events: list[DomainEvent],
        expected_version: int = -1,
    ) -> None:
        """Append events. Raise ConcurrencyError if version mismatch."""
        ...

    async def load(self, aggregate_id: str) -> list[DomainEvent]:
        """Load all events for an aggregate."""
        ...

    async def load_by_context(self, context: str, mission: str = "") -> list[DomainEvent]:
        """Load events filtered by bounded context."""
        ...

    async def load_all(self, since: datetime | None = None) -> list[DomainEvent]:
        """Load all events, optionally since a timestamp."""
        ...

    async def count(self) -> int:
        """Total event count."""
        ...


# ═══════════════════════════════════════════════════════════════════
#  Coordinator Port (LLM abstraction)
# ═══════════════════════════════════════════════════════════════════


@runtime_checkable
class CoordinatorPort(Protocol):
    """Abstraction over the LLM coordinator call.

    The topology delegates agent execution through this port.
    In production: calls Claude Agent SDK's query().
    In tests: returns mock responses.
    """

    async def run(
        self,
        prompt: str,
        agents: dict[str, Any],
        mcp_servers: list[str],
    ) -> str:
        """Run the coordinator with a prompt and return text output."""
        ...


# ═══════════════════════════════════════════════════════════════════
#  Repository Port (generic)
# ═══════════════════════════════════════════════════════════════════


T = TypeVar("T")


@runtime_checkable
class RepositoryPort(Protocol[T]):
    """Generic repository for aggregate persistence."""

    async def save(self, aggregate: T) -> None: ...
    async def get(self, id: str) -> T | None: ...
    async def list_all(self, **filters: Any) -> list[T]: ...
    async def delete(self, id: str) -> None: ...


# ═══════════════════════════════════════════════════════════════════
#  Security Tool Ports (implemented by MCP adapters)
# ═══════════════════════════════════════════════════════════════════


@runtime_checkable
class CodeAnalyzerPort(Protocol):
    """Static code analysis — adapted from Semgrep MCP."""

    async def scan(
        self,
        target_path: str,
        rules: list[str] | None = None,
        language: str | None = None,
    ) -> list[dict[str, Any]]:
        """Run static analysis, return findings."""
        ...

    async def list_rules(self, category: str = "") -> list[str]:
        """List available analysis rules."""
        ...


@runtime_checkable
class TaintEnginePort(Protocol):
    """Taint/dataflow analysis — adapted from Semgrep MCP taint mode."""

    async def trace(
        self,
        target_path: str,
        source_pattern: str,
        sink_pattern: str,
    ) -> list[dict[str, Any]]:
        """Trace taint flows from source to sink."""
        ...


@runtime_checkable
class NetworkScannerPort(Protocol):
    """Network scanning — adapted from Nmap MCP."""

    async def scan(
        self,
        target: str,
        ports: str = "",
        scan_type: str = "default",
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Scan a target, return results."""
        ...


@runtime_checkable
class VulnScannerPort(Protocol):
    """Vulnerability scanning — adapted from Nuclei MCP."""

    async def scan(
        self,
        target: str,
        templates: list[str] | None = None,
        severity: str = "",
    ) -> list[dict[str, Any]]:
        """Scan for known vulnerabilities."""
        ...


@runtime_checkable
class AssetIntelPort(Protocol):
    """Asset intelligence — adapted from Shodan MCP."""

    async def search(self, query: str) -> list[dict[str, Any]]:
        """Search for internet-connected assets."""
        ...

    async def host_info(self, ip: str) -> dict[str, Any]:
        """Get detailed info about a host."""
        ...


@runtime_checkable
class ExploitFrameworkPort(Protocol):
    """Exploit framework — adapted from Metasploit MCP."""

    async def search_exploits(self, query: str) -> list[dict[str, Any]]:
        """Search for available exploit modules."""
        ...

    async def run_exploit(
        self,
        module: str,
        options: dict[str, str],
    ) -> dict[str, Any]:
        """Execute an exploit module."""
        ...


@runtime_checkable
class ExploitDBPort(Protocol):
    """Exploit database lookup — adapted from ExploitDB MCP."""

    async def search(self, cve_id: str = "", query: str = "") -> list[dict[str, Any]]:
        """Search ExploitDB for public exploits."""
        ...


@runtime_checkable
class CVEDatabasePort(Protocol):
    """CVE database queries."""

    async def search(
        self,
        software: str,
        version: str = "",
        severity: str = "",
    ) -> list[dict[str, Any]]:
        """Search for CVEs affecting specific software."""
        ...

    async def get(self, cve_id: str) -> dict[str, Any] | None:
        """Get details for a specific CVE."""
        ...


@runtime_checkable
class DisassemblerPort(Protocol):
    """Disassembler/decompiler — adapted from Ghidra MCP."""

    async def analyze(self, binary_path: str) -> dict[str, Any]:
        """Analyze a binary, return overview."""
        ...

    async def get_functions(self, binary_path: str) -> list[dict[str, Any]]:
        """List functions in a binary."""
        ...

    async def decompile(self, binary_path: str, function: str) -> str:
        """Decompile a specific function."""
        ...


@runtime_checkable
class DebuggerPort(Protocol):
    """Debugger — adapted from GDB/LLDB MCP."""

    async def start(self, binary_path: str, args: list[str] | None = None) -> str:
        """Start debugging session, return session ID."""
        ...

    async def run_command(self, session_id: str, command: str) -> str:
        """Run a debugger command."""
        ...

    async def set_breakpoint(self, session_id: str, location: str) -> None:
        """Set a breakpoint."""
        ...


@runtime_checkable
class WebScannerPort(Protocol):
    """Web application scanner — adapted from SQLMap / Nuclei MCP."""

    async def scan_url(
        self,
        url: str,
        params: dict[str, str] | None = None,
        scan_type: str = "auto",
    ) -> list[dict[str, Any]]:
        """Scan a web endpoint for vulnerabilities."""
        ...


@runtime_checkable
class SandboxPort(Protocol):
    """Sandboxed execution environment for PoC testing."""

    async def execute(
        self,
        code: str,
        language: str = "python",
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Execute code in sandbox, return stdout/stderr/exit_code."""
        ...
