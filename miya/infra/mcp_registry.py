"""MCP Registry — manages external MCP server configurations.

All security tools are integrated through open-source MCP servers.
This registry holds their configs and provides them to agents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class MCPServerConfig:
    """Configuration for an external MCP server."""

    name: str
    server_type: str = "stdio"  # "stdio" | "sse" | "docker"
    command: str = ""
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""  # for SSE servers
    description: str = ""
    required_tools: tuple[str, ...] = ()  # tools this server provides

    def to_sdk_config(self) -> dict[str, Any]:
        """Convert to Claude Agent SDK McpServerConfig format."""
        if self.server_type == "stdio":
            config: dict[str, Any] = {
                "type": "stdio",
                "command": self.command,
                "args": list(self.args),
            }
            if self.env:
                config["env"] = dict(self.env)
            return config
        elif self.server_type == "sse":
            return {"type": "sse", "url": self.url}
        else:
            return {"type": self.server_type, "command": self.command}


# ═══════════════════════════════════════════════════════════════════
#  Pre-configured MCP servers
# ═══════════════════════════════════════════════════════════════════

SEMGREP_MCP = MCPServerConfig(
    name="semgrep",
    command="uvx",
    args=("semgrep-mcp",),
    description="Static code analysis with 5000+ security rules (semgrep/mcp)",
    required_tools=("scan", "list_rules"),
)

NMAP_MCP = MCPServerConfig(
    name="nmap",
    command="uvx",
    args=("nmap-mcp-server",),
    description="Network scanning and host discovery (mohdhaji87/Nmap-MCP-Server)",
    required_tools=("nmap_scan",),
)

NUCLEI_MCP = MCPServerConfig(
    name="nuclei",
    command="uvx",
    args=("nuclei-mcp",),
    description="Template-based vulnerability scanning (addcontent/nuclei-mcp)",
    required_tools=("nuclei_scan",),
)

SHODAN_MCP = MCPServerConfig(
    name="shodan",
    command="uvx",
    args=("mcp-shodan",),
    description="Internet-connected device intelligence (BurtTheCoder/mcp-shodan)",
    required_tools=("search", "host_info"),
)

METASPLOIT_MCP = MCPServerConfig(
    name="metasploit",
    command="uvx",
    args=("metasploit-mcp",),
    description="Exploit framework integration (GH05TCREW/MetasploitMCP)",
    required_tools=("search_exploits", "run_exploit"),
)

SQLMAP_MCP = MCPServerConfig(
    name="sqlmap",
    command="uvx",
    args=("sqlmap-mcp-server",),
    description="Automated SQL injection testing (mohdhaji87/SQLMap-MCP)",
    required_tools=("sqlmap_scan",),
)

EXPLOITDB_MCP = MCPServerConfig(
    name="exploitdb",
    command="uvx",
    args=("mcp-exploitdb",),
    description="Public exploit database search (CyberRoute/mcp_exploitdb)",
    required_tools=("search",),
)

GHIDRA_MCP = MCPServerConfig(
    name="ghidra",
    command="uvx",
    args=("ghidra-mcp",),
    description="Binary reverse engineering (LaurieWired/GhidraMCP)",
    required_tools=("analyze", "decompile", "get_functions"),
)

GDB_MCP = MCPServerConfig(
    name="gdb",
    command="uvx",
    args=("mdb-mcp",),
    description="GDB/LLDB debugger integration (smadi0x86/MDB-MCP)",
    required_tools=("start", "run_command"),
)

# ── Crypto tools ──────────────────────────────────────────────────

SAGEMATH_MCP = MCPServerConfig(
    name="sage",
    command="uvx",
    args=("sage-mcp",),
    description="SageMath for number theory, algebra, and cryptanalysis",
    required_tools=("evaluate", "factor", "solve"),
)

FACTORDB_MCP = MCPServerConfig(
    name="factordb",
    command="uvx",
    args=("factordb-mcp",),
    description="Integer factorization database (factordb.com API)",
    required_tools=("factor", "status"),
)

CYBERCHEF_MCP = MCPServerConfig(
    name="cyberchef",
    command="uvx",
    args=("cyberchef-mcp",),
    description="CyberChef encoding/decoding chains (GCHQ CyberChef)",
    required_tools=("bake", "magic"),
)

# ── Misc / forensics tools ────────────────────────────────────────

BINWALK_MCP = MCPServerConfig(
    name="binwalk",
    command="uvx",
    args=("binwalk-mcp",),
    description="Firmware analysis, embedded file extraction (binwalk)",
    required_tools=("scan", "extract"),
)

EXIFTOOL_MCP = MCPServerConfig(
    name="exiftool",
    command="uvx",
    args=("exiftool-mcp",),
    description="File metadata extraction (ExifTool)",
    required_tools=("read_metadata", "write_metadata"),
)


# ═══════════════════════════════════════════════════════════════════
#  Registry
# ═══════════════════════════════════════════════════════════════════


class MCPRegistry:
    """Registry of available MCP servers.

    Agents request servers by name. The registry provides configs
    for the Claude Agent SDK to connect.
    """

    def __init__(self) -> None:
        self._servers: dict[str, MCPServerConfig] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        for config in [
            SEMGREP_MCP, NMAP_MCP, NUCLEI_MCP, SHODAN_MCP,
            METASPLOIT_MCP, SQLMAP_MCP, EXPLOITDB_MCP,
            GHIDRA_MCP, GDB_MCP,
            SAGEMATH_MCP, FACTORDB_MCP, CYBERCHEF_MCP,
            BINWALK_MCP, EXIFTOOL_MCP,
        ]:
            self._servers[config.name] = config

    def register(self, config: MCPServerConfig) -> None:
        self._servers[config.name] = config

    def get(self, name: str) -> MCPServerConfig | None:
        return self._servers.get(name)

    def get_configs_for_agent(self, server_names: list[str]) -> dict[str, dict[str, Any]]:
        """Get SDK-ready MCP configs for a set of server names."""
        result = {}
        for name in server_names:
            config = self._servers.get(name)
            if config:
                result[name] = config.to_sdk_config()
        return result

    def available(self) -> list[str]:
        return list(self._servers.keys())

    def describe(self) -> list[dict[str, str]]:
        return [
            {"name": c.name, "description": c.description}
            for c in self._servers.values()
        ]
