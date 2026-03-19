"""Miya CLI — elegant command-line interface for the DDD Pentest Agent.

Usage:
    miya oneday --target 192.168.1.0/24
    miya zeroday --target ./app --language python
    miya ctf --target https://ctf.example.com/chall/3 --category web
    miya interactive
"""

from __future__ import annotations

import asyncio
import os
import shlex
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

# Load .env before anything reads env vars
load_dotenv()

from miya.infra.logging_config import setup_logging, TRACE
setup_logging()

DEFAULT_MODEL = os.environ.get("MIYA_MODEL", "opus")

_MODEL_HELP = "Claude model (opus/sonnet/haiku). Env: MIYA_MODEL"
_KEY_HELP = "Anthropic API key. Env: ANTHROPIC_API_KEY"
_BASE_URL_HELP = "Anthropic API base URL. Env: ANTHROPIC_BASE_URL"


def _apply_api_env(api_key: str | None, base_url: str | None) -> None:
    """Apply CLI overrides to environment so the SDK picks them up."""
    if api_key:
        os.environ["ANTHROPIC_API_KEY"] = api_key
    if base_url:
        os.environ["ANTHROPIC_BASE_URL"] = base_url

import click
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from rich.layout import Layout
from rich.syntax import Syntax
from rich import box

console = Console()


# ═══════════════════════════════════════════════════════════════════
#  Banner & Styling
# ═══════════════════════════════════════════════════════════════════

BANNER = r"""[bold red]
    ╔══════════════════════════════════════════════════╗
    ║                                                  ║
    ║   ███╗   ███╗ ██╗ ██╗   ██╗  █████╗             ║
    ║   ████╗ ████║ ██║ ╚██╗ ██╔╝ ██╔══██╗            ║
    ║   ██╔████╔██║ ██║  ╚████╔╝  ███████║            ║
    ║   ██║╚██╔╝██║ ██║   ╚██╔╝   ██╔══██║            ║
    ║   ██║ ╚═╝ ██║ ██║    ██║    ██║  ██║            ║
    ║   ╚═╝     ╚═╝ ╚═╝    ╚═╝    ╚═╝  ╚═╝            ║
    ║                                                  ║
    ║   [bold white]DDD Pentest Agent[/bold white]                            ║
    ║   [dim]0day · 1day · CTF[/dim]                              ║
    ║   [dim]OODA · AttackGraph · EventSourcing[/dim]              ║
    ║                                                  ║
    ╚══════════════════════════════════════════════════╝
[/bold red]"""


def show_banner() -> None:
    console.print(BANNER)


def make_mission_table() -> Table:
    table = Table(
        title="Available Missions",
        box=box.ROUNDED,
        title_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Mission", style="bold green", width=12)
    table.add_column("Description", style="white")
    table.add_column("Bounded Contexts", style="dim cyan")
    table.add_row(
        "oneday",
        "Exploit known CVEs (1-day vulnerabilities)",
        "Recon → Scan → Vuln → Exploit → Post",
    )
    table.add_row(
        "zeroday",
        "Discover unknown vulnerabilities (0-day)",
        "EntryPoint → DataFlow → Sink → PoC",
    )
    table.add_row(
        "ctf",
        "Solve CTF challenges",
        "Web · Pwn · Crypto · Reverse · Misc",
    )
    return table


def make_topology_table() -> Table:
    table = Table(
        title="Orchestration Topologies",
        box=box.ROUNDED,
        title_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Topology", style="bold yellow", width=15)
    table.add_column("Description", style="white")
    table.add_row(
        "ooda",
        "OODA Loop — Observe→Orient→Decide→Act with Reflection Gate",
    )
    table.add_row(
        "attack_graph",
        "Attack Graph — DAG-based path planning + tactical execution",
    )
    table.add_row(
        "fanout",
        "Fan-Out — parallel solving for multi-challenge CTF competitions",
    )
    return table


def make_mcp_table() -> Table:
    table = Table(
        title="Integrated MCP Servers",
        box=box.ROUNDED,
        title_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Server", style="bold magenta", width=12)
    table.add_column("Description", style="white")
    table.add_column("Used By", style="dim")

    servers = [
        ("semgrep", "Static code analysis (5000+ rules)", "0-day"),
        ("nmap", "Network scanning & host discovery", "1-day"),
        ("nuclei", "Template-based vulnerability scanning", "1-day, CTF"),
        ("shodan", "Internet asset intelligence", "1-day"),
        ("metasploit", "Exploit framework", "1-day"),
        ("sqlmap", "SQL injection testing", "1-day, CTF"),
        ("exploitdb", "Public exploit database", "1-day"),
        ("ghidra", "Binary reverse engineering", "CTF"),
        ("gdb", "Debugger (GDB/LLDB)", "CTF"),
        ("sage", "SageMath — number theory & algebra", "CTF"),
        ("factordb", "FactorDB — integer factorization lookup", "CTF"),
        ("cyberchef", "CyberChef — encoding/decoding transforms", "CTF"),
        ("binwalk", "Binwalk — firmware & file analysis", "CTF"),
        ("exiftool", "ExifTool — metadata extraction", "CTF"),
    ]
    for name, desc, used_by in servers:
        table.add_row(name, desc, used_by)
    return table


def print_report(report: Any) -> None:
    """Print a MissionReport with rich formatting."""
    # Header
    status_color = "green" if report.status == "completed" else "red"
    console.print(Panel(
        f"[bold]{report.mission_type.upper()}[/bold] → {report.target}\n"
        f"Topology: [yellow]{report.topology}[/yellow]  |  "
        f"Status: [{status_color}]{report.status}[/{status_color}]  |  "
        f"Duration: {report.duration_seconds:.1f}s  |  "
        f"Events: {report.events_count}",
        title="[bold red]Mission Report[/bold red]",
        border_style="red",
        box=box.DOUBLE,
    ))

    # Findings table
    if report.findings:
        table = Table(
            title=f"Findings ({len(report.findings)} total, {report.critical_count} critical)",
            box=box.SIMPLE_HEAVY,
            title_style="bold",
        )
        table.add_column("Severity", width=10)
        table.add_column("Title", style="white")
        table.add_column("Detail", style="dim", max_width=50)
        table.add_column("Context", style="cyan", width=12)

        for f in sorted(report.findings, key=lambda x: -x.severity.score):
            sev_colors = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
                "info": "dim",
            }
            color = sev_colors.get(f.severity.value, "white")
            table.add_row(
                f"[{color}]{f.severity.value.upper()}[/{color}]",
                f.title,
                f.detail[:50] + "..." if len(f.detail) > 50 else f.detail,
                f.context,
            )
        console.print(table)
    else:
        console.print("[dim]No findings.[/dim]")

    # Blackboard summary
    if report.blackboard_summary:
        summary = report.blackboard_summary
        console.print(Panel(
            f"Assets: {summary.get('assets', 0)}  |  "
            f"CVEs: {summary.get('cve_matches', 0)}  |  "
            f"Exploits: {summary.get('exploit_attempts', 0)}  |  "
            f"Access: [bold]{summary.get('access_level', 'none')}[/bold]\n"
            f"{summary.get('attack_graph', '')}",
            title="Blackboard Summary",
            border_style="cyan",
        ))


# ═══════════════════════════════════════════════════════════════════
#  CLI Commands
# ═══════════════════════════════════════════════════════════════════


@click.group(invoke_without_command=True)
@click.option("--verbose", "-v", count=True, help="Verbosity: -v = DEBUG, -vv = TRACE (tool use)")
@click.pass_context
def cli(ctx: click.Context, verbose: int) -> None:
    """Miya — DDD Pentest Agent"""
    if verbose:
        import logging
        level = TRACE if verbose >= 2 else logging.DEBUG
        setup_logging(level_override=level)
    # Store verbose level in context so subcommands (interactive) can access it
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    if ctx.invoked_subcommand is None:
        # Default: launch interactive mode
        ctx.invoke(interactive, db="miya_events.db", model=None, api_key=None, base_url=None)


def _common_options(f: Any) -> Any:
    """Shared --model, --api-key, --base-url options."""
    f = click.option("--model", "-m", default=None, help=_MODEL_HELP)(f)
    f = click.option("--api-key", default=None, help=_KEY_HELP)(f)
    f = click.option("--base-url", default=None, help=_BASE_URL_HELP)(f)
    return f


@cli.command()
@click.option("--target", "-t", required=True, help="Target (IP, URL, CIDR, hostname)")
@click.option("--prompt", "-p", default="", help="Operator instructions for the mission")
@click.option("--source", "-s", default=None, help="Source code path for white-box analysis (optional)")
@click.option("--topology", "-T", default="ooda", type=click.Choice(["ooda", "attack_graph", "fanout"]))
@click.option("--db", default="miya_events.db", help="SQLite database path")
@_common_options
def oneday(target: str, prompt: str, source: str | None, topology: str, db: str, model: str | None, api_key: str | None, base_url: str | None) -> None:
    """Exploit known CVEs (1-day vulnerabilities)"""
    _apply_api_env(api_key, base_url)
    opts: dict[str, Any] = {}
    target_kind = "service"
    if source:
        opts["source_path"] = source
        target_kind = "source"  # white-box: source code provided
    asyncio.run(_run_mission("oneday", target, target_kind, topology, db, model=model or DEFAULT_MODEL, prompt=prompt, **opts))


@cli.command()
@click.option("--target", "-t", required=True, help="Source code path or repo URL")
@click.option("--prompt", "-p", default="", help="Operator instructions for the mission")
@click.option("--service", default=None, help="Live service URL/IP to exploit after analysis (optional)")
@click.option("--language", "-l", default="", help="Programming language hint")
@click.option("--topology", "-T", default="ooda", type=click.Choice(["ooda", "attack_graph", "fanout"]))
@click.option("--db", default="miya_events.db", help="SQLite database path")
@_common_options
def zeroday(target: str, prompt: str, service: str | None, language: str, topology: str, db: str, model: str | None, api_key: str | None, base_url: str | None) -> None:
    """Discover unknown vulnerabilities (0-day)"""
    _apply_api_env(api_key, base_url)
    opts: dict[str, Any] = {"language": language}
    if service:
        opts["service_url"] = service
    asyncio.run(_run_mission("zeroday", target, "source", topology, db, model=model or DEFAULT_MODEL, prompt=prompt, **opts))


def _detect_target_kind(target: str) -> str:
    """Infer the target kind from the URI string."""
    if target.startswith(("http://", "https://")):
        return "url"
    if target.startswith("/") or target.startswith("./") or target.startswith("../"):
        return "binary" if Path(target).suffix in (".elf", ".bin", ".so", "") else "source"
    if Path(target).exists():
        return "binary" if Path(target).suffix in (".elf", ".bin", ".so", "") else "source"
    return "challenge"


@cli.command()
@click.option("--target", "-t", required=True, help="Challenge URL or file path")
@click.option("--prompt", "-p", default="", help="Operator instructions (challenge description, hints, etc.)")
@click.option("--category", "-c", default="", help="Challenge category (web/pwn/crypto/reverse/misc)")
@click.option("--topology", "-T", default="ooda", type=click.Choice(["ooda", "attack_graph", "fanout"]))
@click.option("--db", default="miya_events.db", help="SQLite database path")
@_common_options
def ctf(target: str, prompt: str, category: str, topology: str, db: str, model: str | None, api_key: str | None, base_url: str | None) -> None:
    """Solve CTF challenges"""
    _apply_api_env(api_key, base_url)
    kind = _detect_target_kind(target)
    asyncio.run(_run_mission("ctf", target, kind, topology, db, model=model or DEFAULT_MODEL, prompt=prompt, category=category))


@cli.command()
def info() -> None:
    """Show system information"""
    show_banner()
    console.print(make_mission_table())
    console.print()
    console.print(make_topology_table())
    console.print()
    console.print(make_mcp_table())


@cli.command()
def health() -> None:
    """Verify miya works end-to-end: deps, SDK connectivity, LLM ping."""
    import importlib
    import subprocess
    import miya as _miya_pkg

    console.print(Panel(
        "[bold]Miya Health Check[/bold]",
        border_style="cyan",
        box=box.DOUBLE,
    ))

    checks: list[tuple[str, bool, str]] = []

    # ── Environment ──────────────────────────────────────────────
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 10)
    checks.append(("Python", py_ok, f"{py_ver}" + ("" if py_ok else " (need >=3.10)")))
    checks.append(("Miya", True, _miya_pkg.__version__))

    project_root = str(Path(__file__).resolve().parent.parent)
    checks.append(("Project Root", True, project_root))

    try:
        git_hash = subprocess.check_output(
            ["git", "-C", project_root, "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL, text=True,
        ).strip()
        git_branch = subprocess.check_output(
            ["git", "-C", project_root, "rev-parse", "--abbrev-ref", "HEAD"],
            stderr=subprocess.DEVNULL, text=True,
        ).strip()
        checks.append(("Git", True, f"{git_branch}@{git_hash}"))
    except Exception:
        checks.append(("Git", True, "n/a"))

    # ── Dependencies ─────────────────────────────────────────────
    _deps = [
        ("claude_agent_sdk", "Claude Agent SDK"),
        ("pydantic", "Pydantic"),
        ("rich", "Rich"),
        ("click", "Click"),
        ("aiosqlite", "aiosqlite"),
    ]
    for mod_name, display_name in _deps:
        try:
            mod = importlib.import_module(mod_name)
            ver = getattr(mod, "__version__", "ok")
            checks.append((display_name, True, str(ver)))
        except ImportError:
            checks.append((display_name, False, "not installed"))

    # ── SDK live connectivity test ───────────────────────────────
    # This is the real test: call Claude Agent SDK with a trivial
    # prompt. If the user runs Claude Code locally with built-in
    # auth, this just works — no API key or base_url config needed.
    sdk_ok = False
    sdk_msg = ""
    console.print("[dim]Testing Claude Agent SDK connectivity...[/dim]")
    try:
        sdk_reply = asyncio.run(_health_ping_sdk())
        if sdk_reply:
            sdk_ok = True
            sdk_msg = f"connected ({sdk_reply[:60]})"
        else:
            sdk_msg = "no response from SDK"
    except Exception as exc:
        err = str(exc)
        # Provide actionable hints for common failures
        if "API key" in err or "authentication" in err.lower() or "401" in err:
            sdk_msg = f"auth failed — set ANTHROPIC_API_KEY or run inside Claude Code"
        elif "Connection" in err or "timeout" in err.lower():
            sdk_msg = f"connection failed — check network or ANTHROPIC_BASE_URL"
        else:
            sdk_msg = f"error: {err[:80]}"
    checks.append(("SDK Connectivity", sdk_ok, sdk_msg))

    # ── Render ───────────────────────────────────────────────────
    table = Table(box=box.ROUNDED, border_style="dim")
    table.add_column("Component", style="bold", width=20)
    table.add_column("Status", width=6)
    table.add_column("Detail", style="dim")

    all_ok = True
    for name, ok, detail in checks:
        status = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
        if not ok:
            all_ok = False
        table.add_row(name, status, detail)

    console.print(table)
    console.print()

    if all_ok:
        console.print("[bold green]All checks passed. Miya is ready.[/bold green]")
    else:
        console.print("[bold yellow]Some checks failed. Review the table above.[/bold yellow]")

    raise SystemExit(0 if all_ok else 1)


async def _health_ping_sdk() -> str:
    """Send a trivial prompt to Claude Agent SDK and return the reply text.

    Uses max_turns=1 to keep it cheap and fast.  If the user's environment
    has working auth (local Claude Code, or ANTHROPIC_API_KEY), this succeeds.
    """
    from claude_agent_sdk import query, ClaudeAgentOptions

    options = ClaudeAgentOptions(
        max_turns=1,
        permission_mode="default",
    )

    parts: list[str] = []
    async for message in query(prompt="Reply with exactly: MIYA_OK", options=options):
        if hasattr(message, "content"):
            for block in message.content:
                if hasattr(block, "text"):
                    parts.append(block.text)
    return "".join(parts).strip()


@cli.command()
@click.option("--branch", "-b", default=None, help="Git branch. Default: current branch. Env: MIYA_BRANCH")
def update(branch: str | None) -> None:
    """Pull latest code from git and re-sync dependencies."""
    import subprocess

    # Resolve project root from this package's location (works from any cwd)
    project_root = str(Path(__file__).resolve().parent.parent)

    # Auto-detect: explicit flag > env var > current branch > main
    if branch:
        target_branch = branch
    elif os.environ.get("MIYA_BRANCH", ""):
        target_branch = os.environ["MIYA_BRANCH"]
    else:
        # Default to current branch, fallback to main
        try:
            target_branch = subprocess.check_output(
                ["git", "-C", project_root, "rev-parse", "--abbrev-ref", "HEAD"],
                stderr=subprocess.DEVNULL, text=True,
            ).strip()
        except Exception:
            target_branch = "main"

    # Detect current branch to decide if checkout is needed
    try:
        current_branch = subprocess.check_output(
            ["git", "-C", project_root, "rev-parse", "--abbrev-ref", "HEAD"],
            stderr=subprocess.DEVNULL, text=True,
        ).strip()
    except Exception:
        current_branch = ""

    console.print(f"[cyan]Updating to origin/{target_branch}...[/cyan]")
    console.print(f"[dim]Project: {project_root}[/dim]")

    steps: list[tuple[str, list[str]]] = [
        ("Fetching", ["git", "-C", project_root, "fetch", "origin", target_branch]),
    ]
    if current_branch != target_branch:
        steps.append(
            ("Switching branch", ["git", "-C", project_root, "checkout", target_branch]),
        )
    steps.extend([
        ("Pulling", ["git", "-C", project_root, "pull", "origin", target_branch]),
        ("Syncing deps", ["uv", "sync", "--directory", project_root]),
    ])

    for label, cmd in steps:
        console.print(f"  [dim]{label}...[/dim]", end=" ")
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            console.print("[green]ok[/green]")
        except FileNotFoundError:
            console.print(f"[red]command not found: {cmd[0]}[/red]")
            raise SystemExit(1)
        except subprocess.CalledProcessError as exc:
            console.print("[red]failed[/red]")
            if exc.stderr:
                console.print(f"  [dim]{exc.stderr.strip()}[/dim]")
            raise SystemExit(1)

    # Show new version
    try:
        git_hash = subprocess.check_output(
            ["git", "-C", project_root, "rev-parse", "--short", "HEAD"],
            text=True,
        ).strip()
        console.print(f"\n[bold green]Updated to {target_branch}@{git_hash}[/bold green]")
    except Exception:
        console.print(f"\n[bold green]Updated to {target_branch}.[/bold green]")


@cli.command()
@click.option("--db", default="miya_events.db", help="SQLite database path")
@_common_options
@click.pass_context
def interactive(ctx: click.Context, db: str, model: str | None, api_key: str | None, base_url: str | None) -> None:
    """Interactive REPL mode"""
    _apply_api_env(api_key, base_url)
    asyncio.run(_interactive_loop(db, model=model or DEFAULT_MODEL))


# ═══════════════════════════════════════════════════════════════════
#  Natural Language Mission Parsing
# ═══════════════════════════════════════════════════════════════════


_NL_PARSE_PROMPT = (
    "You are Miya's task parser. The user typed a natural language description of a\n"
    "penetration testing or CTF task.  Your job is to extract structured mission\n"
    "parameters AND runtime directives from their input.\n"
    "\n"
    "Available mission types:\n"
    "- ctf      — Solve a CTF challenge (categories: web, pwn, crypto, reverse, misc)\n"
    "- oneday   — Exploit known CVEs in a target service/software\n"
    "- zeroday  — Discover 0-day vulnerabilities in source code or binaries\n"
    "\n"
    "Available topologies:\n"
    "- ooda          — Observe→Orient→Decide→Act loop with reflection gate (default)\n"
    "- attack_graph  — DAG-based attack path planning\n"
    "- fanout        — parallel solving for multi-challenge CTF competitions\n"
    "\n"
    'Respond EXACTLY in this format (JSON on a single line):\n'
    '{"mission_type": "ctf|oneday|zeroday", "target": "<url_or_path>", '
    '"topology": "ooda|attack_graph|fanout", "prompt": "<task description for the agent>", '
    '"options": {}, "meta": {}, "general_instructions": []}\n'
    "\n"
    "Rules for mission parameters:\n"
    '- "target" should be a URL, IP, file path, or network range extracted from the input\n'
    '- "prompt" should include ONLY challenge-specific context (challenge description, hints, etc.)\n'
    '  Do NOT include general setup commands or runtime directives in "prompt"\n'
    "- If a URL is present, extract it as target\n"
    "- If a file path (.zip, .py, .c, etc.) is present, extract it as target\n"
    '- For CTF, add "category" to options if you can determine it (web/pwn/crypto/reverse/misc)\n'
    "- **Multi-challenge CTF**: If the user provides multiple challenges (any format — JSON,\n"
    "  table, list, natural language), extract each as {name, target_url}. Combine IP+port\n"
    '  into target URLs like "http://IP:PORT". Set topology to "fanout" and add:\n'
    '  "challenges": [{"name": "...", "target": "http://ip:port"}, ...] to options.\n'
    '  Set "target" to the base IP or platform URL.\n'
    "- If you cannot determine mission_type, default to ctf\n"
    "- If you cannot determine topology, use ooda (fanout for multiple challenges)\n"
    "\n"
    'Rules for "general_instructions" (IMPORTANT — separating concerns):\n'
    "- Extract ALL non-CTF commands the user wants executed BEFORE solving challenges.\n"
    "  Examples: git checkout, git reset, branch switching, file cleanup, environment setup,\n"
    "  dependency installation, directory changes, etc.\n"
    '- Each instruction should be a string describing the action, e.g.:\n'
    '  ["switch to bench branch", "discard all uncommitted changes"]\n'
    "- These are executed in a PREPARE phase before any challenge solving begins.\n"
    "- If no general instructions are found, use an empty array [].\n"
    "\n"
    'Rules for "meta" (runtime directives — set ONLY if user explicitly requests):\n'
    '- "verbose": "trace" | "debug" | "info" — log verbosity level.\n'
    "  Use your judgment to infer the user's intent:\n"
    "    trace = most detailed (tool calls, SDK internals, full output)\n"
    "    debug = moderate detail (phase summaries, timing)\n"
    "    info  = normal / quiet\n"
    "  Examples: 详细日志→trace, verbose→trace, debug模式→debug, 安静→info,\n"
    "  看看工具调用→trace, 我想看每一步→trace, show me everything→trace\n"
    '- "model": "opus" | "sonnet" | "haiku" — model override.\n'
    "  Infer from context: 用sonnet→sonnet, fast/快→sonnet, cheap→haiku, etc.\n"
    "- Only include keys in meta that the user explicitly requested. Empty {} if none.\n"
    "\n"
    "Do NOT wrap JSON in markdown code blocks.\n"
    "\n"
    "User input:\n"
)  # User input is appended via concatenation, NOT .format(), to avoid brace issues


def _apply_verbose(level_name: str, cfg: dict[str, Any], console_obj: Any) -> None:
    """Apply a verbose level from NL meta directive."""
    import logging as _logging
    _valid = {"trace": TRACE, "debug": _logging.DEBUG, "info": _logging.INFO,
              "warning": _logging.WARNING, "error": _logging.ERROR}
    level_name = level_name.lower().strip()
    if level_name in _valid:
        setup_logging(level_override=_valid[level_name])
        cfg["verbose"] = level_name
        console_obj.print(f"  [green]Verbose → {level_name}[/green]")


async def _nl_parse_mission(
    raw: str,
    cfg: dict[str, Any],
    console_obj: Any,
    session: Any,
) -> tuple[str, str, str, dict[str, Any]] | None:
    """Use Claude Agent SDK to parse natural language into mission parameters.

    Returns the same tuple as _parse_mission_args, or None if user declines.
    """
    import json as _json

    console_obj.print("[dim]Understanding your request...[/dim]")

    try:
        from claude_agent_sdk import query, ClaudeAgentOptions
        from claude_agent_sdk.types import AssistantMessage, TextBlock

        options = ClaudeAgentOptions(
            max_turns=1,
            permission_mode="default",
        )

        # Concatenate — NOT .format() — to avoid breaking on flag{...} in user input
        prompt_text = _NL_PARSE_PROMPT + raw

        parts: list[str] = []
        async for message in query(
            prompt=prompt_text,
            options=options,
        ):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        parts.append(block.text)

        reply = "".join(parts).strip()

        # Extract JSON from reply (handle possible markdown wrapping)
        json_str = reply
        if "```" in reply:
            # Strip markdown code blocks
            import re
            m = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', reply, re.DOTALL)
            if m:
                json_str = m.group(1).strip()

        data = _json.loads(json_str)

        mission_type = data.get("mission_type", "ctf")
        target = data.get("target", "")
        topology = data.get("topology", cfg.get("topology", "ooda"))
        prompt = data.get("prompt", raw)
        extra_options = data.get("options", {})
        meta = data.get("meta", {})
        general_instructions = data.get("general_instructions", [])

        # Carry general_instructions into options for PREPARE phase
        if general_instructions:
            extra_options["general_instructions"] = general_instructions

        # Validate mission_type — LLM may hallucinate
        if mission_type not in ("oneday", "zeroday", "ctf"):
            console_obj.print(f"[yellow]AI suggested unknown mission '{mission_type}', defaulting to ctf[/yellow]")
            mission_type = "ctf"

        # Meta directives (verbose, model) are applied AFTER user confirmation

        if not target:
            console_obj.print("[red]Could not extract a target from your input.[/red]")
            console_obj.print("[dim]Please specify: <mission_type> <target> [options][/dim]")
            return None

        # ── Build editable fields ────────────────────────────────
        # Mutable dict so interactive edit can modify in place.
        # Complex values (lists, dicts) are stored separately to
        # avoid lossy str() conversion — they are NOT editable via
        # the interactive field editor but are preserved as-is.
        fields: dict[str, str] = {
            "mission":  mission_type,
            "target":   target,
            "topology": topology,
            "model":    meta.get("model") or cfg.get("model", "opus"),
            "verbose":  meta.get("verbose", ""),
            "prompt":   prompt,
        }
        # Complex options (lists/dicts) bypass the string-based editor
        _complex_options: dict[str, Any] = {}
        for k, v in extra_options.items():
            if k.startswith("_"):
                continue
            if isinstance(v, (list, dict)):
                _complex_options[k] = v
            else:
                fields[k] = str(v)

        from prompt_toolkit.formatted_text import HTML

        def _show_fields() -> None:
            """Print numbered field table."""
            console_obj.print()
            idx = 1
            for key, val in fields.items():
                display = val
                if key == "prompt" and len(val) > 80:
                    display = val[:77] + "..."
                style = "bold cyan" if key in ("mission", "target") else "white"
                console_obj.print(
                    f"  [dim]{idx:>2}.[/dim] [bold]{key:.<12s}[/bold] [{style}]{display}[/{style}]"
                )
                idx += 1
            # Show complex options as read-only summaries
            for key, val in _complex_options.items():
                if key == "challenges" and isinstance(val, list):
                    console_obj.print(
                        f"  [dim]{idx:>2}.[/dim] [bold]{key:.<12s}[/bold] "
                        f"[white]{len(val)} challenge(s)[/white]"
                    )
                    for ch in val:
                        if isinstance(ch, dict):
                            console_obj.print(
                                f"       [dim]- {ch.get('name', '?')} → "
                                f"{ch.get('target', '?')}[/dim]"
                            )
                else:
                    console_obj.print(
                        f"  [dim]{idx:>2}.[/dim] [bold]{key:.<12s}[/bold] "
                        f"[white]{val}[/white]"
                    )
                idx += 1

        _show_fields()

        # ── Confirmation loop ─────────────────────────────────────
        while True:
            action = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: session.prompt(
                    HTML(
                        '<ansiyellow><b>y</b></ansiyellow>'
                        '<ansibrightblack>=run, </ansibrightblack>'
                        '<ansiyellow><b>n</b></ansiyellow>'
                        '<ansibrightblack>=cancel, </ansibrightblack>'
                        '<ansiyellow><b>#</b></ansiyellow>'
                        '<ansibrightblack>=edit field </ansibrightblack>'
                        '<ansibrightblack>&gt; </ansibrightblack>'
                    ),
                ),
            )
            action = action.strip().lower()

            if action in ("n", "no", "q"):
                console_obj.print("[dim]Cancelled.[/dim]")
                return None

            if action in ("y", "yes", ""):
                break

            # Try to parse as field number
            try:
                field_idx = int(action)
            except ValueError:
                # Maybe they typed a field name directly
                if action in fields:
                    field_idx = list(fields.keys()).index(action) + 1
                else:
                    console_obj.print(f"[dim]Enter y, n, or a field number (1-{len(fields)})[/dim]")
                    continue

            field_keys = list(fields.keys())
            if field_idx < 1 or field_idx > len(field_keys):
                console_obj.print(f"[dim]Field number must be 1-{len(field_keys)}[/dim]")
                continue

            field_name = field_keys[field_idx - 1]
            current_val = fields[field_name]

            # Special handling for fields with constrained values
            if field_name == "mission":
                hint = " [dim](oneday/zeroday/ctf)[/dim]"
            elif field_name == "topology":
                hint = " [dim](ooda/attack_graph/fanout)[/dim]"
            elif field_name == "model":
                hint = " [dim](opus/sonnet/haiku)[/dim]"
            elif field_name == "verbose":
                hint = " [dim](trace/debug/info or empty)[/dim]"
            else:
                hint = ""

            console_obj.print(f"  [bold]{field_name}[/bold]{hint}")
            new_val = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: session.prompt(
                    HTML(f'<ansibrightblack>  new value &gt; </ansibrightblack>'),
                    default=current_val,
                ),
            )
            new_val = new_val.strip()

            # Validate constrained fields
            if field_name == "mission" and new_val not in ("oneday", "zeroday", "ctf"):
                console_obj.print("[red]Must be oneday, zeroday, or ctf[/red]")
                continue
            if field_name == "topology" and new_val not in ("ooda", "attack_graph", "fanout"):
                console_obj.print("[red]Must be ooda, attack_graph, or fanout[/red]")
                continue
            if field_name == "model" and new_val not in ("opus", "sonnet", "haiku"):
                console_obj.print("[red]Must be opus, sonnet, or haiku[/red]")
                continue
            if field_name == "verbose" and new_val and new_val not in ("trace", "debug", "info"):
                console_obj.print("[red]Must be trace, debug, info, or empty[/red]")
                continue
            if field_name == "target" and not new_val:
                console_obj.print("[red]Target cannot be empty[/red]")
                continue

            fields[field_name] = new_val
            _show_fields()

        # ── User confirmed — apply meta & build result ────────────
        mission_type = fields["mission"]
        target = fields["target"]
        topology = fields["topology"]
        prompt = fields["prompt"]

        if fields.get("verbose"):
            _apply_verbose(fields["verbose"], cfg, console_obj)

        opts: dict[str, Any] = {}
        if fields.get("model"):
            opts["_model_override"] = fields["model"]
        if prompt:
            opts["_prompt"] = prompt

        # Carry over extra option fields (category, language, etc.)
        _core_fields = {"mission", "target", "topology", "model", "verbose", "prompt"}
        for k, v in fields.items():
            if k not in _core_fields and v:
                opts[k] = v
        # Restore complex options (lists/dicts) that bypassed the editor
        opts.update(_complex_options)

        opts["_nl_confirmed"] = True
        return mission_type, target, topology, opts

    except ImportError:
        console_obj.print("[red]Claude Agent SDK not available for NL parsing.[/red]")
        return None
    except _json.JSONDecodeError:
        console_obj.print("[red]Could not parse AI response. Please use structured format:[/red]")
        console_obj.print("[dim]  <mission_type> <target> [--prompt <text>] [--topology <t>][/dim]")
        return None
    except Exception as e:
        console_obj.print(f"[red]NL parse error: {e}[/red]")
        console_obj.print("[dim]Please use structured format: <mission_type> <target> [options][/dim]")
        return None


# ═══════════════════════════════════════════════════════════════════
#  Core Execution
# ═══════════════════════════════════════════════════════════════════


async def _run_mission(
    mission_type: str,
    target: str,
    target_kind: str,
    topology: str,
    db: str,
    model: str = "opus",
    prompt: str = "",
    **options: Any,
) -> None:
    from miya.mission.service import MissionService

    show_banner()

    panel_lines = [
        f"[bold]Mission:[/bold] {mission_type.upper()}",
        f"[bold]Target:[/bold]  {target}",
        f"[bold]Topology:[/bold] {topology}",
        f"[bold]Model:[/bold]   {model}",
    ]
    if prompt:
        panel_lines.append(f"[bold]Prompt:[/bold]  {prompt[:80]}")
    if options:
        panel_lines.append(f"[bold]Options:[/bold] {options}")
    console.print(Panel(
        "\n".join(panel_lines),
        title="[bold cyan]Mission Configuration[/bold cyan]",
        border_style="cyan",
    ))

    service = await MissionService.create(db_path=db)

    try:
        with Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold blue]{task.description}[/bold blue]"),
            console=console,
        ) as progress:
            task = progress.add_task("Executing mission...", total=None)

            report = await service.execute(
                mission_type=mission_type,
                target_uri=target,
                target_kind=target_kind,
                topology=topology,
                model=model,
                prompt=prompt,
                **options,
            )

            progress.update(task, completed=True, description="Mission complete!")

        console.print()
        print_report(report)

    except Exception as e:
        console.print(f"[bold red]Mission failed:[/bold red] {e}")
        raise
    finally:
        await service.close()


async def _interactive_loop(db: str, model: str = "opus") -> None:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.formatted_text import HTML

    from miya.mission.service import MissionService, MissionReport
    from miya.shared.blackboard import Blackboard
    from miya.shared.events import DomainEvent
    from miya.topology.base import TopologyRegistry

    show_banner()
    console.print(make_mission_table())
    console.print()

    # ── Runtime state ──────────────────────────────────────────────
    import logging as _logging
    _current_level = _logging.getLogger("miya").level
    _level_names = {_logging.CRITICAL: "critical", _logging.ERROR: "error",
                    _logging.WARNING: "warning", _logging.INFO: "info",
                    _logging.DEBUG: "debug", TRACE: "trace"}
    cfg: dict[str, Any] = {"model": model, "topology": "ooda",
                           "verbose": _level_names.get(_current_level, "info")}
    mission_history: list[MissionReport] = []

    # ── Prompt toolkit session with history + completion ──────────
    history_path = Path.home() / ".miya_history"
    completer = WordCompleter(
        [
            # missions
            "oneday", "zeroday", "ctf",
            # repl
            "set", "status", "history", "events", "blackboard", "campaign",
            "report", "export", "replay", "info", "clear", "help",
            "exit", "quit",
            # options
            "--topology", "--category", "--language", "--source", "--service", "--prompt",
            # set targets
            "model", "topology", "api_key", "base_url", "verbose",
            # values
            "opus", "sonnet", "haiku", "ooda", "attack_graph", "fanout",
            "info", "debug", "trace",
            # categories
            "web", "pwn", "crypto", "reverse", "misc",
        ],
        ignore_case=True,
    )
    session: PromptSession[str] = PromptSession(
        history=FileHistory(str(history_path)),
        completer=completer,
        complete_while_typing=False,
    )

    def _prompt_html() -> HTML:
        return HTML(
            f'<ansired><b>miya</b></ansired> '
            f'<ansibrightblack>({cfg["model"]})</ansibrightblack> '
            f'<ansibrightblack>&gt;</ansibrightblack> '
        )

    # ── Event severity coloring ───────────────────────────────────
    _EVENT_STYLES: dict[str, str] = {
        "ExploitSucceeded": "bold green",
        "ExploitFailed": "red",
        "VulnerabilityFound": "bold yellow",
        "CVEMatched": "bold yellow",
        "ExploitAttempted": "cyan",
        "AssetDiscovered": "blue",
        "ChallengeSolved": "bold green",
        "PoCValidated": "bold green",
        "SinkConfirmed": "bold yellow",
        "PrivilegeEscalated": "bold magenta",
        "MissionFailed": "bold red",
        "PhaseTransition": "dim",
    }

    def _truncate(text: str, maxlen: int) -> str:
        """Truncate with ellipsis indicator."""
        return text if len(text) <= maxlen else text[:maxlen - 1] + "…"

    def _event_detail(ev: DomainEvent) -> str:
        for attr in ("cve_id", "vulnerability", "host", "ip", "software",
                      "title", "challenge_name", "technique", "phase"):
            val = getattr(ev, attr, None)
            if val:
                return str(val)
        return ""

    # ── Help ──────────────────────────────────────────────────────
    def _print_help() -> None:
        console.print(make_mission_table())
        console.print(make_topology_table())
        console.print()
        t = Table(title="REPL Commands", box=box.SIMPLE, title_style="bold cyan")
        t.add_column("Command", style="bold green", width=40)
        t.add_column("Description", style="white")
        t.add_row("oneday <target> [opts]", "Exploit known CVEs")
        t.add_row("zeroday <target> [opts]", "Discover 0-day vulnerabilities")
        t.add_row("ctf <target> [opts]", "Solve CTF challenge")
        t.add_row("", "")
        t.add_row("[dim]Mission options:[/dim]", "")
        t.add_row("  --prompt/-p <text>", "Operator instructions / context")
        t.add_row("  --topology/-T <topo>", "ooda, attack_graph, or fanout")
        t.add_row("  --category/-c <cat>", "CTF: web/pwn/crypto/reverse/misc")
        t.add_row("  --language/-l <lang>", "Language hint (zeroday)")
        t.add_row("  --source/-s <path>", "Source code path (oneday white-box)")
        t.add_row('  --service <url>', "Live service URL (zeroday PoC)")
        t.add_row("", "")
        t.add_row("[dim]Session:[/dim]", "")
        t.add_row("set model <m>", "Switch model (opus/sonnet/haiku)")
        t.add_row("set topology <t>", "Set default topology")
        t.add_row("set verbose <level>", "Log level: info/debug/trace")
        t.add_row("set api_key <key>", "Set Anthropic API key")
        t.add_row("set base_url <url>", "Set Anthropic base URL")
        t.add_row("status", "Current config & session stats")
        t.add_row("", "")
        t.add_row("[dim]Review:[/dim]", "")
        t.add_row("history", "Mission history")
        t.add_row("report [n]", "Re-view report #n (default: last)")
        t.add_row("export [n] <file>", "Export report to file")
        t.add_row("replay [n]", "Re-run mission #n with same params")
        t.add_row("events [n]", "Last n domain events (default: 20)")
        t.add_row("blackboard", "Current blackboard state")
        t.add_row("campaign", "Cross-mission knowledge (solved, infra, techniques)")
        t.add_row("", "")
        t.add_row("[dim]Natural Language:[/dim]", "")
        t.add_row("<free text description>", "AI parses intent, confirms before run")
        t.add_row("", "")
        t.add_row("[dim]Other:[/dim]", "")
        t.add_row("info", "MCP server info")
        t.add_row("clear", "Clear screen")
        t.add_row("exit / quit / q / Ctrl+D", "Exit")
        console.print(t)

    # ── Status ────────────────────────────────────────────────────
    def _print_status(event_count: int) -> None:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        key_status = f"[green]set ({api_key[:8]}...)[/green]" if api_key else "[red]not set[/red]"
        base_url = os.environ.get("ANTHROPIC_BASE_URL", "")
        url_display = f"[green]{base_url}[/green]" if base_url else "[dim]default[/dim]"
        console.print(Panel(
            f"[bold]Model:[/bold]     {cfg['model']}\n"
            f"[bold]Topology:[/bold]  {cfg['topology']}\n"
            f"[bold]Verbose:[/bold]   {cfg['verbose']}\n"
            f"[bold]API Key:[/bold]   {key_status}\n"
            f"[bold]Base URL:[/bold]  {url_display}\n"
            f"[bold]DB:[/bold]        {db}\n"
            f"[bold]Events:[/bold]    {event_count}\n"
            f"[bold]Missions:[/bold]  {len(mission_history)}",
            title="[bold cyan]Session Status[/bold cyan]",
            border_style="cyan",
        ))

    # ── Parse mission args (shlex for quoted paths) ───────────────
    def _parse_mission_args(raw: str) -> tuple[str, str, str, dict[str, Any]] | None:
        """Parse structured mission command. Returns None silently for NL fallback.

        Only succeeds when ALL tokens are recognized structured options.
        If any free-text (non-option) tokens are found after <target>,
        returns None so the NL parser handles the full input.
        """
        try:
            parts = shlex.split(raw)
        except ValueError:
            return None  # let NL parser handle malformed input

        if len(parts) < 2:
            return None  # too short for structured format

        mission_type = parts[0]

        # Only parse if first word is a known mission type
        if mission_type not in ("oneday", "zeroday", "ctf"):
            return None  # fall through to NL parser

        target = parts[1]
        topology = cfg["topology"]
        options: dict[str, Any] = {}

        # Pre-scan: if any token after target is NOT a recognized flag,
        # this is free-text input — route to NL parser.
        _KNOWN_FLAGS = {
            "--topology", "-T", "--category", "-c", "--language", "-l",
            "--source", "-s", "--service", "--prompt", "-p", "--model", "-m",
        }
        i = 2
        while i < len(parts):
            tok = parts[i]
            if tok in _KNOWN_FLAGS:
                i += 2  # skip flag + value
            else:
                # Found free-text after target — fall through to NL parser
                return None
        # All tokens are structured flags — parse normally
        i = 2
        while i < len(parts):
            if parts[i] in ("--topology", "-T") and i + 1 < len(parts):
                topology = parts[i + 1]
                i += 2
            elif parts[i] in ("--category", "-c") and i + 1 < len(parts):
                options["category"] = parts[i + 1]
                i += 2
            elif parts[i] in ("--language", "-l") and i + 1 < len(parts):
                options["language"] = parts[i + 1]
                i += 2
            elif parts[i] in ("--source", "-s") and i + 1 < len(parts):
                options["source_path"] = parts[i + 1]
                i += 2
            elif parts[i] == "--service" and i + 1 < len(parts):
                options["service_url"] = parts[i + 1]
                i += 2
            elif parts[i] in ("--prompt", "-p") and i + 1 < len(parts):
                options["_prompt"] = parts[i + 1]
                i += 2
            elif parts[i] in ("--model", "-m") and i + 1 < len(parts):
                options["_model_override"] = parts[i + 1]
                i += 2
            else:
                i += 1

        if topology not in TopologyRegistry.available():
            available = ", ".join(TopologyRegistry.available())
            console.print(f"[red]Unknown topology: {topology}[/red]")
            console.print(f"[dim]Available: {available}[/dim]")
            return None

        return mission_type, target, topology, options

    # ── Get report by index ───────────────────────────────────────
    def _get_report(arg: str = "") -> MissionReport | None:
        if not mission_history:
            console.print("[dim]No missions executed yet.[/dim]")
            return None
        idx = len(mission_history)  # default: last
        if arg.strip():
            try:
                idx = int(arg.strip())
            except ValueError:
                console.print(f"[red]Invalid index: {arg}[/red]")
                return None
        if idx < 1 or idx > len(mission_history):
            console.print(f"[red]Index out of range (1-{len(mission_history)})[/red]")
            return None
        return mission_history[idx - 1]

    _print_help()
    console.print()

    service = await MissionService.create(db_path=db)

    try:
        while True:
            try:
                raw = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: session.prompt(_prompt_html())
                )
                raw = raw.strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Goodbye.[/dim]")
                break

            if not raw:
                continue

            lower = raw.lower()
            parts = lower.split()
            cmd = parts[0] if parts else ""

            # ── Exit ──────────────────────────────────────────────
            if cmd in ("exit", "quit", "q"):
                console.print("[dim]Goodbye.[/dim]")
                break

            # ── Clear ─────────────────────────────────────────────
            if cmd == "clear":
                console.clear()
                show_banner()
                continue

            # ── Help ──────────────────────────────────────────────
            if cmd == "help":
                _print_help()
                continue

            # ── Info ──────────────────────────────────────────────
            if cmd == "info":
                console.print(make_mcp_table())
                continue

            # ── Status ────────────────────────────────────────────
            if cmd == "status":
                event_count = await service._event_store.count() if service._event_store else 0
                _print_status(event_count)
                continue

            # ── Events ────────────────────────────────────────────
            if cmd == "events":
                if service._event_store:
                    # Parse optional count: events [n]
                    ev_parts = raw.split()
                    limit = 20
                    if len(ev_parts) > 1:
                        try:
                            limit = int(ev_parts[1])
                        except ValueError:
                            pass
                    all_ev = await service._event_store.load_all()
                    if not all_ev:
                        console.print("[dim]No events recorded yet.[/dim]")
                    else:
                        table = Table(
                            title=f"Domain Events (showing last {min(limit, len(all_ev))} of {len(all_ev)})",
                            box=box.SIMPLE, title_style="bold",
                        )
                        table.add_column("#", style="dim", width=4)
                        table.add_column("Type", style="bold cyan", width=25)
                        table.add_column("Context", style="yellow", width=10)
                        table.add_column("Time", style="dim", width=20)
                        table.add_column("Details", style="white", max_width=50)
                        for i, ev in enumerate(all_ev[-limit:], len(all_ev) - limit + 1):
                            style = _EVENT_STYLES.get(type(ev).__name__, "")
                            name = type(ev).__name__
                            if style:
                                name = f"[{style}]{name}[/{style}]"
                            table.add_row(
                                str(i),
                                name,
                                getattr(ev, "context", ""),
                                str(getattr(ev, "timestamp", ""))[:19],
                                _truncate(_event_detail(ev), 50),
                            )
                        console.print(table)
                continue

            # ── Blackboard ────────────────────────────────────────
            if cmd == "blackboard":
                if service._event_store:
                    bb = Blackboard()
                    all_ev = await service._event_store.load_all()
                    bb.apply_all(all_ev)
                    summary = bb.summary()
                    if not any(summary.values()):
                        console.print("[dim]Blackboard is empty.[/dim]")
                    else:
                        console.print(Panel(
                            f"[bold]Assets:[/bold]          {summary.get('assets', 0)}\n"
                            f"[bold]Findings:[/bold]        {summary.get('findings', 0)}\n"
                            f"[bold]CVE Matches:[/bold]     {summary.get('cve_matches', 0)}\n"
                            f"[bold]Exploits:[/bold]        {summary.get('exploit_attempts', 0)}\n"
                            f"[bold]Access Level:[/bold]    {summary.get('access_level', 'none')}\n"
                            f"[bold]Credentials:[/bold]     {summary.get('credentials', 0)}\n"
                            + (f"[bold]Attack Graph:[/bold]\n{summary.get('attack_graph', '')}"
                               if summary.get('attack_graph') else ""),
                            title="[bold cyan]Blackboard State[/bold cyan]",
                            border_style="cyan",
                        ))
                continue

            # ── Campaign (cross-mission knowledge) ────────────────
            if cmd == "campaign":
                camp = service.campaign
                if not camp.entries:
                    console.print("[dim]Campaign is empty. Solve some challenges first.[/dim]")
                else:
                    solved = camp.get_solved()
                    infra = camp.get_by_category("infra")
                    techniques = camp.get_by_category("technique")
                    parts = []
                    if solved:
                        parts.append(f"[bold]Solved ({len(solved)}):[/bold]")
                        for s in solved:
                            parts.append(f"  {s['name']}: {s.get('technique', '?')}")
                    if infra:
                        parts.append(f"\n[bold]Infrastructure ({len(infra)}):[/bold]")
                        for e in infra[-10:]:
                            parts.append(f"  {e.key.removeprefix('infra:')}: {e.value[:60]}")
                    if techniques:
                        parts.append(f"\n[bold]Techniques ({len(techniques)}):[/bold]")
                        for e in techniques[-10:]:
                            parts.append(f"  {e.key.removeprefix('technique:')}: {e.value[:60]}")
                    console.print(Panel(
                        "\n".join(parts),
                        title="[bold cyan]Campaign Knowledge[/bold cyan]",
                        border_style="cyan",
                    ))
                continue

            # ── History ───────────────────────────────────────────
            if cmd == "history":
                if not mission_history:
                    console.print("[dim]No missions executed yet.[/dim]")
                else:
                    table = Table(title="Mission History", box=box.SIMPLE, title_style="bold")
                    table.add_column("#", style="dim", width=3)
                    table.add_column("Type", style="bold green", width=10)
                    table.add_column("Target", style="white", width=30)
                    table.add_column("Topo", style="yellow", width=12)
                    table.add_column("Status", width=10)
                    table.add_column("Findings", style="yellow", width=10)
                    table.add_column("Duration", style="dim", width=10)
                    for idx, r in enumerate(mission_history, 1):
                        sc = "green" if r.status == "completed" else "red"
                        table.add_row(
                            str(idx),
                            r.mission_type,
                            r.target[:30],
                            r.topology,
                            f"[{sc}]{r.status}[/{sc}]",
                            f"{r.critical_count}C/{len(r.findings)}T",
                            f"{r.duration_seconds:.1f}s",
                        )
                    console.print(table)
                continue

            # ── Report [n] ────────────────────────────────────────
            if cmd == "report":
                arg = raw[len("report"):].strip()
                r = _get_report(arg)
                if r:
                    print_report(r)
                continue

            # ── Export [n] <file> ──────────────────────────────────
            if cmd == "export":
                ex_parts = raw.split(None, 2)
                if len(ex_parts) < 2:
                    console.print("[yellow]Usage: export [n] <file>[/yellow]")
                    continue
                # Determine if first arg is index or filename
                report_idx = ""
                filename = ""
                if len(ex_parts) == 2:
                    # export <file> → export last report
                    filename = ex_parts[1]
                elif len(ex_parts) == 3:
                    report_idx = ex_parts[1]
                    filename = ex_parts[2]
                r = _get_report(report_idx)
                if r:
                    try:
                        Path(filename).write_text(r.as_text(), encoding="utf-8")
                        console.print(f"[green]Report exported to: {filename}[/green]")
                    except OSError as e:
                        console.print(f"[red]Export failed: {e}[/red]")
                continue

            # ── Replay [n] ───────────────────────────────────────
            if cmd == "replay":
                arg = raw[len("replay"):].strip()
                r = _get_report(arg)
                if r:
                    console.print(f"[cyan]Replaying mission #{arg or len(mission_history)}: "
                                  f"{r.mission_type} → {r.target}[/cyan]")
                    # Reconstruct full command from preserved parameters
                    replay_parts = [r.mission_type, r.target]
                    if r.topology and r.topology != "ooda":
                        replay_parts.extend(["--topology", r.topology])
                    if r.prompt:
                        replay_parts.extend(["--prompt", r.prompt])
                    if r.model and r.model != cfg.get("model", "opus"):
                        replay_parts.extend(["--model", r.model])
                    replay_raw = " ".join(replay_parts)
                    # Fall through to mission execution below
                    raw = replay_raw
                    lower = raw.lower()
                    cmd = lower.split()[0]
                else:
                    continue

            # ── Set ───────────────────────────────────────────────
            if cmd == "set":
                set_parts = raw.split(None, 2)
                if len(set_parts) == 3:
                    key, val = set_parts[1].lower(), set_parts[2]
                    if key == "model":
                        if val.lower() in ("opus", "sonnet", "haiku"):
                            cfg["model"] = val.lower()
                            console.print(f"[green]Model → {val.lower()}[/green]")
                        else:
                            console.print("[red]Use 'opus', 'sonnet', or 'haiku'.[/red]")
                    elif key == "topology":
                        if val in ("ooda", "attack_graph", "fanout"):
                            cfg["topology"] = val
                            console.print(f"[green]Topology → {val}[/green]")
                        else:
                            console.print("[red]Use 'ooda', 'attack_graph', or 'fanout'.[/red]")
                    elif key == "verbose":
                        val_lower = val.lower()
                        _valid_levels = {"info": _logging.INFO, "debug": _logging.DEBUG, "trace": TRACE,
                                         "warning": _logging.WARNING, "error": _logging.ERROR}
                        if val_lower in _valid_levels:
                            setup_logging(level_override=_valid_levels[val_lower])
                            cfg["verbose"] = val_lower
                            console.print(f"[green]Verbose → {val_lower}[/green]")
                        else:
                            console.print(f"[red]Use: info, debug, trace (or warning, error)[/red]")
                    elif key == "api_key":
                        os.environ["ANTHROPIC_API_KEY"] = val
                        console.print(f"[green]API key → {val[:8]}...[/green]")
                    elif key == "base_url":
                        os.environ["ANTHROPIC_BASE_URL"] = val
                        console.print(f"[green]Base URL → {val}[/green]")
                    else:
                        console.print(f"[red]Unknown: {key}. Try: model, topology, verbose, api_key, base_url[/red]")
                else:
                    console.print("[yellow]Usage: set <key> <value>[/yellow]")
                continue

            # ── Mission execution ─────────────────────────────────
            parsed = _parse_mission_args(raw)
            if parsed is None:
                # Not a structured command — try natural language understanding
                nl_result = await _nl_parse_mission(raw, cfg, console, session)
                if nl_result is None:
                    continue
                parsed = nl_result

            mission_type, target, topology, options = parsed
            mission_model = options.pop("_model_override", cfg["model"])
            mission_prompt = options.pop("_prompt", "")
            nl_confirmed = options.pop("_nl_confirmed", False)

            kind_map = {"oneday": "service", "zeroday": "source"}
            target_kind = kind_map.get(mission_type, _detect_target_kind(target))

            # Skip panel if NL parser already showed a confirmed "Proposed Mission" panel
            if not nl_confirmed:
                panel_lines = [
                    f"[bold]Mission:[/bold]  {mission_type.upper()}",
                    f"[bold]Target:[/bold]   {target}",
                    f"[bold]Topology:[/bold] {topology}",
                    f"[bold]Model:[/bold]    {mission_model}",
                ]
                if mission_prompt:
                    panel_lines.append(f"[bold]Prompt:[/bold]  {mission_prompt[:80]}")
                if options:
                    panel_lines.append(f"[bold]Options:[/bold]  {options}")
                console.print(Panel(
                    "\n".join(panel_lines),
                    title="[bold cyan]Launching Mission[/bold cyan]",
                    border_style="cyan",
                ))

            # Live event table during execution
            live_events: list[DomainEvent] = []

            def _on_event(ev: DomainEvent) -> None:
                live_events.append(ev)
                name = type(ev).__name__
                style = _EVENT_STYLES.get(name, "dim")
                detail = _event_detail(ev)
                console.print(
                    f"  [{style}]{name:.<30s}[/{style}] "
                    f"[dim]{getattr(ev, 'context', ''):>10s}[/dim]  "
                    f"{detail[:60]}",
                )

            # Create HITL operator queue
            import asyncio as _aio
            import threading
            op_queue: _aio.Queue[str] = _aio.Queue()
            loop = asyncio.get_event_loop()

            async def _execute_mission() -> MissionReport:
                return await service.execute(
                    mission_type=mission_type,
                    target_uri=target,
                    target_kind=target_kind,
                    topology=topology,
                    model=mission_model,
                    prompt=mission_prompt,
                    on_event=_on_event,
                    operator_queue=op_queue,
                    **options,
                )

            # Thread-safe HITL input: one dedicated thread reads stdin,
            # posts to an asyncio.Queue, and exits when stop_event is set.
            # IMPORTANT: Use a SEPARATE PromptSession — prompt_toolkit's
            # PromptSession is not thread-safe for concurrent .prompt() calls.
            hitl_queue: _aio.Queue[str] = _aio.Queue()
            stop_input = threading.Event()

            def _hitl_reader() -> None:
                """Blocking input reader running in a dedicated thread."""
                # Separate session avoids concurrent .prompt() on main session
                from prompt_toolkit import PromptSession as _PS
                from prompt_toolkit.formatted_text import HTML as _HTML
                hitl_session: _PS[str] = _PS()
                while not stop_input.is_set():
                    try:
                        text = hitl_session.prompt(
                            _HTML(
                                '<ansiyellow><b>hitl</b></ansiyellow> '
                                '<ansibrightblack>&gt;</ansibrightblack> '
                            ),
                        )
                        text = text.strip()
                        if text and not stop_input.is_set():
                            loop.call_soon_threadsafe(hitl_queue.put_nowait, text)
                    except (EOFError, KeyboardInterrupt):
                        break

            try:
                console.print("[dim]── Events (type to inject HITL, Ctrl+C to cancel) ──[/dim]")
                mission_task = _aio.create_task(_execute_mission())

                # Start HITL reader in a daemon thread (exits with process)
                input_thread = threading.Thread(
                    target=_hitl_reader, daemon=True, name="hitl-reader",
                )
                input_thread.start()

                # Main loop: transfer hitl_queue → op_queue, wait for mission
                while not mission_task.done():
                    # Wait a bit, then drain any HITL input
                    await _aio.sleep(0.3)
                    while not hitl_queue.empty():
                        try:
                            msg = hitl_queue.get_nowait()
                            op_queue.put_nowait(msg)
                            console.print(f"  [yellow]📨 queued:[/yellow] {msg[:80]}")
                        except _aio.QueueEmpty:
                            break

                # Signal input thread to stop (it will exit on next prompt or EOFError)
                stop_input.set()

                report = await mission_task
                console.print(f"[dim]── {len(live_events)} events ──[/dim]")
                console.print()
                print_report(report)
                mission_history.append(report)
                if report.error:
                    console.print(f"[yellow]Mission ended with error: {report.error}[/yellow]")

            except KeyboardInterrupt:
                console.print("\n[yellow]Mission cancelled by user.[/yellow]")
                stop_input.set()
                if not mission_task.done():
                    mission_task.cancel()
                    try:
                        await mission_task
                    except (asyncio.CancelledError, Exception):
                        pass
            except Exception as e:
                console.print(f"[bold red]Error:[/bold red] {e}")
                stop_input.set()

            console.print()

    finally:
        await service.close()


if __name__ == "__main__":
    cli()
