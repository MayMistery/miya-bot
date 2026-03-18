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
@click.option("--source", "-s", default=None, help="Source code path for white-box analysis (optional)")
@click.option("--topology", "-T", default="ooda", type=click.Choice(["ooda", "attack_graph"]))
@click.option("--db", default="miya_events.db", help="SQLite database path")
@_common_options
def oneday(target: str, source: str | None, topology: str, db: str, model: str | None, api_key: str | None, base_url: str | None) -> None:
    """Exploit known CVEs (1-day vulnerabilities)"""
    _apply_api_env(api_key, base_url)
    opts: dict[str, Any] = {}
    if source:
        opts["source_path"] = source
    asyncio.run(_run_mission("oneday", target, "service", topology, db, model=model or DEFAULT_MODEL, **opts))


@cli.command()
@click.option("--target", "-t", required=True, help="Source code path or repo URL")
@click.option("--service", default=None, help="Live service URL/IP to exploit after analysis (optional)")
@click.option("--language", "-l", default="", help="Programming language hint")
@click.option("--topology", "-T", default="ooda", type=click.Choice(["ooda", "attack_graph"]))
@click.option("--db", default="miya_events.db", help="SQLite database path")
@_common_options
def zeroday(target: str, service: str | None, language: str, topology: str, db: str, model: str | None, api_key: str | None, base_url: str | None) -> None:
    """Discover unknown vulnerabilities (0-day)"""
    _apply_api_env(api_key, base_url)
    opts: dict[str, Any] = {"language": language}
    if service:
        opts["service_url"] = service
    asyncio.run(_run_mission("zeroday", target, "source", topology, db, model=model or DEFAULT_MODEL, **opts))


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
@click.option("--category", "-c", default="", help="Challenge category (web/pwn/crypto/reverse/misc)")
@click.option("--topology", "-T", default="ooda", type=click.Choice(["ooda", "attack_graph"]))
@click.option("--db", default="miya_events.db", help="SQLite database path")
@_common_options
def ctf(target: str, category: str, topology: str, db: str, model: str | None, api_key: str | None, base_url: str | None) -> None:
    """Solve CTF challenges"""
    _apply_api_env(api_key, base_url)
    kind = _detect_target_kind(target)
    asyncio.run(_run_mission("ctf", target, kind, topology, db, model=model or DEFAULT_MODEL, category=category))


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

    # Auto-detect: explicit flag > env var > current git branch
    target_branch = branch or os.environ.get("MIYA_BRANCH", "")
    if not target_branch:
        try:
            target_branch = subprocess.check_output(
                ["git", "-C", project_root, "rev-parse", "--abbrev-ref", "HEAD"],
                stderr=subprocess.DEVNULL, text=True,
            ).strip()
        except Exception:
            target_branch = "main"

    console.print(f"[cyan]Updating from origin/{target_branch}...[/cyan]")
    console.print(f"[dim]Project: {project_root}[/dim]")

    steps = [
        ("Fetching", ["git", "-C", project_root, "fetch", "origin", target_branch]),
        ("Pulling", ["git", "-C", project_root, "pull", "origin", target_branch]),
        ("Syncing deps", ["uv", "sync", "--directory", project_root]),
    ]

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
        console.print(f"\n[bold green]Updated to {git_hash}[/bold green]")
    except Exception:
        console.print("\n[bold green]Update complete.[/bold green]")


@cli.command()
@click.option("--db", default="miya_events.db", help="SQLite database path")
@_common_options
@click.pass_context
def interactive(ctx: click.Context, db: str, model: str | None, api_key: str | None, base_url: str | None) -> None:
    """Interactive REPL mode"""
    _apply_api_env(api_key, base_url)
    asyncio.run(_interactive_loop(db, model=model or DEFAULT_MODEL))


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
    **options: Any,
) -> None:
    from miya.mission.service import MissionService

    show_banner()

    console.print(Panel(
        f"[bold]Mission:[/bold] {mission_type.upper()}\n"
        f"[bold]Target:[/bold]  {target}\n"
        f"[bold]Topology:[/bold] {topology}\n"
        f"[bold]Model:[/bold]   {model}\n"
        + (f"[bold]Options:[/bold] {options}" if options else ""),
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
            "set", "status", "history", "events", "blackboard",
            "report", "export", "replay", "info", "clear", "help",
            "exit", "quit",
            # options
            "--topology", "--category", "--language", "--source", "--service",
            # set targets
            "model", "topology", "api_key", "base_url", "verbose",
            # values
            "opus", "sonnet", "haiku", "ooda", "attack_graph",
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
        t.add_row("  --topology/-T <topo>", "ooda or attack_graph")
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
        try:
            parts = shlex.split(raw)
        except ValueError as e:
            console.print(f"[red]Parse error: {e}[/red]")
            return None

        if len(parts) < 2:
            console.print("[yellow]Usage: <mission> <target> [options][/yellow]")
            return None

        mission_type = parts[0]
        target = parts[1]
        topology = cfg["topology"]
        options: dict[str, Any] = {}

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
            elif parts[i] in ("--model", "-m") and i + 1 < len(parts):
                # per-mission model override
                options["_model_override"] = parts[i + 1]
                i += 2
            else:
                console.print(f"[yellow]Unknown option: {parts[i]}[/yellow]")
                i += 1

        if mission_type not in ("oneday", "zeroday", "ctf"):
            console.print(f"[red]Unknown mission: {mission_type}[/red]")
            console.print("[dim]Available: oneday, zeroday, ctf. Type 'help'.[/dim]")
            return None

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
                    # Re-construct the raw command
                    replay_raw = f"{r.mission_type} {r.target}"
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
                        cfg["model"] = val
                        console.print(f"[green]Model → {val}[/green]")
                    elif key == "topology":
                        if val in ("ooda", "attack_graph"):
                            cfg["topology"] = val
                            console.print(f"[green]Topology → {val}[/green]")
                        else:
                            console.print("[red]Use 'ooda' or 'attack_graph'.[/red]")
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
                continue

            mission_type, target, topology, options = parsed
            mission_model = options.pop("_model_override", cfg["model"])

            kind_map = {"oneday": "service", "zeroday": "source", "ctf": "challenge"}

            console.print(Panel(
                f"[bold]Mission:[/bold]  {mission_type.upper()}\n"
                f"[bold]Target:[/bold]   {target}\n"
                f"[bold]Topology:[/bold] {topology}\n"
                f"[bold]Model:[/bold]    {mission_model}"
                + (f"\n[bold]Options:[/bold]  {options}" if options else ""),
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

            try:
                console.print("[dim]── Events ──[/dim]")
                report = await service.execute(
                    mission_type=mission_type,
                    target_uri=target,
                    target_kind=kind_map[mission_type],
                    topology=topology,
                    model=mission_model,
                    on_event=_on_event,
                    **options,
                )
                console.print(f"[dim]── {len(live_events)} events ──[/dim]")
                console.print()
                print_report(report)
                mission_history.append(report)
                if report.error:
                    console.print(f"[yellow]Mission ended with error: {report.error}[/yellow]")

            except KeyboardInterrupt:
                console.print("\n[yellow]Mission cancelled by user.[/yellow]")
            except Exception as e:
                console.print(f"[bold red]Error:[/bold red] {e}")

            console.print()

    finally:
        await service.close()


if __name__ == "__main__":
    cli()
