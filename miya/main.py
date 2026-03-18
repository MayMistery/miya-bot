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
import sys
from typing import Any

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
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Miya — DDD Pentest Agent"""
    if ctx.invoked_subcommand is None:
        show_banner()
        console.print(make_mission_table())
        console.print()
        console.print(make_topology_table())
        console.print()
        console.print("[dim]Usage: miya <mission> --target <target> [--topology ooda|attack_graph][/dim]")
        console.print("[dim]       miya interactive[/dim]")
        console.print("[dim]       miya info[/dim]")


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


@cli.command()
@click.option("--target", "-t", required=True, help="Challenge URL or file path")
@click.option("--category", "-c", default="", help="Challenge category (web/pwn/crypto/reverse/misc)")
@click.option("--topology", "-T", default="ooda", type=click.Choice(["ooda", "attack_graph"]))
@click.option("--db", default="miya_events.db", help="SQLite database path")
@_common_options
def ctf(target: str, category: str, topology: str, db: str, model: str | None, api_key: str | None, base_url: str | None) -> None:
    """Solve CTF challenges"""
    _apply_api_env(api_key, base_url)
    kind = "challenge" if not target.startswith(("http", "/")) else "url"
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
@click.option("--db", default="miya_events.db", help="SQLite database path")
@_common_options
def interactive(db: str, model: str | None, api_key: str | None, base_url: str | None) -> None:
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
    from miya.mission.service import MissionService
    from miya.shared.blackboard import Blackboard

    show_banner()
    console.print(make_mission_table())
    console.print()

    # Runtime state
    cfg = {"model": model, "topology": "ooda"}
    mission_history: list[Any] = []

    def _prompt() -> str:
        return f"[bold red]miya[/bold red] [dim]({cfg['model']})[/dim] [dim]>[/dim] "

    def _print_help() -> None:
        console.print(make_mission_table())
        console.print(make_topology_table())
        console.print()
        help_table = Table(title="REPL Commands", box=box.SIMPLE, title_style="bold cyan")
        help_table.add_column("Command", style="bold green", width=40)
        help_table.add_column("Description", style="white")
        help_table.add_row("oneday <target> [opts]", "Exploit known CVEs")
        help_table.add_row("zeroday <target> [opts]", "Discover 0-day vulnerabilities")
        help_table.add_row("ctf <target> [opts]", "Solve CTF challenge")
        help_table.add_row("", "")
        help_table.add_row("[dim]Options:[/dim]", "")
        help_table.add_row("  --topology/-T <topo>", "ooda or attack_graph")
        help_table.add_row("  --category/-c <cat>", "CTF category (web/pwn/crypto/...)")
        help_table.add_row("  --language/-l <lang>", "Language hint for 0-day")
        help_table.add_row("  --source/-s <path>", "Source code path (oneday white-box)")
        help_table.add_row("  --service <url>", "Live service URL (zeroday PoC)")
        help_table.add_row("", "")
        help_table.add_row("[dim]REPL:[/dim]", "")
        help_table.add_row("set model <model>", "Switch model (opus/sonnet/haiku)")
        help_table.add_row("set topology <topo>", "Set default topology")
        help_table.add_row("status", "Show current config and session stats")
        help_table.add_row("history", "Show mission history")
        help_table.add_row("events", "Show recent domain events")
        help_table.add_row("blackboard", "Show current blackboard state")
        help_table.add_row("info", "Show MCP server info")
        help_table.add_row("clear", "Clear screen")
        help_table.add_row("exit/quit/q", "Exit interactive mode")
        console.print(help_table)

    def _print_status(event_count: int) -> None:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        key_status = f"[green]set ({api_key[:8]}...)[/green]" if api_key else "[red]not set[/red]"
        base_url = os.environ.get("ANTHROPIC_BASE_URL", "")
        url_display = f"[green]{base_url}[/green]" if base_url else "[dim]default[/dim]"
        console.print(Panel(
            f"[bold]Model:[/bold]     {cfg['model']}\n"
            f"[bold]Topology:[/bold]  {cfg['topology']}\n"
            f"[bold]API Key:[/bold]   {key_status}\n"
            f"[bold]Base URL:[/bold]  {url_display}\n"
            f"[bold]DB:[/bold]        {db}\n"
            f"[bold]Events:[/bold]    {event_count}\n"
            f"[bold]Missions:[/bold]  {len(mission_history)}",
            title="[bold cyan]Session Status[/bold cyan]",
            border_style="cyan",
        ))

    _print_help()
    console.print()

    service = await MissionService.create(db_path=db)

    try:
        while True:
            try:
                raw = console.input(_prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Goodbye.[/dim]")
                break

            if not raw:
                continue

            lower = raw.lower()

            # Exit
            if lower in ("exit", "quit", "q"):
                console.print("[dim]Goodbye.[/dim]")
                break

            # Clear
            if lower == "clear":
                console.clear()
                show_banner()
                continue

            # Help
            if lower == "help":
                _print_help()
                continue

            # Info
            if lower == "info":
                console.print(make_mcp_table())
                continue

            # Status
            if lower == "status":
                event_count = await service._event_store.count() if service._event_store else 0
                _print_status(event_count)
                continue

            # Events
            if lower == "events":
                if service._event_store:
                    events = await service._event_store.load_all()
                    if not events:
                        console.print("[dim]No events recorded yet.[/dim]")
                    else:
                        table = Table(title=f"Domain Events ({len(events)} total)", box=box.SIMPLE, title_style="bold")
                        table.add_column("Type", style="bold cyan", width=25)
                        table.add_column("Context", style="yellow", width=12)
                        table.add_column("Time", style="dim", width=20)
                        table.add_column("Details", style="white", max_width=50)
                        for ev in events[-20:]:  # last 20
                            details = ""
                            for attr in ("host", "ip", "cve_id", "software", "title", "vulnerability", "challenge_name"):
                                if hasattr(ev, attr) and getattr(ev, attr):
                                    details = str(getattr(ev, attr))
                                    break
                            table.add_row(
                                type(ev).__name__,
                                getattr(ev, "context", ""),
                                str(getattr(ev, "timestamp", ""))[:19],
                                details[:50],
                            )
                        console.print(table)
                continue

            # Blackboard
            if lower == "blackboard":
                if service._event_store:
                    bb = Blackboard()
                    all_events = await service._event_store.load_all()
                    bb.apply_all(all_events)
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
                            + (f"[bold]Attack Graph:[/bold]\n{summary.get('attack_graph', '')}" if summary.get('attack_graph') else ""),
                            title="[bold cyan]Blackboard State[/bold cyan]",
                            border_style="cyan",
                        ))
                continue

            # History
            if lower == "history":
                if not mission_history:
                    console.print("[dim]No missions executed yet.[/dim]")
                else:
                    table = Table(title="Mission History", box=box.SIMPLE, title_style="bold")
                    table.add_column("#", style="dim", width=3)
                    table.add_column("Type", style="bold green", width=10)
                    table.add_column("Target", style="white", width=30)
                    table.add_column("Status", width=10)
                    table.add_column("Findings", style="yellow", width=10)
                    table.add_column("Duration", style="dim", width=10)
                    for idx, r in enumerate(mission_history, 1):
                        status_color = "green" if r.status == "completed" else "red"
                        table.add_row(
                            str(idx),
                            r.mission_type,
                            r.target[:30],
                            f"[{status_color}]{r.status}[/{status_color}]",
                            f"{r.critical_count}C/{len(r.findings)}T",
                            f"{r.duration_seconds:.1f}s",
                        )
                    console.print(table)
                continue

            # Set commands
            if lower.startswith("set "):
                set_parts = raw.split(None, 2)
                if len(set_parts) == 3:
                    key, val = set_parts[1].lower(), set_parts[2]
                    if key == "model":
                        cfg["model"] = val
                        console.print(f"[green]Model set to: {val}[/green]")
                    elif key == "topology":
                        if val in ("ooda", "attack_graph"):
                            cfg["topology"] = val
                            console.print(f"[green]Default topology set to: {val}[/green]")
                        else:
                            console.print(f"[red]Unknown topology: {val}. Use 'ooda' or 'attack_graph'.[/red]")
                    elif key == "api_key":
                        os.environ["ANTHROPIC_API_KEY"] = val
                        console.print(f"[green]API key updated ({val[:8]}...)[/green]")
                    elif key == "base_url":
                        os.environ["ANTHROPIC_BASE_URL"] = val
                        console.print(f"[green]Base URL set to: {val}[/green]")
                    else:
                        console.print(f"[red]Unknown setting: {key}. Try: model, topology, api_key, base_url[/red]")
                else:
                    console.print("[yellow]Usage: set <key> <value>[/yellow]")
                continue

            # Parse mission command
            parts = raw.split()
            if len(parts) < 2:
                console.print("[yellow]Usage: <mission> <target> [options][/yellow]")
                console.print("[dim]Type 'help' for full usage.[/dim]")
                continue

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
                else:
                    i += 1

            if mission_type not in ("oneday", "zeroday", "ctf"):
                console.print(f"[red]Unknown command: {mission_type}[/red]")
                console.print("[dim]Type 'help' for available commands.[/dim]")
                continue

            kind_map = {
                "oneday": "service",
                "zeroday": "source",
                "ctf": "challenge",
            }

            console.print(Panel(
                f"[bold]Mission:[/bold]  {mission_type.upper()}\n"
                f"[bold]Target:[/bold]   {target}\n"
                f"[bold]Topology:[/bold] {topology}\n"
                f"[bold]Model:[/bold]    {cfg['model']}"
                + (f"\n[bold]Options:[/bold]  {options}" if options else ""),
                title="[bold cyan]Launching Mission[/bold cyan]",
                border_style="cyan",
            ))

            try:
                with Progress(
                    SpinnerColumn(spinner_name="dots"),
                    TextColumn("[bold blue]{task.description}[/bold blue]"),
                    console=console,
                ) as progress:
                    task = progress.add_task(
                        f"Running {mission_type} against {target}...", total=None
                    )
                    report = await service.execute(
                        mission_type=mission_type,
                        target_uri=target,
                        target_kind=kind_map[mission_type],
                        topology=topology,
                        model=cfg["model"],
                        **options,
                    )
                    progress.update(task, completed=True)

                console.print()
                print_report(report)
                mission_history.append(report)

            except Exception as e:
                console.print(f"[bold red]Error:[/bold red] {e}")

            console.print()

    finally:
        await service.close()


if __name__ == "__main__":
    cli()
