"""Rich Live panel grid for parallel challenge solving.

Displays per-challenge progress panels during FAN-OUT phase.
Supports display modes: GRID (overview), ATTACHED (single challenge logs),
and interactive commands for bg/fg, attach/detach, per-challenge HITL.

Interactive commands (typed via HITL input):
    logs <name>          — show recent log buffer for a challenge
    attach <name>        — live-follow a challenge's logs
    detach               — return to grid view
    extend <name> [min]  — extend a challenge's timeout (default +30m)
    extend all [min]     — extend all timeouts
    @<name> <message>    — send HITL message to a specific challenge
    <message>            — broadcast HITL to all running challenges
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from rich.columns import Columns
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.text import Text


# ═══════════════════════════════════════════════════════════════════
#  Per-challenge log buffer
# ═══════════════════════════════════════════════════════════════════


class ChallengeLogBuffer:
    """Ring buffer capturing log lines for a single challenge."""

    def __init__(self, maxlen: int = 200) -> None:
        self._lines: deque[str] = deque(maxlen=maxlen)

    def append(self, line: str) -> None:
        self._lines.append(line)

    def tail(self, n: int = 20) -> list[str]:
        """Return the last n lines."""
        lines = list(self._lines)
        return lines[-n:]

    def __len__(self) -> int:
        return len(self._lines)


# ═══════════════════════════════════════════════════════════════════
#  Challenge state
# ═══════════════════════════════════════════════════════════════════


@dataclass
class ChallengeState:
    """Per-challenge progress state."""

    name: str
    category: str = ""
    phase: str = "WAITING"
    iteration: int = 0
    max_iterations: int = 5
    status: str = "waiting"  # waiting, classifying, running, solved, failed, timeout
    flag: str = ""
    last_activity: str = ""
    started_at: float = 0.0
    whitebox: bool = False
    timeout_at: float = 0.0  # monotonic time when timeout fires
    log_buffer: ChallengeLogBuffer = field(default_factory=ChallengeLogBuffer)

    @property
    def elapsed(self) -> str:
        if not self.started_at:
            return ""
        secs = time.monotonic() - self.started_at
        if secs < 60:
            return f"{secs:.0f}s"
        return f"{secs / 60:.1f}m"

    @property
    def remaining(self) -> float:
        """Seconds remaining until timeout. Negative = expired."""
        if not self.timeout_at:
            return float("inf")
        return self.timeout_at - time.monotonic()

    @property
    def remaining_str(self) -> str:
        r = self.remaining
        if r == float("inf"):
            return ""
        if r < 0:
            return "expired"
        if r < 60:
            return f"{r:.0f}s left"
        return f"{r / 60:.0f}m left"

    @property
    def status_icon(self) -> str:
        return {
            "waiting": "\u23f3",
            "classifying": "\U0001f50d",
            "running": "\u25b6",
            "solved": "\u2705",
            "failed": "\u274c",
            "timeout": "\u23f0",
        }.get(self.status, "?")

    @property
    def phase_style(self) -> str:
        return {
            "WAITING": "dim",
            "CLASSIFY": "magenta",
            "OBSERVE": "cyan",
            "ACT": "yellow",
            "REFLECT": "blue",
            "CONTINUE": "green",
            "DONE": "bold green",
            "FAILED": "bold red",
            "TIMEOUT": "bold yellow",
        }.get(self.phase, "white")


# ═══════════════════════════════════════════════════════════════════
#  Display modes
# ═══════════════════════════════════════════════════════════════════


class _Mode:
    GRID = "grid"
    ATTACHED = "attached"


class FanoutDisplay:
    """Rich Live display for parallel challenge solving.

    Supports two display modes:
    - GRID: panel grid showing all challenges at a glance
    - ATTACHED: live log tail for a single challenge

    Usage::

        display = FanoutDisplay(challenges, timeout=3600)
        with display:
            display.update("Easy-Gin", phase="OBSERVE")
            display.capture_log("Easy-Gin", "▶ OBSERVE — gathering intelligence")
            display.attach("Easy-Gin")  # switch to log view
            display.detach()             # back to grid
    """

    def __init__(
        self,
        challenges: list[dict[str, Any]],
        max_columns: int = 3,
        timeout: float = 3600.0,
    ) -> None:
        self._states: dict[str, ChallengeState] = {}
        self._max_columns = max_columns
        self._live: Live | None = None
        self._event_log: deque[str] = deque(maxlen=12)
        self._mode = _Mode.GRID
        self._attached_name: str = ""
        self._timeout = timeout
        self._solved_set: set[str] = set()  # dedup solved notifications

        for ch in challenges:
            name = ch.get("name", "?")
            self._states[name] = ChallengeState(
                name=name,
                category=ch.get("category", ""),
                max_iterations=ch.get("_max_iter", 5),
                whitebox=ch.get("_whitebox", False),
            )

    # ── State updates ────────────────────────────────────────────

    def update(self, challenge_name: str, **kwargs: Any) -> None:
        """Update a challenge's progress state."""
        state = self._states.get(challenge_name)
        if not state:
            return
        for k, v in kwargs.items():
            if hasattr(state, k):
                setattr(state, k, v)
        self._refresh()

    def capture_log(self, challenge_name: str, line: str) -> None:
        """Capture a log line into a challenge's buffer."""
        state = self._states.get(challenge_name)
        if state:
            state.log_buffer.append(line)
            state.last_activity = line[:60]
        self._refresh()

    def log_event(self, text: str) -> None:
        """Add a line to the global scrolling event log."""
        # Dedup solved notifications
        if text.startswith("\u2713") and "SOLVED" in text:
            if text in self._solved_set:
                return
            self._solved_set.add(text)
        self._event_log.append(text)
        self._refresh()

    def mark_timeout_at(self, challenge_name: str, timeout_at: float) -> None:
        """Set the absolute monotonic time when timeout fires."""
        state = self._states.get(challenge_name)
        if state:
            state.timeout_at = timeout_at

    # ── Display modes ────────────────────────────────────────────

    def attach(self, challenge_name: str) -> bool:
        """Switch to live log view for a specific challenge."""
        if challenge_name not in self._states:
            self.log_event(f"Unknown challenge: {challenge_name}")
            return False
        self._mode = _Mode.ATTACHED
        self._attached_name = challenge_name
        self.log_event(f"Attached to {challenge_name} (type 'detach' to return)")
        self._refresh()
        return True

    def detach(self) -> None:
        """Return to grid view."""
        self._mode = _Mode.GRID
        self._attached_name = ""
        self._refresh()

    def get_logs(self, challenge_name: str, n: int = 30) -> list[str]:
        """Get recent log lines for a challenge."""
        state = self._states.get(challenge_name)
        if not state:
            return [f"Unknown challenge: {challenge_name}"]
        return state.log_buffer.tail(n)

    @property
    def challenge_names(self) -> list[str]:
        return list(self._states.keys())

    # ── Rendering ────────────────────────────────────────────────

    def _refresh(self) -> None:
        if self._live:
            self._live.update(self._render())

    def _render(self) -> Group:
        if self._mode == _Mode.ATTACHED:
            return self._render_attached()
        return self._render_grid()

    def _render_grid(self) -> Group:
        """Render the panel grid + event log."""
        panels = [
            self._render_challenge_panel(s)
            for s in self._states.values()
        ]
        grid = Columns(panels, equal=True, expand=True)

        # Summary line
        total = len(self._states)
        solved = sum(1 for s in self._states.values() if s.status == "solved")
        running = sum(1 for s in self._states.values() if s.status in ("running", "classifying"))
        failed = sum(1 for s in self._states.values() if s.status in ("failed", "timeout"))
        waiting = total - solved - running - failed

        summary = Text.from_markup(
            f"  [bold]Progress:[/bold] "
            f"[green]{solved}[/green] solved  "
            f"[cyan]{running}[/cyan] running  "
            f"[dim]{waiting}[/dim] waiting  "
            f"[red]{failed}[/red] failed  "
            f"[dim]({total} total)[/dim]"
        )

        # Help hint
        hint = Text.from_markup(
            "  [dim]Commands: help | attach <name> | logs <name> [n] | "
            "status <name> | @<name> <msg> | ref <src> @<dst> | "
            "extend <name|all>[/dim]"
        )

        parts: list[Any] = [grid, summary, hint]
        if self._event_log:
            event_text = "\n".join(
                f"  [dim]{line}[/dim]" for line in self._event_log
            )
            parts.append(Text.from_markup(event_text))

        return Group(*parts)

    def _render_attached(self) -> Group:
        """Render the attached single-challenge log view."""
        state = self._states.get(self._attached_name)
        if not state:
            self._mode = _Mode.GRID
            return self._render_grid()

        # Header
        header = Text.from_markup(
            f"  {state.status_icon} [bold]{state.name}[/bold] "
            f"[dim]({state.category or '?'})[/dim]  "
            f"[{state.phase_style}]{state.phase}[/{state.phase_style}]"
            + (f" #{state.iteration}/{state.max_iterations}" if state.iteration else "")
            + f"  [dim]{state.elapsed}[/dim]"
            + (f"  [dim]{state.remaining_str}[/dim]" if state.remaining_str else "")
        )

        # Log tail
        lines = state.log_buffer.tail(30)
        if lines:
            log_text = "\n".join(f"  {line}" for line in lines)
        else:
            log_text = "  [dim](no logs yet)[/dim]"

        log_panel = Panel(
            Text.from_markup(log_text),
            title=f"[bold]{state.name}[/bold] logs",
            border_style="cyan",
        )

        hint = Text.from_markup(
            f"  [dim]detach | @{state.name} <msg> | extend {state.name}[/dim]"
        )

        # Global progress summary (compact)
        total = len(self._states)
        solved = sum(1 for s in self._states.values() if s.status == "solved")
        compact = Text.from_markup(
            f"  [dim]{solved}/{total} solved[/dim]"
        )

        return Group(header, log_panel, hint, compact)

    def _render_challenge_panel(self, state: ChallengeState) -> Panel:
        """Render a single challenge's status panel."""
        lines: list[str] = []

        cat_str = f"[dim]{state.category or '?'}[/dim]"
        if state.whitebox:
            cat_str += " [yellow](wb)[/yellow]"
        lines.append(cat_str)

        if state.status in ("running", "classifying"):
            phase_text = f"[{state.phase_style}]{state.phase}[/{state.phase_style}]"
            if state.iteration > 0:
                phase_text += f" [dim]#{state.iteration}/{state.max_iterations}[/dim]"
            lines.append(phase_text)
            # Timeout warning
            remaining = state.remaining
            if 0 < remaining < 300:
                lines.append(f"[bold yellow]⚠ {state.remaining_str}[/bold yellow]")
            elif state.remaining_str and remaining != float("inf"):
                lines.append(f"[dim]{state.remaining_str}[/dim]")
        elif state.status == "solved":
            lines.append("[bold green]SOLVED[/bold green]")
        elif state.status == "failed":
            lines.append("[bold red]FAILED[/bold red]")
        elif state.status == "timeout":
            lines.append("[bold yellow]TIMEOUT[/bold yellow]")
        else:
            lines.append("[dim]waiting...[/dim]")

        if state.flag:
            flag_display = state.flag if len(state.flag) <= 30 else state.flag[:27] + "..."
            lines.append(f"[green]{flag_display}[/green]")

        if state.last_activity:
            lines.append(f"[dim]{state.last_activity[:40]}[/dim]")

        if state.elapsed:
            lines.append(f"[dim]{state.elapsed}[/dim]")

        border_styles = {
            "waiting": "dim",
            "classifying": "magenta",
            "running": "cyan",
            "solved": "green",
            "failed": "red",
            "timeout": "yellow",
        }

        return Panel(
            "\n".join(lines),
            title=f"{state.status_icon} [bold]{state.name}[/bold]",
            border_style=border_styles.get(state.status, "dim"),
            width=30,
            height=9,
        )

    # ── Context manager ──────────────────────────────────────────

    def __enter__(self) -> "FanoutDisplay":
        from rich.console import Console
        self._live = Live(
            self._render(),
            console=Console(stderr=True),
            refresh_per_second=2,
            transient=False,
        )
        self._live.__enter__()
        return self

    def __exit__(self, *exc: Any) -> bool:
        if self._live:
            self._live.update(self._render())
            self._live.__exit__(*exc)
            self._live = None
        return False

    @property
    def is_active(self) -> bool:
        return self._live is not None
