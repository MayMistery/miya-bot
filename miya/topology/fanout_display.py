"""Rich Live panel grid for parallel challenge solving.

Displays per-challenge progress panels during FAN-OUT phase,
replacing interleaved log output with a structured visual grid.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from rich.columns import Columns
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


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

    @property
    def elapsed(self) -> str:
        if not self.started_at:
            return ""
        secs = time.monotonic() - self.started_at
        if secs < 60:
            return f"{secs:.0f}s"
        return f"{secs / 60:.1f}m"

    @property
    def status_icon(self) -> str:
        return {
            "waiting": "\u23f3",      # hourglass
            "classifying": "\U0001f50d",  # magnifying glass
            "running": "\u25b6",      # play
            "solved": "\u2705",       # checkmark
            "failed": "\u274c",       # cross
            "timeout": "\u23f0",      # alarm clock
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


class FanoutDisplay:
    """Rich Live display for parallel challenge solving.

    Usage::

        display = FanoutDisplay(challenges)
        with display:
            # ... run challenges in parallel ...
            display.update("Easy-Gin", phase="OBSERVE", iteration=1)
            display.update("Easy-Gin", status="solved", flag="flag{...}")
    """

    def __init__(
        self,
        challenges: list[dict[str, Any]],
        max_columns: int = 3,
    ) -> None:
        self._states: dict[str, ChallengeState] = {}
        self._max_columns = max_columns
        self._live: Live | None = None
        self._event_log: list[str] = []  # recent events for bottom feed
        self._max_events = 8

        for ch in challenges:
            name = ch.get("name", "?")
            self._states[name] = ChallengeState(
                name=name,
                category=ch.get("category", ""),
                max_iterations=ch.get("_max_iter", 5),
                whitebox=ch.get("_whitebox", False),
            )

    def update(self, challenge_name: str, **kwargs: Any) -> None:
        """Update a challenge's progress state."""
        state = self._states.get(challenge_name)
        if not state:
            return
        for k, v in kwargs.items():
            if hasattr(state, k):
                setattr(state, k, v)
        if self._live:
            self._live.update(self._render())

    def log_event(self, text: str) -> None:
        """Add a line to the scrolling event log at the bottom."""
        self._event_log.append(text)
        if len(self._event_log) > self._max_events:
            self._event_log = self._event_log[-self._max_events:]
        if self._live:
            self._live.update(self._render())

    def _render_challenge_panel(self, state: ChallengeState) -> Panel:
        """Render a single challenge's status panel."""
        lines: list[str] = []

        # Category + mode
        cat_str = f"[dim]{state.category or '?'}[/dim]"
        if state.whitebox:
            cat_str += " [yellow](whitebox)[/yellow]"
        lines.append(cat_str)

        # Phase + iteration
        if state.status in ("running", "classifying"):
            phase_text = f"[{state.phase_style}]{state.phase}[/{state.phase_style}]"
            if state.iteration > 0:
                phase_text += f" [dim]#{state.iteration}/{state.max_iterations}[/dim]"
            lines.append(phase_text)
        elif state.status == "solved":
            lines.append("[bold green]SOLVED[/bold green]")
        elif state.status == "failed":
            lines.append("[bold red]FAILED[/bold red]")
        elif state.status == "timeout":
            lines.append("[bold yellow]TIMEOUT[/bold yellow]")
        else:
            lines.append("[dim]waiting...[/dim]")

        # Flag
        if state.flag:
            flag_display = state.flag if len(state.flag) <= 30 else state.flag[:27] + "..."
            lines.append(f"[green]{flag_display}[/green]")

        # Last activity
        if state.last_activity:
            activity = state.last_activity[:40]
            lines.append(f"[dim]{activity}[/dim]")

        # Elapsed
        if state.elapsed:
            lines.append(f"[dim]{state.elapsed}[/dim]")

        # Border style based on status
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
            height=8,
        )

    def _render(self) -> Group:
        """Render the full display: challenge grid + event log."""
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

        # Event log
        parts: list[Any] = [grid, summary]
        if self._event_log:
            event_text = "\n".join(f"  [dim]{line}[/dim]" for line in self._event_log)
            parts.append(Text.from_markup(event_text))

        return Group(*parts)

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
            # Final render
            self._live.update(self._render())
            self._live.__exit__(*exc)
            self._live = None
        return False

    @property
    def is_active(self) -> bool:
        return self._live is not None
