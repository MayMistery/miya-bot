"""CTF Batch — challenge registry, health probing, task board, and writeup generation.

Supports the batch CTF workflow:
  1. Parse challenge definitions (JSON) from user input
  2. Probe each target for connectivity
  3. Display a live task board with progress
  4. Generate per-challenge writeup markdown files after solving
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
#  Challenge Registry — parsed from user JSON input
# ═══════════════════════════════════════════════════════════════════


class TaskStatus(str, Enum):
    PENDING = "pending"
    PROBING = "probing"
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    SOLVING = "solving"
    SOLVED = "solved"
    FAILED = "failed"


@dataclass
class ChallengeEntry:
    """A single CTF challenge from the batch definition."""

    name: str
    port: int
    ip: str = ""
    flag: str = ""
    status: TaskStatus = TaskStatus.PENDING
    category: str = ""
    probe_ms: float = 0.0
    http_code: int = 0
    approach: str = ""
    error: str = ""

    @property
    def url(self) -> str:
        return f"http://{self.ip}:{self.port}"

    @property
    def display_status(self) -> str:
        icons = {
            TaskStatus.PENDING: "⏳",
            TaskStatus.PROBING: "🔍",
            TaskStatus.REACHABLE: "✅",
            TaskStatus.UNREACHABLE: "❌",
            TaskStatus.SOLVING: "⚔️",
            TaskStatus.SOLVED: "🏴",
            TaskStatus.FAILED: "💀",
        }
        return f"{icons.get(self.status, '?')} {self.status.value}"

    @property
    def writeup_filename(self) -> str:
        """Generate writeup filename: {name}_{flag}.md"""
        safe_name = re.sub(r'[^\w\-]', '_', self.name)
        if self.flag:
            # Extract the inner part of flag{...} for filename
            m = re.match(r'[A-Za-z0-9_]+\{(.+)\}', self.flag)
            flag_part = m.group(1) if m else self.flag
            safe_flag = re.sub(r'[^\w\-]', '_', flag_part)
            return f"{safe_name}_{safe_flag}.md"
        return f"{safe_name}_unsolved.md"


@dataclass
class BatchRegistry:
    """Registry of all challenges in a batch CTF session."""

    challenges: list[ChallengeEntry] = field(default_factory=list)
    ip: str = ""
    created_at: float = field(default_factory=time.time)

    @classmethod
    def from_user_input(cls, raw_input: str) -> BatchRegistry:
        """Parse challenge definitions from user input containing JSON array + IP.

        Handles inputs like:
          "... [{"name": "Easy-Gin", "port": 16235}, ...] ip是10.37.225.178"
        """
        registry = cls()

        # Extract IP address
        ip_match = re.search(
            r'(?:ip[是为:\s]+|ip\s*[:=]\s*)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            raw_input, re.IGNORECASE,
        )
        if ip_match:
            registry.ip = ip_match.group(1)

        # Extract JSON array
        json_match = re.search(r'\[.*\]', raw_input, re.DOTALL)
        if not json_match:
            raise ValueError("No JSON challenge array found in input")

        try:
            items = json.loads(json_match.group())
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in challenge definition: {e}") from e

        if not isinstance(items, list):
            raise ValueError("Challenge definition must be a JSON array")

        for item in items:
            if not isinstance(item, dict):
                continue
            entry = ChallengeEntry(
                name=item.get("name", "unknown"),
                port=int(item.get("port", 0)),
                ip=registry.ip,
                flag=item.get("flag", ""),
                category=item.get("category", ""),
            )
            registry.challenges.append(entry)

        if not registry.challenges:
            raise ValueError("No challenges parsed from input")

        return registry

    def get(self, name: str) -> ChallengeEntry | None:
        return next((c for c in self.challenges if c.name == name), None)

    @property
    def total(self) -> int:
        return len(self.challenges)

    @property
    def solved_count(self) -> int:
        return sum(1 for c in self.challenges if c.status == TaskStatus.SOLVED)

    @property
    def all_reachable(self) -> bool:
        return all(
            c.status in (TaskStatus.REACHABLE, TaskStatus.SOLVING, TaskStatus.SOLVED)
            for c in self.challenges
        )


# ═══════════════════════════════════════════════════════════════════
#  Health Probe — check connectivity to challenge targets
# ═══════════════════════════════════════════════════════════════════


async def probe_challenge(entry: ChallengeEntry, timeout: float = 5.0) -> None:
    """Probe a single challenge endpoint for connectivity."""
    import aiohttp

    entry.status = TaskStatus.PROBING
    url = entry.url

    try:
        async with aiohttp.ClientSession() as session:
            start = time.monotonic()
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                elapsed = (time.monotonic() - start) * 1000
                entry.http_code = resp.status
                entry.probe_ms = round(elapsed, 1)
                entry.status = TaskStatus.REACHABLE
    except Exception as e:
        # Fallback: try raw TCP connect (some challenges don't speak HTTP)
        try:
            start = time.monotonic()
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(entry.ip, entry.port),
                timeout=timeout,
            )
            elapsed = (time.monotonic() - start) * 1000
            entry.probe_ms = round(elapsed, 1)
            entry.status = TaskStatus.REACHABLE
            entry.http_code = 0  # TCP only
            writer.close()
            await writer.wait_closed()
        except Exception as tcp_err:
            entry.status = TaskStatus.UNREACHABLE
            entry.error = str(tcp_err)[:80]


async def probe_all(registry: BatchRegistry, timeout: float = 5.0) -> None:
    """Probe all challenges concurrently."""
    await asyncio.gather(
        *(probe_challenge(c, timeout) for c in registry.challenges),
        return_exceptions=True,
    )


# ═══════════════════════════════════════════════════════════════════
#  Task Board — rich terminal display
# ═══════════════════════════════════════════════════════════════════


def render_probe_report(registry: BatchRegistry) -> str:
    """Render a connectivity probe report as a formatted string."""
    width = 62
    lines = [
        "",
        f"  ┌{'─' * width}┐",
        f"  │{'CTF 环境连通性检测报告':^{width - 18}}│",
        f"  ├{'─' * 20}┬{'─' * 8}┬{'─' * 14}┬{'─' * (width - 20 - 8 - 14 - 3)}┤",
        f"  │ {'题目':<16} │ {'端口':^6} │ {'状态':^10}  │ {'响应时间':^{width - 20 - 8 - 14 - 7}} │",
        f"  ├{'─' * 20}┼{'─' * 8}┼{'─' * 14}┼{'─' * (width - 20 - 8 - 14 - 3)}┤",
    ]
    for c in registry.challenges:
        if c.status == TaskStatus.REACHABLE:
            status_str = f"✅ HTTP {c.http_code}" if c.http_code else "✅ TCP OK"
            time_str = f"{c.probe_ms:.1f}ms"
        elif c.status == TaskStatus.UNREACHABLE:
            status_str = "❌ FAIL"
            time_str = "—"
        else:
            status_str = "⏳ ..."
            time_str = "—"
        name_display = c.name[:16]
        lines.append(
            f"  │ {name_display:<18} │ {c.port:^6} │ {status_str:<12} │ {time_str:^{width - 20 - 8 - 14 - 7}} │"
        )
    lines.append(f"  └{'─' * 20}┴{'─' * 8}┴{'─' * 14}┴{'─' * (width - 20 - 8 - 14 - 3)}┘")

    reachable = sum(1 for c in registry.challenges if c.status == TaskStatus.REACHABLE)
    total = registry.total
    lines.append(f"  {reachable}/{total} 环境可达")
    lines.append("")
    return "\n".join(lines)


def render_task_board(registry: BatchRegistry) -> str:
    """Render the live task board showing challenge solving progress."""
    width = 72
    solved = registry.solved_count
    total = registry.total
    bar_len = 30
    filled = int(bar_len * solved / total) if total else 0
    bar = "█" * filled + "░" * (bar_len - filled)

    lines = [
        "",
        f"  ╔{'═' * width}╗",
        f"  ║{'CTF Task Board':^{width}}║",
        f"  ╠{'═' * width}╣",
        f"  ║  进度: [{bar}] {solved}/{total}  {' ' * (width - bar_len - 18)}║",
        f"  ╟{'─' * width}╢",
    ]

    for i, c in enumerate(registry.challenges, 1):
        status_icon = {
            TaskStatus.PENDING: "⏳",
            TaskStatus.REACHABLE: "🎯",
            TaskStatus.SOLVING: "⚔️ ",
            TaskStatus.SOLVED: "🏴",
            TaskStatus.FAILED: "💀",
        }.get(c.status, "?")

        flag_display = c.flag[:30] if c.flag else "—"
        name_col = f"{status_icon} {c.name}"
        flag_col = flag_display

        # Pad to width
        content = f"  {i}. {name_col:<24} {c.url:<28} {flag_col}"
        padding = width - len(content) + 4
        lines.append(f"  ║{content}{' ' * max(0, padding)}║")

    lines.append(f"  ╚{'═' * width}╝")
    lines.append("")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
#  WriteUp Generator
# ═══════════════════════════════════════════════════════════════════


def generate_writeup(
    entry: ChallengeEntry,
    events: list[Any] | None = None,
    approach_detail: str = "",
) -> str:
    """Generate a markdown writeup for a solved challenge."""
    lines = [
        f"# {entry.name}",
        "",
        f"**Category:** {entry.category or 'web/client'}",
        f"**Target:** `{entry.url}`",
        f"**Flag:** `{entry.flag}`",
        "",
        "---",
        "",
        "## Solution",
        "",
    ]

    if approach_detail:
        lines.append(approach_detail)
    elif entry.approach:
        lines.append(entry.approach)
    else:
        lines.append("*(Automated solution by Miya)*")

    lines.extend([
        "",
        "---",
        "",
        f"*Solved by Miya DDD Pentest Agent*",
    ])

    return "\n".join(lines)


def write_all_writeups(
    registry: BatchRegistry,
    output_dir: Path | str = ".",
    events_by_challenge: dict[str, list[Any]] | None = None,
) -> list[Path]:
    """Generate writeup files for all solved challenges.

    Returns list of created file paths.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []

    for entry in registry.challenges:
        if entry.status != TaskStatus.SOLVED or not entry.flag:
            continue

        content = generate_writeup(
            entry,
            events=(events_by_challenge or {}).get(entry.name),
        )
        filepath = output_dir / entry.writeup_filename
        filepath.write_text(content, encoding="utf-8")
        created.append(filepath)
        logger.info("Writeup written: %s", filepath)

    return created


def render_writeup_summary(created_files: list[Path]) -> str:
    """Render a summary of generated writeup files."""
    if not created_files:
        return "  No writeups generated (no challenges solved)."

    lines = [
        "",
        "  📝 Generated Writeups:",
        "  ─────────────────────",
    ]
    for f in created_files:
        lines.append(f"    ✅ {f.name}")
    lines.append("")
    return "\n".join(lines)
