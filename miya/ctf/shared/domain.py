"""CTF Shared Domain — aggregate root, entities, and value objects.

Provides the core CTF abstractions shared across all category-specific
bounded contexts (web, pwn, crypto, reverse, misc).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from miya.shared.types import new_id as _uuid, utc_now as _now


# ═══════════════════════════════════════════════════════════════════
#  Enums
# ═══════════════════════════════════════════════════════════════════


class ChallengeCategory(str, Enum):
    WEB = "web"
    PWN = "pwn"
    CRYPTO = "crypto"
    REVERSE = "reverse"
    MISC = "misc"


class ChallengeStatus(str, Enum):
    IDENTIFIED = "identified"
    ANALYZING = "analyzing"
    EXPLOITING = "exploiting"
    SOLVED = "solved"
    ABANDONED = "abandoned"


class Difficulty(str, Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    INSANE = "insane"


# ═══════════════════════════════════════════════════════════════════
#  Value Objects
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class Flag:
    """Captured flag string with format validation."""

    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("Flag value cannot be empty")

    def matches_format(self, prefix: str = "") -> bool:
        """Check if flag matches expected CTF format, e.g. 'flag{...}'."""
        if not prefix:
            return bool(re.match(r"^[A-Za-z0-9_]+\{.+\}$", self.value))
        return self.value.startswith(f"{prefix}{{") and self.value.endswith("}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class WriteUp:
    """Solution documentation for a solved challenge."""

    summary: str
    steps: tuple[str, ...] = ()
    tools_used: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    @property
    def full_text(self) -> str:
        parts = [self.summary]
        if self.steps:
            parts.append("\n".join(f"  {i + 1}. {s}" for i, s in enumerate(self.steps)))
        return "\n\n".join(parts)


@dataclass(frozen=True)
class SolveStrategy:
    """Planned or attempted approach for a challenge."""

    name: str
    description: str
    confidence: float = 0.5  # 0.0 - 1.0
    priority: int = 0  # higher = try first

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            object.__setattr__(self, "confidence", max(0.0, min(1.0, self.confidence)))


# ═══════════════════════════════════════════════════════════════════
#  Entities
# ═══════════════════════════════════════════════════════════════════


@dataclass
class Challenge:
    """A single CTF challenge."""

    id: str = field(default_factory=_uuid)
    name: str = ""
    category: ChallengeCategory = ChallengeCategory.MISC
    points: int = 0
    description: str = ""
    url: str = ""
    file_paths: list[str] = field(default_factory=list)
    status: ChallengeStatus = ChallengeStatus.IDENTIFIED
    difficulty: Difficulty = Difficulty.MEDIUM
    flag: Flag | None = None
    strategies: list[SolveStrategy] = field(default_factory=list)
    writeup: WriteUp | None = None
    created_at: datetime = field(default_factory=_now)
    solved_at: datetime | None = None

    @property
    def is_solved(self) -> bool:
        return self.status == ChallengeStatus.SOLVED and self.flag is not None

    def start_analysis(self) -> None:
        if self.status == ChallengeStatus.IDENTIFIED:
            self.status = ChallengeStatus.ANALYZING

    def start_exploit(self) -> None:
        self.status = ChallengeStatus.EXPLOITING

    def solve(self, flag: Flag, writeup: WriteUp | None = None) -> None:
        self.flag = flag
        self.status = ChallengeStatus.SOLVED
        self.solved_at = _now()
        if writeup:
            self.writeup = writeup

    def abandon(self) -> None:
        self.status = ChallengeStatus.ABANDONED

    def add_strategy(self, strategy: SolveStrategy) -> None:
        self.strategies.append(strategy)
        self.strategies.sort(key=lambda s: s.priority, reverse=True)

    @property
    def best_strategy(self) -> SolveStrategy | None:
        return self.strategies[0] if self.strategies else None


# ═══════════════════════════════════════════════════════════════════
#  Aggregate Root
# ═══════════════════════════════════════════════════════════════════


@dataclass
class Competition:
    """Aggregate Root — a CTF competition containing challenges."""

    id: str = field(default_factory=_uuid)
    name: str = ""
    url: str = ""
    flag_format: str = ""  # e.g. "flag" for flag{...}
    challenges: list[Challenge] = field(default_factory=list)
    started_at: datetime = field(default_factory=_now)
    status: Literal["active", "completed", "paused"] = "active"

    def add_challenge(self, challenge: Challenge) -> None:
        if any(c.id == challenge.id for c in self.challenges):
            return
        self.challenges.append(challenge)

    def get_challenge(self, challenge_id: str) -> Challenge | None:
        return next((c for c in self.challenges if c.id == challenge_id), None)

    def get_challenge_by_name(self, name: str) -> Challenge | None:
        return next((c for c in self.challenges if c.name == name), None)

    def unsolved_challenges(self) -> list[Challenge]:
        return [c for c in self.challenges if not c.is_solved]

    def solved_challenges(self) -> list[Challenge]:
        return [c for c in self.challenges if c.is_solved]

    @property
    def total_points(self) -> int:
        return sum(c.points for c in self.challenges if c.is_solved)

    @property
    def solve_count(self) -> int:
        return len(self.solved_challenges())

    @property
    def progress(self) -> float:
        if not self.challenges:
            return 0.0
        return self.solve_count / len(self.challenges)

    def complete(self) -> None:
        self.status = "completed"

    def pause(self) -> None:
        self.status = "paused"
