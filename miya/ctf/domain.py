"""CTF domain model — challenges, flags, and write-ups."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class Category(str, Enum):
    WEB = "web"
    PWN = "pwn"
    CRYPTO = "crypto"
    REVERSE = "reverse"
    MISC = "misc"
    FORENSICS = "forensics"


@dataclass(frozen=True)
class Flag:
    """Captured flag — the ultimate proof."""

    value: str
    format: str = "flag{...}"  # expected wrapper

    def matches(self, expected_format: str | None = None) -> bool:
        fmt = expected_format or self.format
        prefix = fmt.split("{")[0] + "{"
        return self.value.startswith(prefix) and self.value.endswith("}")


@dataclass(frozen=True)
class WriteUp:
    """Solution explanation — knowledge capture."""

    approach: str
    steps: list[str]
    tools_used: list[str]
    flag: Flag


SolveStatus = Literal["unsolved", "in_progress", "solved"]


@dataclass
class Challenge:
    """Aggregate root — a CTF challenge under attack."""

    name: str
    category: Category
    description: str
    points: int = 0
    attachments: list[str] = field(default_factory=list)  # file paths or URLs
    status: SolveStatus = "unsolved"
    flag: Flag | None = None
    writeup: WriteUp | None = None

    def solve(self, flag: Flag, writeup: WriteUp) -> None:
        self.flag = flag
        self.writeup = writeup
        self.status = "solved"

    @property
    def is_solved(self) -> bool:
        return self.status == "solved"
