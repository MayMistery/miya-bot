"""Pwn CTF Domain — binary exploitation challenge models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

from miya.ctf.shared.domain import (
    ChallengeStatus,
    Difficulty,
    Flag,
    SolveStrategy,
    WriteUp,
    _now,
    _uuid,
)


# ═══════════════════════════════════════════════════════════════════
#  Value Objects
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class Protection:
    """Binary protection flags (checksec output)."""

    nx: bool = True
    aslr: bool = True
    pie: bool = False
    canary: bool = False
    relro: Literal["none", "partial", "full"] = "none"

    @property
    def summary(self) -> str:
        flags = []
        if self.nx:
            flags.append("NX")
        if self.aslr:
            flags.append("ASLR")
        if self.pie:
            flags.append("PIE")
        if self.canary:
            flags.append("Canary")
        if self.relro != "none":
            flags.append(f"RELRO({self.relro})")
        return ", ".join(flags) if flags else "No protections"


@dataclass(frozen=True)
class MemoryLayout:
    """Stack/heap layout information."""

    stack_base: int = 0
    stack_size: int = 0
    heap_base: int = 0
    libc_base: int = 0
    binary_base: int = 0
    writable_segments: tuple[str, ...] = ()

    @property
    def has_known_offsets(self) -> bool:
        return self.stack_base != 0 or self.libc_base != 0


@dataclass(frozen=True)
class GadgetChain:
    """A ROP/JOP gadget chain for exploitation."""

    gadgets: tuple[str, ...] = ()
    description: str = ""
    chain_type: str = ""  # "rop", "jop", "sigreturn", "ret2libc"

    @property
    def length(self) -> int:
        return len(self.gadgets)


# ═══════════════════════════════════════════════════════════════════
#  Entities
# ═══════════════════════════════════════════════════════════════════


@dataclass
class Binary:
    """Target binary with checksec and analysis info."""

    id: str = field(default_factory=_uuid)
    path: str = ""
    arch: str = ""  # "x86", "x86_64", "arm", "aarch64", "mips"
    bits: int = 64
    endian: Literal["little", "big"] = "little"
    stripped: bool = False
    static_linked: bool = False
    protection: Protection = field(default_factory=Protection)
    libc_version: str = ""
    functions: list[str] = field(default_factory=list)
    dangerous_functions: list[str] = field(default_factory=list)  # gets, strcpy, etc.

    @property
    def summary(self) -> str:
        return (
            f"{self.arch} {self.bits}-bit {self.endian} | "
            f"{'stripped' if self.stripped else 'not stripped'} | "
            f"{self.protection.summary}"
        )


@dataclass
class ExploitScript:
    """A pwntools exploit script."""

    id: str = field(default_factory=_uuid)
    code: str = ""
    language: str = "python"
    description: str = ""
    tested: bool = False
    success: bool = False
    output: str = ""

    def mark_tested(self, success: bool, output: str = "") -> None:
        self.tested = True
        self.success = success
        self.output = output


# ═══════════════════════════════════════════════════════════════════
#  Aggregate Root
# ═══════════════════════════════════════════════════════════════════


@dataclass
class PwnChallenge:
    """Aggregate Root — a binary exploitation CTF challenge."""

    id: str = field(default_factory=_uuid)
    name: str = ""
    points: int = 0
    description: str = ""
    remote_host: str = ""
    remote_port: int = 0
    difficulty: Difficulty = Difficulty.MEDIUM
    status: ChallengeStatus = ChallengeStatus.IDENTIFIED
    binary: Binary | None = None
    memory_layout: MemoryLayout | None = None
    gadget_chains: list[GadgetChain] = field(default_factory=list)
    exploit_scripts: list[ExploitScript] = field(default_factory=list)
    vuln_class: str = ""  # "buffer_overflow", "format_string", "heap_overflow", "uaf"
    strategies: list[SolveStrategy] = field(default_factory=list)
    flag: Flag | None = None
    writeup: WriteUp | None = None

    def set_binary(self, binary: Binary) -> None:
        self.binary = binary

    def set_memory_layout(self, layout: MemoryLayout) -> None:
        self.memory_layout = layout

    def add_gadget_chain(self, chain: GadgetChain) -> None:
        self.gadget_chains.append(chain)

    def add_exploit(self, script: ExploitScript) -> None:
        self.exploit_scripts.append(script)

    def get_successful_exploit(self) -> ExploitScript | None:
        return next(
            (s for s in self.exploit_scripts if s.tested and s.success), None
        )

    def solve(self, flag: Flag, writeup: WriteUp | None = None) -> None:
        self.flag = flag
        self.status = ChallengeStatus.SOLVED
        if writeup:
            self.writeup = writeup

    @property
    def is_solved(self) -> bool:
        return self.status == ChallengeStatus.SOLVED and self.flag is not None
