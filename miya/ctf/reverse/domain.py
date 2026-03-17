"""Reverse Engineering CTF Domain — reverse challenge models."""

from __future__ import annotations

from dataclasses import dataclass, field

from miya.ctf.shared.domain import (
    ChallengeStatus,
    Difficulty,
    Flag,
    SolveStrategy,
    WriteUp,
    _uuid,
)


# ═══════════════════════════════════════════════════════════════════
#  Value Objects
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class Algorithm:
    """An identified algorithm within a binary."""

    name: str  # "TEA", "RC4", "custom_xor", "base64_variant"
    description: str = ""
    function_address: str = ""  # hex address in binary
    decompiled_code: str = ""
    is_custom: bool = False

    @property
    def is_known_cipher(self) -> bool:
        known = {
            "tea", "xtea", "xxtea", "rc4", "aes", "des", "blowfish",
            "chacha20", "salsa20", "md5", "sha1", "sha256", "crc32",
        }
        return self.name.lower() in known


@dataclass(frozen=True)
class Constraint:
    """An extracted constraint for z3/angr solving."""

    expression: str  # z3 or angr constraint expression
    description: str = ""
    variable: str = ""
    constraint_type: str = ""  # "equality", "range", "modular", "bitwise"

    @property
    def as_z3(self) -> str:
        """Return z3-compatible constraint string."""
        return self.expression


# ═══════════════════════════════════════════════════════════════════
#  Entities
# ═══════════════════════════════════════════════════════════════════


@dataclass
class BinaryAnalysis:
    """Decompilation and analysis result for a binary."""

    id: str = field(default_factory=_uuid)
    binary_path: str = ""
    arch: str = ""  # "x86", "x86_64", "arm", "mips"
    bits: int = 64
    entry_point: str = ""
    functions: list[str] = field(default_factory=list)
    strings_of_interest: list[str] = field(default_factory=list)
    identified_algorithms: list[Algorithm] = field(default_factory=list)
    constraints: list[Constraint] = field(default_factory=list)
    decompiled_main: str = ""
    anti_debug: bool = False
    obfuscated: bool = False
    packing: str = ""  # "UPX", "custom", ""

    def add_algorithm(self, algo: Algorithm) -> None:
        if not any(a.name == algo.name for a in self.identified_algorithms):
            self.identified_algorithms.append(algo)

    def add_constraint(self, constraint: Constraint) -> None:
        self.constraints.append(constraint)

    @property
    def has_solvable_constraints(self) -> bool:
        return len(self.constraints) > 0


# ═══════════════════════════════════════════════════════════════════
#  Aggregate Root
# ═══════════════════════════════════════════════════════════════════


@dataclass
class ReverseChallenge:
    """Aggregate Root — a reverse engineering CTF challenge."""

    id: str = field(default_factory=_uuid)
    name: str = ""
    points: int = 0
    description: str = ""
    difficulty: Difficulty = Difficulty.MEDIUM
    status: ChallengeStatus = ChallengeStatus.IDENTIFIED
    binary_path: str = ""
    analysis: BinaryAnalysis | None = None
    solver_script: str = ""  # z3 / angr solver code
    strategies: list[SolveStrategy] = field(default_factory=list)
    flag: Flag | None = None
    writeup: WriteUp | None = None

    def set_analysis(self, analysis: BinaryAnalysis) -> None:
        self.analysis = analysis

    def set_solver(self, script: str) -> None:
        self.solver_script = script

    def solve(self, flag: Flag, writeup: WriteUp | None = None) -> None:
        self.flag = flag
        self.status = ChallengeStatus.SOLVED
        if writeup:
            self.writeup = writeup

    @property
    def is_solved(self) -> bool:
        return self.status == ChallengeStatus.SOLVED and self.flag is not None
