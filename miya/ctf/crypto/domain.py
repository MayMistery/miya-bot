"""Crypto CTF Domain — cryptography challenge models."""

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
class Cipher:
    """Identified cipher algorithm and its parameters."""

    algorithm: str  # "RSA", "AES-CBC", "DES", "ChaCha20", "custom"
    key_size: int = 0
    parameters: dict[str, str] = field(default_factory=dict)
    # RSA: {"n": ..., "e": ..., "c": ...}
    # AES: {"mode": "CBC", "iv": ...}

    @property
    def is_rsa(self) -> bool:
        return self.algorithm.upper().startswith("RSA")

    @property
    def is_aes(self) -> bool:
        return self.algorithm.upper().startswith("AES")

    @property
    def is_classical(self) -> bool:
        return self.algorithm.lower() in (
            "caesar", "vigenere", "substitution", "affine",
            "hill", "playfair", "rail_fence", "xor",
        )


@dataclass(frozen=True)
class CryptoAttack:
    """A cryptographic attack method."""

    name: str  # "wiener", "hastad", "coppersmith", "padding_oracle", etc.
    description: str = ""
    applicable: bool = True
    requirements: tuple[str, ...] = ()  # conditions needed



@dataclass(frozen=True)
class PlainText:
    """Decrypted/recovered plaintext result."""

    value: str
    encoding: str = "utf-8"  # or "hex", "base64"
    partial: bool = False


# ═══════════════════════════════════════════════════════════════════
#  Aggregate Root
# ═══════════════════════════════════════════════════════════════════


@dataclass
class CryptoChallenge:
    """Aggregate Root — a cryptography CTF challenge."""

    id: str = field(default_factory=_uuid)
    name: str = ""
    points: int = 0
    description: str = ""
    difficulty: Difficulty = Difficulty.MEDIUM
    status: ChallengeStatus = ChallengeStatus.IDENTIFIED
    cipher: Cipher | None = None
    attacks_tried: list[CryptoAttack] = field(default_factory=list)
    plaintext: PlainText | None = None
    source_code: str = ""  # challenge source if provided
    ciphertext: str = ""
    provided_files: list[str] = field(default_factory=list)
    strategies: list[SolveStrategy] = field(default_factory=list)
    flag: Flag | None = None
    writeup: WriteUp | None = None

    def identify_cipher(self, cipher: Cipher) -> None:
        self.cipher = cipher

    def try_attack(self, attack: CryptoAttack) -> None:
        if not any(a.name == attack.name for a in self.attacks_tried):
            self.attacks_tried.append(attack)

    def set_plaintext(self, plaintext: PlainText) -> None:
        self.plaintext = plaintext

    def solve(self, flag: Flag, writeup: WriteUp | None = None) -> None:
        self.flag = flag
        self.status = ChallengeStatus.SOLVED
        if writeup:
            self.writeup = writeup

    @property
    def is_solved(self) -> bool:
        return self.status == ChallengeStatus.SOLVED and self.flag is not None
