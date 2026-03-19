"""Misc CTF Domain — forensics, stego, and miscellaneous challenge models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from miya.ctf.shared.domain import (
    ChallengeStatus,
    Difficulty,
    Flag,
    SolveStrategy,
    WriteUp,
    _uuid,
)


# ═══════════════════════════════════════════════════════════════════
#  Enums
# ═══════════════════════════════════════════════════════════════════


class FileType(str, Enum):
    PCAP = "pcap"
    MEMORY_DUMP = "memory_dump"
    IMAGE = "image"
    AUDIO = "audio"
    PDF = "pdf"
    ARCHIVE = "archive"
    DISK_IMAGE = "disk_image"
    LOG_FILE = "log_file"
    OTHER = "other"


# ═══════════════════════════════════════════════════════════════════
#  Value Objects
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class HiddenData:
    """Steganography or embedded data found in a file."""

    data: str
    extraction_method: str  # "lsb", "strings", "exiftool", "binwalk", "volatility"
    location: str = ""  # where in the file it was found
    encoding: str = "raw"  # "raw", "base64", "hex"
    confidence: float = 1.0


# ═══════════════════════════════════════════════════════════════════
#  Entities
# ═══════════════════════════════════════════════════════════════════


@dataclass
class FileArtifact:
    """A file sample to analyze (pcap, memory dump, image, etc.)."""

    id: str = field(default_factory=_uuid)
    path: str = ""
    file_type: FileType = FileType.OTHER
    size_bytes: int = 0
    mime_type: str = ""
    hash_md5: str = ""
    hash_sha256: str = ""
    metadata: dict[str, str] = field(default_factory=dict)
    hidden_data: list[HiddenData] = field(default_factory=list)
    extracted_files: list[str] = field(default_factory=list)
    strings_of_interest: list[str] = field(default_factory=list)

    def add_hidden_data(self, data: HiddenData) -> None:
        self.hidden_data.append(data)

    def add_extracted_file(self, path: str) -> None:
        if path not in self.extracted_files:
            self.extracted_files.append(path)

    @property
    def has_hidden_data(self) -> bool:
        return len(self.hidden_data) > 0


# ═══════════════════════════════════════════════════════════════════
#  Aggregate Root
# ═══════════════════════════════════════════════════════════════════


@dataclass
class MiscChallenge:
    """Aggregate Root — a misc/forensics/stego CTF challenge."""

    id: str = field(default_factory=_uuid)
    name: str = ""
    points: int = 0
    description: str = ""
    difficulty: Difficulty = Difficulty.MEDIUM
    status: ChallengeStatus = ChallengeStatus.IDENTIFIED
    artifacts: list[FileArtifact] = field(default_factory=list)
    strategies: list[SolveStrategy] = field(default_factory=list)
    flag: Flag | None = None
    writeup: WriteUp | None = None

    def add_artifact(self, artifact: FileArtifact) -> None:
        if not any(a.id == artifact.id for a in self.artifacts):
            self.artifacts.append(artifact)

    def get_artifacts_by_type(self, file_type: FileType) -> list[FileArtifact]:
        return [a for a in self.artifacts if a.file_type == file_type]

    def all_hidden_data(self) -> list[HiddenData]:
        return [hd for artifact in self.artifacts for hd in artifact.hidden_data]

    def solve(self, flag: Flag, writeup: WriteUp | None = None) -> None:
        self.flag = flag
        self.status = ChallengeStatus.SOLVED
        if writeup:
            self.writeup = writeup

    @property
    def is_solved(self) -> bool:
        return self.status == ChallengeStatus.SOLVED and self.flag is not None
