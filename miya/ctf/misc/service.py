"""Misc CTF Domain Service — orchestrates forensics, stego, and misc challenges."""

from __future__ import annotations

from miya.ctf.misc.domain import (
    FileArtifact,
    FileType,
    HiddenData,
    MiscChallenge,
)
from miya.ctf.shared.domain import Flag, WriteUp
from miya.shared.events import ChallengeSolved, DomainEvent
from miya.shared.ports import RepositoryPort


class MiscCTFService:
    """Domain service for misc/forensics/stego CTF challenges."""

    def __init__(
        self,
        challenge_repo: RepositoryPort[MiscChallenge],
    ) -> None:
        self._repo = challenge_repo

    async def create_challenge(
        self,
        name: str,
        points: int = 0,
        description: str = "",
    ) -> MiscChallenge:
        challenge = MiscChallenge(
            name=name,
            points=points,
            description=description,
        )
        await self._repo.save(challenge)
        return challenge

    async def add_artifact(
        self,
        challenge_id: str,
        path: str,
        file_type: FileType = FileType.OTHER,
        size_bytes: int = 0,
        mime_type: str = "",
        hash_md5: str = "",
        hash_sha256: str = "",
        metadata: dict[str, str] | None = None,
    ) -> FileArtifact:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        artifact = FileArtifact(
            path=path,
            file_type=file_type,
            size_bytes=size_bytes,
            mime_type=mime_type,
            hash_md5=hash_md5,
            hash_sha256=hash_sha256,
            metadata=metadata or {},
        )
        challenge.add_artifact(artifact)
        await self._repo.save(challenge)
        return artifact

    async def report_hidden_data(
        self,
        challenge_id: str,
        artifact_id: str,
        data: str,
        extraction_method: str,
        location: str = "",
        encoding: str = "raw",
        confidence: float = 1.0,
    ) -> HiddenData:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        artifact = next(
            (a for a in challenge.artifacts if a.id == artifact_id), None
        )
        if artifact is None:
            raise ValueError(f"Artifact {artifact_id} not found")

        hidden = HiddenData(
            data=data,
            extraction_method=extraction_method,
            location=location,
            encoding=encoding,
            confidence=confidence,
        )
        artifact.add_hidden_data(hidden)
        await self._repo.save(challenge)
        return hidden

    async def add_extracted_file(
        self,
        challenge_id: str,
        artifact_id: str,
        extracted_path: str,
    ) -> None:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        artifact = next(
            (a for a in challenge.artifacts if a.id == artifact_id), None
        )
        if artifact is None:
            raise ValueError(f"Artifact {artifact_id} not found")

        artifact.add_extracted_file(extracted_path)
        await self._repo.save(challenge)

    async def submit_flag(
        self,
        challenge_id: str,
        flag_value: str,
        approach: str = "",
        writeup: WriteUp | None = None,
    ) -> tuple[bool, list[DomainEvent]]:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        flag = Flag(value=flag_value)
        challenge.solve(flag, writeup)
        await self._repo.save(challenge)

        event = ChallengeSolved(
            challenge_name=challenge.name,
            flag=flag_value,
            approach=approach,
            aggregate_id=challenge_id,
            aggregate_type="MiscChallenge",
        )
        return True, [event]
