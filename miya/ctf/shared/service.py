"""CTF Shared Domain Service — orchestrates competition and challenge lifecycle."""

from __future__ import annotations

from typing import Any

from miya.ctf.shared.domain import (
    Challenge,
    ChallengeCategory,
    ChallengeStatus,
    Competition,
    Difficulty,
    Flag,
    SolveStrategy,
    WriteUp,
)
from miya.shared.events import ChallengeIdentified, ChallengeSolved, DomainEvent
from miya.shared.ports import RepositoryPort


async def submit_challenge_flag(
    repo: RepositoryPort[Any],
    challenge_id: str,
    flag_value: str,
    approach: str = "",
    writeup: WriteUp | None = None,
) -> tuple[bool, list[DomainEvent]]:
    """Shared flag submission logic for all CTF category services.

    Looks up the challenge, solves it, and emits a ChallengeSolved event.
    The aggregate_type is inferred from the challenge class name.
    """
    challenge = await repo.get(challenge_id)
    if challenge is None:
        raise ValueError(f"Challenge {challenge_id} not found")

    flag = Flag(value=flag_value)
    challenge.solve(flag, writeup)
    await repo.save(challenge)

    event = ChallengeSolved(
        challenge_name=challenge.name,
        flag=flag_value,
        approach=approach,
        aggregate_id=challenge_id,
        aggregate_type=challenge.__class__.__name__,
    )
    return True, [event]


class CTFService:
    """Domain service for managing CTF competitions and challenges."""

    def __init__(self, competition_repo: RepositoryPort[Competition]) -> None:
        self._repo = competition_repo

    async def create_competition(
        self,
        name: str,
        url: str = "",
        flag_format: str = "",
    ) -> Competition:
        comp = Competition(name=name, url=url, flag_format=flag_format)
        await self._repo.save(comp)
        return comp

    async def register_challenge(
        self,
        competition_id: str,
        name: str,
        category: ChallengeCategory,
        points: int = 0,
        description: str = "",
        url: str = "",
        file_paths: list[str] | None = None,
        difficulty: Difficulty = Difficulty.MEDIUM,
    ) -> tuple[Challenge, list[DomainEvent]]:
        comp = await self._repo.get(competition_id)
        if comp is None:
            raise ValueError(f"Competition {competition_id} not found")

        existing = comp.get_challenge_by_name(name)
        if existing:
            return existing, []

        challenge = Challenge(
            name=name,
            category=category,
            points=points,
            description=description,
            url=url,
            file_paths=file_paths or [],
            difficulty=difficulty,
        )
        comp.add_challenge(challenge)
        await self._repo.save(comp)

        event = ChallengeIdentified(
            challenge_name=name,
            category=category.value,
            points=points,
            aggregate_id=challenge.id,
            aggregate_type="Challenge",
        )
        return challenge, [event]

    async def add_strategy(
        self,
        competition_id: str,
        challenge_id: str,
        strategy: SolveStrategy,
    ) -> None:
        comp = await self._repo.get(competition_id)
        if comp is None:
            raise ValueError(f"Competition {competition_id} not found")

        challenge = comp.get_challenge(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        challenge.add_strategy(strategy)
        await self._repo.save(comp)

    async def submit_flag(
        self,
        competition_id: str,
        challenge_id: str,
        flag_value: str,
        approach: str = "",
        writeup: WriteUp | None = None,
    ) -> tuple[bool, list[DomainEvent]]:
        comp = await self._repo.get(competition_id)
        if comp is None:
            raise ValueError(f"Competition {competition_id} not found")

        challenge = comp.get_challenge(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        flag = Flag(value=flag_value)

        if comp.flag_format and not flag.matches_format(comp.flag_format):
            return False, []

        challenge.solve(flag, writeup)
        await self._repo.save(comp)

        event = ChallengeSolved(
            challenge_name=challenge.name,
            flag=flag_value,
            approach=approach,
            aggregate_id=challenge.id,
            aggregate_type="Challenge",
        )
        return True, [event]

    async def update_status(
        self,
        competition_id: str,
        challenge_id: str,
        status: ChallengeStatus,
    ) -> None:
        comp = await self._repo.get(competition_id)
        if comp is None:
            raise ValueError(f"Competition {competition_id} not found")

        challenge = comp.get_challenge(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        challenge.status = status
        await self._repo.save(comp)

    async def get_progress(self, competition_id: str) -> dict[str, int | float]:
        comp = await self._repo.get(competition_id)
        if comp is None:
            raise ValueError(f"Competition {competition_id} not found")

        return {
            "total_challenges": len(comp.challenges),
            "solved": comp.solve_count,
            "total_points": comp.total_points,
            "progress": comp.progress,
        }
