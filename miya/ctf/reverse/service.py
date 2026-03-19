"""Reverse Engineering CTF Domain Service — orchestrates reverse challenges."""

from __future__ import annotations

from miya.ctf.reverse.domain import (
    Algorithm,
    BinaryAnalysis,
    Constraint,
    ReverseChallenge,
)
from miya.ctf.shared.domain import WriteUp
from miya.ctf.shared.service import submit_challenge_flag
from miya.shared.events import DomainEvent
from miya.shared.ports import DebuggerPort, DisassemblerPort, RepositoryPort


class ReverseCTFService:
    """Domain service for reverse engineering CTF challenges."""

    def __init__(
        self,
        challenge_repo: RepositoryPort[ReverseChallenge],
        disassembler: DisassemblerPort | None = None,
        debugger: DebuggerPort | None = None,
    ) -> None:
        self._repo = challenge_repo
        self._disassembler = disassembler
        self._debugger = debugger

    async def create_challenge(
        self,
        name: str,
        binary_path: str = "",
        points: int = 0,
        description: str = "",
    ) -> ReverseChallenge:
        challenge = ReverseChallenge(
            name=name,
            binary_path=binary_path,
            points=points,
            description=description,
        )
        await self._repo.save(challenge)
        return challenge

    async def analyze_binary(
        self,
        challenge_id: str,
        binary_path: str = "",
    ) -> BinaryAnalysis:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        path = binary_path or challenge.binary_path
        analysis = BinaryAnalysis(binary_path=path)

        if self._disassembler:
            await self._disassembler.analyze(path)
            functions = await self._disassembler.get_functions(path)
            analysis.functions = [f.get("name", "") for f in functions]

            main_code = await self._disassembler.decompile(path, "main")
            analysis.decompiled_main = main_code

        challenge.set_analysis(analysis)
        await self._repo.save(challenge)
        return analysis

    async def identify_algorithm(
        self,
        challenge_id: str,
        name: str,
        description: str = "",
        function_address: str = "",
        decompiled_code: str = "",
        is_custom: bool = False,
    ) -> None:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")
        if challenge.analysis is None:
            raise ValueError("Binary analysis not performed yet")

        algo = Algorithm(
            name=name,
            description=description,
            function_address=function_address,
            decompiled_code=decompiled_code,
            is_custom=is_custom,
        )
        challenge.analysis.add_algorithm(algo)
        await self._repo.save(challenge)

    async def add_constraint(
        self,
        challenge_id: str,
        expression: str,
        description: str = "",
        variable: str = "",
        constraint_type: str = "equality",
    ) -> None:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")
        if challenge.analysis is None:
            raise ValueError("Binary analysis not performed yet")

        constraint = Constraint(
            expression=expression,
            description=description,
            variable=variable,
            constraint_type=constraint_type,
        )
        challenge.analysis.add_constraint(constraint)
        await self._repo.save(challenge)

    async def set_solver_script(
        self,
        challenge_id: str,
        script: str,
    ) -> None:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        challenge.set_solver(script)
        await self._repo.save(challenge)

    async def submit_flag(
        self,
        challenge_id: str,
        flag_value: str,
        approach: str = "",
        writeup: WriteUp | None = None,
    ) -> tuple[bool, list[DomainEvent]]:
        return await submit_challenge_flag(
            self._repo, challenge_id, flag_value, approach, writeup,
        )
