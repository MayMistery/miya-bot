"""Pwn CTF Domain Service — orchestrates binary exploitation challenges."""

from __future__ import annotations

from miya.ctf.pwn.domain import (
    Binary,
    ExploitScript,
    GadgetChain,
    MemoryLayout,
    Protection,
    PwnChallenge,
)
from miya.ctf.shared.domain import WriteUp
from miya.ctf.shared.service import submit_challenge_flag
from miya.shared.events import DomainEvent
from miya.shared.ports import DebuggerPort, DisassemblerPort, RepositoryPort


class PwnCTFService:
    """Domain service for pwn CTF challenges."""

    def __init__(
        self,
        challenge_repo: RepositoryPort[PwnChallenge],
        disassembler: DisassemblerPort | None = None,
        debugger: DebuggerPort | None = None,
    ) -> None:
        self._repo = challenge_repo
        self._disassembler = disassembler
        self._debugger = debugger

    async def create_challenge(
        self,
        name: str,
        points: int = 0,
        description: str = "",
        remote_host: str = "",
        remote_port: int = 0,
    ) -> PwnChallenge:
        challenge = PwnChallenge(
            name=name,
            points=points,
            description=description,
            remote_host=remote_host,
            remote_port=remote_port,
        )
        await self._repo.save(challenge)
        return challenge

    async def analyze_binary(
        self,
        challenge_id: str,
        binary_path: str,
        arch: str = "x86_64",
        bits: int = 64,
    ) -> Binary:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        binary = Binary(path=binary_path, arch=arch, bits=bits)

        if self._disassembler:
            await self._disassembler.analyze(binary_path)
            functions = await self._disassembler.get_functions(binary_path)
            binary.functions = [f.get("name", "") for f in functions]

            dangerous = {"gets", "strcpy", "strcat", "sprintf", "scanf", "read"}
            binary.dangerous_functions = [
                f for f in binary.functions if f in dangerous
            ]

        challenge.set_binary(binary)
        await self._repo.save(challenge)
        return binary

    async def set_protections(
        self,
        challenge_id: str,
        nx: bool = True,
        aslr: bool = True,
        pie: bool = False,
        canary: bool = False,
        relro: str = "none",
    ) -> None:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")
        if challenge.binary is None:
            raise ValueError("Binary not set for this challenge")

        challenge.binary.protection = Protection(
            nx=nx, aslr=aslr, pie=pie, canary=canary,
            relro=relro,  # type: ignore[arg-type]
        )
        await self._repo.save(challenge)

    async def set_memory_layout(
        self,
        challenge_id: str,
        layout: MemoryLayout,
    ) -> None:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        challenge.set_memory_layout(layout)
        await self._repo.save(challenge)

    async def add_gadget_chain(
        self,
        challenge_id: str,
        gadgets: list[str],
        description: str = "",
        chain_type: str = "rop",
    ) -> None:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        chain = GadgetChain(
            gadgets=tuple(gadgets),
            description=description,
            chain_type=chain_type,
        )
        challenge.add_gadget_chain(chain)
        await self._repo.save(challenge)

    async def add_exploit(
        self,
        challenge_id: str,
        code: str,
        description: str = "",
    ) -> ExploitScript:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        script = ExploitScript(code=code, description=description)
        challenge.add_exploit(script)
        await self._repo.save(challenge)
        return script

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
