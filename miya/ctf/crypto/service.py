"""Crypto CTF Domain Service — orchestrates cryptography challenges."""

from __future__ import annotations

from miya.ctf.crypto.domain import (
    Cipher,
    CryptoAttack,
    CryptoChallenge,
    PlainText,
)
from miya.ctf.shared.domain import WriteUp
from miya.ctf.shared.service import submit_challenge_flag
from miya.shared.events import DomainEvent
from miya.shared.ports import RepositoryPort


class CryptoCTFService:
    """Domain service for crypto CTF challenges."""

    def __init__(
        self,
        challenge_repo: RepositoryPort[CryptoChallenge],
    ) -> None:
        self._repo = challenge_repo

    async def create_challenge(
        self,
        name: str,
        points: int = 0,
        description: str = "",
        source_code: str = "",
        ciphertext: str = "",
        provided_files: list[str] | None = None,
    ) -> CryptoChallenge:
        challenge = CryptoChallenge(
            name=name,
            points=points,
            description=description,
            source_code=source_code,
            ciphertext=ciphertext,
            provided_files=provided_files or [],
        )
        await self._repo.save(challenge)
        return challenge

    async def identify_cipher(
        self,
        challenge_id: str,
        algorithm: str,
        key_size: int = 0,
        parameters: dict[str, str] | None = None,
    ) -> Cipher:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        cipher = Cipher(
            algorithm=algorithm,
            key_size=key_size,
            parameters=parameters or {},
        )
        challenge.identify_cipher(cipher)
        await self._repo.save(challenge)
        return cipher

    async def try_attack(
        self,
        challenge_id: str,
        attack_name: str,
        description: str = "",
    ) -> None:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        attack = CryptoAttack(name=attack_name, description=description)
        challenge.try_attack(attack)
        await self._repo.save(challenge)

    async def set_plaintext(
        self,
        challenge_id: str,
        value: str,
        encoding: str = "utf-8",
        partial: bool = False,
    ) -> PlainText:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        plaintext = PlainText(value=value, encoding=encoding, partial=partial)
        challenge.set_plaintext(plaintext)
        await self._repo.save(challenge)
        return plaintext

    async def suggest_rsa_attacks(
        self,
        challenge_id: str,
    ) -> list[CryptoAttack]:
        """Suggest applicable RSA attacks based on challenge parameters."""
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        if challenge.cipher is None or not challenge.cipher.is_rsa:
            return []

        params = challenge.cipher.parameters
        attacks: list[CryptoAttack] = []

        e = params.get("e", "")
        if e and int(e) < 100:
            attacks.append(CryptoAttack(
                name="hastad",
                description="Small public exponent — try Hastad's broadcast attack",
            ))
        if e and int(e) > 2**20:
            attacks.append(CryptoAttack(
                name="wiener",
                description="Large public exponent — try Wiener's continued fraction attack",
            ))
        if params.get("n"):
            attacks.append(CryptoAttack(
                name="fermat",
                description="Try Fermat factorization for close primes",
            ))
            attacks.append(CryptoAttack(
                name="pollard_p1",
                description="Try Pollard's p-1 for smooth prime factors",
            ))

        return attacks

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
