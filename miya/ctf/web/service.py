"""Web CTF Domain Service — orchestrates web challenge analysis and exploitation."""

from __future__ import annotations

from miya.ctf.web.domain import (
    HttpEndpoint,
    InjectionPoint,
    WebChallenge,
    WebVulnType,
)
from miya.ctf.shared.domain import Flag, SolveStrategy, WriteUp
from miya.ctf.shared.service import submit_challenge_flag
from miya.shared.events import ChallengeSolved, DomainEvent, VulnerabilityFound
from miya.shared.ports import RepositoryPort, WebScannerPort


class WebCTFService:
    """Domain service for web CTF challenges."""

    def __init__(
        self,
        challenge_repo: RepositoryPort[WebChallenge],
        web_scanner: WebScannerPort | None = None,
    ) -> None:
        self._repo = challenge_repo
        self._scanner = web_scanner

    async def create_challenge(
        self,
        name: str,
        target_url: str,
        points: int = 0,
        description: str = "",
    ) -> WebChallenge:
        challenge = WebChallenge(
            name=name,
            target_url=target_url,
            points=points,
            description=description,
        )
        await self._repo.save(challenge)
        return challenge

    async def add_endpoint(
        self,
        challenge_id: str,
        url: str,
        method: str = "GET",
        parameters: list[str] | None = None,
        technology: str = "",
    ) -> HttpEndpoint:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        endpoint = HttpEndpoint(
            url=url,
            method=method,
            parameters=parameters or [],
            technology=technology,
        )
        challenge.add_endpoint(endpoint)
        await self._repo.save(challenge)
        return endpoint

    async def report_injection(
        self,
        challenge_id: str,
        endpoint_id: str,
        parameter: str,
        injection_type: WebVulnType,
        location: str = "query",
        payload: str = "",
        confirmed: bool = False,
    ) -> list[DomainEvent]:
        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        endpoint = next(
            (e for e in challenge.endpoints if e.id == endpoint_id), None
        )
        if endpoint is None:
            raise ValueError(f"Endpoint {endpoint_id} not found")

        point = InjectionPoint(
            parameter=parameter,
            injection_type=injection_type,
            location=location,
            payload=payload,
            confirmed=confirmed,
        )
        endpoint.add_injection_point(point)
        challenge.identify_vuln(injection_type)
        await self._repo.save(challenge)

        events: list[DomainEvent] = []
        if confirmed:
            events.append(VulnerabilityFound(
                vuln_type=injection_type.value,
                severity="high",
                location=endpoint.url,
                description=f"{injection_type.value} in parameter '{parameter}'",
                context="ctf.web",
                aggregate_id=challenge_id,
                aggregate_type="WebChallenge",
            ))
        return events

    async def scan_endpoint(
        self,
        challenge_id: str,
        endpoint_id: str,
    ) -> list[DomainEvent]:
        if self._scanner is None:
            return []

        challenge = await self._repo.get(challenge_id)
        if challenge is None:
            raise ValueError(f"Challenge {challenge_id} not found")

        endpoint = next(
            (e for e in challenge.endpoints if e.id == endpoint_id), None
        )
        if endpoint is None:
            raise ValueError(f"Endpoint {endpoint_id} not found")

        results = await self._scanner.scan_url(endpoint.url)
        events: list[DomainEvent] = []
        for result in results:
            vuln_type_str = result.get("type", "")
            try:
                vuln_type = WebVulnType(vuln_type_str)
            except ValueError:
                continue

            point = InjectionPoint(
                parameter=result.get("parameter", ""),
                injection_type=vuln_type,
                confirmed=True,
                payload=result.get("payload", ""),
            )
            endpoint.add_injection_point(point)
            challenge.identify_vuln(vuln_type)

            events.append(VulnerabilityFound(
                vuln_type=vuln_type.value,
                severity=result.get("severity", "medium"),
                location=endpoint.url,
                description=result.get("description", ""),
                context="ctf.web",
                aggregate_id=challenge_id,
                aggregate_type="WebChallenge",
            ))

        await self._repo.save(challenge)
        return events

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
