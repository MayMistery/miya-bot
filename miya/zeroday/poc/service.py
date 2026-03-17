"""PoC context — domain service.

Orchestrates PoC construction, execution, and validation using ports.
"""

from __future__ import annotations

from miya.shared.events import DomainEvent
from miya.shared.ports import SandboxPort

from .domain import PoCPayload, PoCProject, PoCResult
from .ports import PoCExecutorPort


class PoCService:
    """Domain service for PoC construction and validation.

    Uses SandboxPort for safe code execution and optionally
    PoCExecutorPort for more sophisticated payload delivery.
    """

    def __init__(
        self,
        sandbox: SandboxPort,
        executor: PoCExecutorPort | None = None,
    ) -> None:
        self._sandbox = sandbox
        self._executor = executor

    async def execute_poc(
        self,
        project: PoCProject,
        poc_code: str,
        language: str = "python",
        timeout: int = 30,
    ) -> list[DomainEvent]:
        """Execute a complete PoC script and validate the result.

        Runs the PoC code in a sandbox, captures output, and determines
        whether the exploit was successful.
        """
        raw = await self._sandbox.execute(
            code=poc_code,
            language=language,
            timeout=timeout,
        )

        result = PoCResult(
            stdout=raw.get("stdout", ""),
            stderr=raw.get("stderr", ""),
            exit_code=raw.get("exit_code", -1),
            success=raw.get("exit_code", -1) == 0 and not raw.get("stderr", ""),
            evidence=raw.get("stdout", ""),
            duration_ms=raw.get("duration_ms", 0),
            error_message=raw.get("error", ""),
        )

        project.validate(poc_code, result)
        return project.collect_events()

    async def execute_payload(
        self,
        project: PoCProject,
        payload: PoCPayload,
        target: str = "",
    ) -> PoCResult:
        """Execute a single payload against the target.

        Uses PoCExecutorPort for delivery-method-aware execution,
        falling back to sandbox for script-based payloads.
        """
        if self._executor is not None and payload.delivery_method:
            raw = await self._executor.execute_payload(
                payload=payload.content,
                delivery_method=payload.delivery_method,
                target=target or project.target_endpoint,
                timeout=30,
            )
        else:
            raw = await self._sandbox.execute(
                code=payload.content,
                language=project.language,
                timeout=30,
            )

        result = PoCResult(
            stdout=raw.get("stdout", ""),
            stderr=raw.get("stderr", ""),
            exit_code=raw.get("exit_code", -1),
            success=raw.get("exit_code", -1) == 0,
            evidence=raw.get("stdout", ""),
            duration_ms=raw.get("duration_ms", 0),
            error_message=raw.get("error", ""),
        )

        project.record_result(payload.id, result)
        return result

    async def iterate_payloads(
        self,
        project: PoCProject,
        target: str = "",
    ) -> list[DomainEvent]:
        """Execute all payloads in sequence, validate on first success.

        Tries each payload; on first success, records the PoC code
        and emits PoCValidated event.
        """
        for payload in project.payloads:
            result = await self.execute_payload(project, payload, target)

            if result.success:
                # Build final PoC from the successful payload
                poc_code = (
                    f"# PoC for {project.vuln_type} ({project.cwe_id})\n"
                    f"# Target: {project.target_endpoint}\n"
                    f"# Payload: {payload.name}\n\n"
                    f"{payload.content}"
                )
                project.validate(poc_code, result)
                return project.collect_events()

        # No payload succeeded — return empty (no PoCValidated emitted)
        return project.collect_events()
