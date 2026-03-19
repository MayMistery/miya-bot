"""PoC context — ports (driven-side interfaces).

These are consumed by the domain service and implemented by infrastructure.
The PoC context primarily uses SandboxPort from shared ports, but defines
its own port for PoC-specific execution needs.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class PoCExecutorPort(Protocol):
    """Executes PoC exploit code in a controlled environment.

    Wraps sandbox execution with PoC-specific concerns:
    target setup, payload delivery, evidence collection.
    """

    async def execute_poc(
        self,
        poc_code: str,
        language: str = "python",
        timeout: int = 30,
        env_vars: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Execute PoC code and return stdout/stderr/exit_code/evidence."""
        ...

    async def execute_payload(
        self,
        payload: str,
        delivery_method: str,
        target: str,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Deliver a payload to a target and capture the result."""
        ...
