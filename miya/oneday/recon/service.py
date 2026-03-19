"""Recon bounded context — domain service.

Orchestrates reconnaissance operations: network scanning, asset discovery,
service fingerprinting, and OSINT gathering.
"""

from __future__ import annotations

from miya.shared.ports import (
    EventStorePort,
    NetworkScannerPort,
    AssetIntelPort,
)
from miya.oneday.recon.domain import (
    ReconMission,
    Asset,
    ServiceBanner,
)


class ReconService:
    """Domain service for the recon bounded context.

    Coordinates asset discovery using network scanners and OSINT sources,
    then emits domain events for downstream contexts.
    """

    def __init__(
        self,
        event_store: EventStorePort,
        network_scanner: NetworkScannerPort | None = None,
        asset_intel: AssetIntelPort | None = None,
    ) -> None:
        self._event_store = event_store
        self._scanner = network_scanner
        self._intel = asset_intel

    async def start_recon(
        self,
        target: str,
        correlation_id: str = "",
    ) -> ReconMission:
        """Start a new reconnaissance mission against a target."""
        mission = ReconMission(target_scope=target)
        return mission

    async def scan_target(
        self,
        mission: ReconMission,
        ports: str = "1-1000",
        scan_type: str = "default",
        correlation_id: str = "",
    ) -> list[Asset]:
        """Run network scan and register discovered assets."""
        discovered: list[Asset] = []

        if self._scanner:
            results = await self._scanner.scan(
                target=mission.target_scope,
                ports=ports,
                scan_type=scan_type,
            )
            # Parse scan results into assets
            hosts = results.get("hosts", [])
            for host_data in hosts:
                host = host_data.get("hostname", "")
                ip = host_data.get("ip", "")
                open_ports = tuple(
                    p.get("port", 0)
                    for p in host_data.get("ports", [])
                    if p.get("state") == "open"
                )
                services = tuple(
                    p.get("service", "")
                    for p in host_data.get("ports", [])
                    if p.get("state") == "open"
                )
                os_info = host_data.get("os", "")

                asset = mission.discover_asset(
                    host=host,
                    ip=ip,
                    ports=open_ports,
                    services=services,
                    os=os_info,
                    correlation_id=correlation_id,
                )

                # Collect banners
                for port_info in host_data.get("ports", []):
                    if port_info.get("banner"):
                        banner = ServiceBanner(
                            port=port_info["port"],
                            protocol=port_info.get("protocol", "tcp"),
                            service=port_info.get("service", ""),
                            banner=port_info["banner"],
                            tls=port_info.get("tls", False),
                        )
                        mission.add_banner(asset.id, banner)

                discovered.append(asset)

        # Persist events
        events = mission.collect_events()
        if events:
            await self._event_store.append(events)

        return discovered

    async def enrich_with_osint(
        self,
        mission: ReconMission,
        correlation_id: str = "",
    ) -> None:
        """Enrich discovered assets with OSINT data from Shodan etc."""
        if not self._intel:
            return

        for asset_id, asset in mission.assets.items():
            if asset.ip:
                info = await self._intel.host_info(asset.ip)
                software = info.get("product", "")
                version = info.get("version", "")
                tech_stack = tuple(info.get("technologies", []))

                if software:
                    mission.complete_fingerprint(
                        asset_id=asset_id,
                        software=software,
                        version=version,
                        technology_stack=tech_stack,
                        correlation_id=correlation_id,
                    )

        events = mission.collect_events()
        if events:
            await self._event_store.append(events)

    async def fingerprint_asset(
        self,
        mission: ReconMission,
        asset_id: str,
        software: str,
        version: str,
        technology_stack: tuple[str, ...] = (),
        correlation_id: str = "",
    ) -> None:
        """Manually register fingerprint information for an asset."""
        mission.complete_fingerprint(
            asset_id=asset_id,
            software=software,
            version=version,
            technology_stack=technology_stack,
            correlation_id=correlation_id,
        )
        events = mission.collect_events()
        if events:
            await self._event_store.append(events)

    async def load_mission(self, mission_id: str) -> ReconMission:
        """Reconstitute a ReconMission from the event store."""
        events = await self._event_store.load(mission_id)
        mission = ReconMission(id=mission_id)
        for event in events:
            mission.apply(event)
        return mission
