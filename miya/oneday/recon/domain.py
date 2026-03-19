"""Recon bounded context — domain model.

Aggregate Root: ReconMission
Entities: Asset
Value Objects: Fingerprint, ServiceBanner
"""

from __future__ import annotations

from dataclasses import dataclass, field
from miya.shared.events import (
    DomainEvent,
    AssetDiscovered,
    FingerprintCompleted,
)
from miya.shared.types import new_id as _uuid


# ═══════════════════════════════════════════════════════════════════
#  Value Objects
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class Fingerprint:
    """Software fingerprint for a discovered service."""

    software: str = ""
    version: str = ""
    os: str = ""
    technology_stack: tuple[str, ...] = ()


@dataclass(frozen=True)
class ServiceBanner:
    """Raw banner data captured from a service probe."""

    port: int = 0
    protocol: str = ""  # "tcp", "udp"
    service: str = ""  # "http", "ssh", "mysql"
    banner: str = ""  # raw banner string
    tls: bool = False


# ═══════════════════════════════════════════════════════════════════
#  Entity
# ═══════════════════════════════════════════════════════════════════


@dataclass
class Asset:
    """A discovered network asset — host, service, or endpoint."""

    id: str = field(default_factory=_uuid)
    host: str = ""
    ip: str = ""
    ports: tuple[int, ...] = ()
    services: tuple[str, ...] = ()
    os: str = ""
    fingerprint: Fingerprint | None = None
    banners: list[ServiceBanner] = field(default_factory=list)

    @property
    def address(self) -> str:
        return self.ip or self.host


# ═══════════════════════════════════════════════════════════════════
#  Aggregate Root
# ═══════════════════════════════════════════════════════════════════


@dataclass
class ReconMission:
    """Aggregate root for the recon bounded context.

    Manages asset discovery for a target scope. Tracks all discovered
    assets and their fingerprints. Emits domain events for each discovery.
    """

    id: str = field(default_factory=_uuid)
    target_scope: str = ""  # CIDR, domain, or single host
    assets: dict[str, Asset] = field(default_factory=dict)
    version: int = 0
    pending_events: list[DomainEvent] = field(default_factory=list)

    # ── Commands ──────────────────────────────────────────────────

    def discover_asset(
        self,
        host: str,
        ip: str = "",
        ports: tuple[int, ...] = (),
        services: tuple[str, ...] = (),
        os: str = "",
        correlation_id: str = "",
    ) -> Asset:
        """Register a newly discovered asset."""
        asset = Asset(host=host, ip=ip, ports=ports, services=services, os=os)
        self.assets[asset.id] = asset
        self.version += 1

        event = AssetDiscovered(
            aggregate_id=self.id,
            aggregate_type="ReconMission",
            host=host,
            ip=ip,
            ports=ports,
            services=services,
            os=os,
            correlation_id=correlation_id,
            version=self.version,
            mission="oneday",
        )
        self.pending_events.append(event)
        return asset

    def complete_fingerprint(
        self,
        asset_id: str,
        software: str,
        version: str,
        technology_stack: tuple[str, ...] = (),
        correlation_id: str = "",
    ) -> None:
        """Attach fingerprint information to a discovered asset."""
        if asset_id not in self.assets:
            raise ValueError(f"Asset {asset_id} not found in this mission")

        fp = Fingerprint(
            software=software,
            version=version,
            os=self.assets[asset_id].os,
            technology_stack=technology_stack,
        )
        self.assets[asset_id].fingerprint = fp
        self.version += 1

        event = FingerprintCompleted(
            aggregate_id=self.id,
            aggregate_type="ReconMission",
            asset_id=asset_id,
            software=software,
            version=version,
            technology_stack=technology_stack,
            correlation_id=correlation_id,
            mission="oneday",
        )
        self.pending_events.append(event)

    def add_banner(self, asset_id: str, banner: ServiceBanner) -> None:
        """Add a service banner to an existing asset."""
        if asset_id not in self.assets:
            raise ValueError(f"Asset {asset_id} not found in this mission")
        self.assets[asset_id].banners.append(banner)

    # ── Event Sourcing ────────────────────────────────────────────

    def apply(self, event: DomainEvent) -> None:
        """Reconstitute state from a persisted event."""
        if isinstance(event, AssetDiscovered):
            asset = Asset(
                host=event.host,
                ip=event.ip,
                ports=event.ports,
                services=event.services,
                os=event.os,
            )
            self.assets[asset.id] = asset
            self.version = event.version

        elif isinstance(event, FingerprintCompleted):
            if event.asset_id in self.assets:
                self.assets[event.asset_id].fingerprint = Fingerprint(
                    software=event.software,
                    version=event.version,
                    technology_stack=event.technology_stack,
                )
            self.version = event.version

    def collect_events(self) -> list[DomainEvent]:
        """Drain pending events."""
        events = list(self.pending_events)
        self.pending_events.clear()
        return events
