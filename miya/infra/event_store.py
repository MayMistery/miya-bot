"""SQLite-backed EventStore — append-only event persistence with event sourcing support."""

from __future__ import annotations

import json
import aiosqlite
from datetime import datetime
from pathlib import Path
from typing import Any

from miya.shared.events import DomainEvent, event_from_dict
from miya.shared.ports import EventStorePort


_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id       TEXT UNIQUE NOT NULL,
    event_type     TEXT NOT NULL,
    aggregate_id   TEXT NOT NULL DEFAULT '',
    aggregate_type TEXT NOT NULL DEFAULT '',
    context        TEXT NOT NULL DEFAULT '',
    mission        TEXT NOT NULL DEFAULT '',
    payload        TEXT NOT NULL,
    metadata       TEXT NOT NULL,
    version        INTEGER NOT NULL DEFAULT 0,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_aggregate ON events(aggregate_type, aggregate_id);
CREATE INDEX IF NOT EXISTS idx_events_context ON events(context, mission);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
"""


class ConcurrencyError(Exception):
    """Raised when optimistic concurrency check fails."""


class SQLiteEventStore(EventStorePort):
    """Append-only event store backed by SQLite."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = str(db_path)
        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        """Create tables if they don't exist."""
        self._db = await aiosqlite.connect(self._db_path)
        await self._db.executescript(_SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    async def __aenter__(self) -> SQLiteEventStore:
        await self.initialize()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    def _ensure_connected(self) -> aiosqlite.Connection:
        if not self._db:
            raise RuntimeError("EventStore not initialized. Call initialize() or use async with.")
        return self._db

    async def append(
        self,
        events: list[DomainEvent],
        expected_version: int = -1,
    ) -> None:
        db = self._ensure_connected()

        for event in events:
            payload = event.to_dict()
            metadata = json.dumps({
                "correlation_id": event.correlation_id,
                "causation_id": event.causation_id,
                "timestamp": event.timestamp.isoformat(),
            })

            # Optimistic concurrency check
            if expected_version >= 0 and event.aggregate_id:
                async with db.execute(
                    "SELECT MAX(version) FROM events WHERE aggregate_id = ?",
                    (event.aggregate_id,),
                ) as cursor:
                    row = await cursor.fetchone()
                    current = row[0] if row and row[0] is not None else -1
                    if current != expected_version:
                        raise ConcurrencyError(
                            f"Expected version {expected_version}, got {current} "
                            f"for aggregate {event.aggregate_id}"
                        )

            await db.execute(
                """INSERT INTO events
                   (event_id, event_type, aggregate_id, aggregate_type,
                    context, mission, payload, metadata, version)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.event_id,
                    event.__class__.event_type,
                    event.aggregate_id,
                    event.aggregate_type,
                    event.context,
                    event.mission,
                    json.dumps(payload),
                    metadata,
                    event.version,
                ),
            )
        await db.commit()

    async def load(self, aggregate_id: str) -> list[DomainEvent]:
        db = self._ensure_connected()
        async with db.execute(
            "SELECT payload FROM events WHERE aggregate_id = ? ORDER BY id",
            (aggregate_id,),
        ) as cursor:
            rows = await cursor.fetchall()
        return [event_from_dict(json.loads(row[0])) for row in rows]

    async def load_by_context(self, context: str, mission: str = "") -> list[DomainEvent]:
        db = self._ensure_connected()
        if mission:
            sql = "SELECT payload FROM events WHERE context = ? AND mission = ? ORDER BY id"
            params: tuple[str, ...] = (context, mission)
        else:
            sql = "SELECT payload FROM events WHERE context = ? ORDER BY id"
            params = (context,)
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
        return [event_from_dict(json.loads(row[0])) for row in rows]

    async def load_all(self, since: datetime | None = None) -> list[DomainEvent]:
        db = self._ensure_connected()
        if since:
            sql = "SELECT payload FROM events WHERE created_at >= ? ORDER BY id"
            async with db.execute(sql, (since.isoformat(),)) as cursor:
                rows = await cursor.fetchall()
        else:
            async with db.execute("SELECT payload FROM events ORDER BY id") as cursor:
                rows = await cursor.fetchall()
        return [event_from_dict(json.loads(row[0])) for row in rows]

    async def count(self) -> int:
        db = self._ensure_connected()
        async with db.execute("SELECT COUNT(*) FROM events") as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

    async def load_by_type(self, event_type: str) -> list[DomainEvent]:
        db = self._ensure_connected()
        async with db.execute(
            "SELECT payload FROM events WHERE event_type = ? ORDER BY id",
            (event_type,),
        ) as cursor:
            rows = await cursor.fetchall()
        return [event_from_dict(json.loads(row[0])) for row in rows]
