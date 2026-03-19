"""In-memory repository implementations for DDD aggregates."""

from __future__ import annotations

from typing import Any, TypeVar

T = TypeVar("T")


class InMemoryRepository:
    """Generic in-memory repository implementing RepositoryPort.

    Stores aggregates in a dict keyed by their ``id`` attribute.
    Supports optional keyword filters in ``list_all``.
    """

    def __init__(self) -> None:
        self._store: dict[str, Any] = {}

    async def save(self, aggregate: Any) -> None:
        key = getattr(aggregate, "id", None) or id(aggregate)
        self._store[str(key)] = aggregate

    async def get(self, id: str) -> Any | None:
        return self._store.get(id)

    async def list_all(self, **filters: Any) -> list[Any]:
        results = list(self._store.values())
        for attr, value in filters.items():
            results = [r for r in results if getattr(r, attr, None) == value]
        return results

    async def delete(self, id: str) -> None:
        self._store.pop(id, None)

    def __len__(self) -> int:
        return len(self._store)
