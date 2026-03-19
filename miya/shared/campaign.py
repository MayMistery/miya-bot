"""Campaign — persistent cross-mission knowledge store.

A Campaign groups related missions (e.g. all challenges on one CTF platform)
and provides shared context that survives across individual mission runs.

Unlike the per-mission Blackboard (which starts fresh each time), the Campaign
persists solved challenges, shared infrastructure, cookies, and techniques
across missions in the same session.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class CampaignEntry:
    """A single knowledge entry in the campaign store."""

    key: str  # e.g. "solved:challenge_name", "infra:cookie", "technique:sqli"
    value: str
    category: str = ""  # "solved", "infra", "technique", "credential", "note"
    mission_id: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class Campaign:
    """Session-level persistent knowledge across multiple missions.

    Stored as a simple JSON file alongside the event store DB.
    """

    name: str = "default"
    entries: list[CampaignEntry] = field(default_factory=list)
    _path: Path | None = field(default=None, repr=False)

    # ── Persistence ────────────────────────────────────────────────

    @classmethod
    def load(cls, path: Path | str) -> Campaign:
        """Load campaign from JSON file, or create empty if not exists."""
        p = Path(path)
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                entries = [CampaignEntry(**e) for e in data.get("entries", [])]
                c = cls(name=data.get("name", "default"), entries=entries)
                c._path = p
                return c
            except Exception:
                logger.warning("Failed to load campaign from %s — starting fresh", p, exc_info=True)
        c = cls()
        c._path = p
        return c

    def save(self) -> None:
        """Persist campaign to JSON file (atomic write via temp+rename)."""
        if self._path is None:
            return
        data = {
            "name": self.name,
            "entries": [
                {
                    "key": e.key,
                    "value": e.value,
                    "category": e.category,
                    "mission_id": e.mission_id,
                    "timestamp": e.timestamp,
                }
                for e in self.entries
            ],
        }
        content = json.dumps(data, ensure_ascii=False, indent=2)
        # Atomic write: write to temp file, then rename
        tmp = self._path.with_suffix(".tmp")
        try:
            tmp.write_text(content, encoding="utf-8")
            tmp.replace(self._path)
        except Exception:
            logger.warning("Failed to save campaign to %s", self._path, exc_info=True)
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass

    # ── Knowledge Operations ───────────────────────────────────────

    def add(
        self,
        key: str,
        value: str,
        category: str = "",
        mission_id: str = "",
    ) -> None:
        """Add or update a knowledge entry."""
        # Update existing entry if key matches
        for e in self.entries:
            if e.key == key:
                e.value = value
                e.mission_id = mission_id
                e.timestamp = datetime.now(timezone.utc).isoformat()
                self.save()
                return
        self.entries.append(CampaignEntry(
            key=key, value=value, category=category, mission_id=mission_id,
        ))
        self.save()

    def record_solved(
        self, challenge_name: str, flag: str, technique: str, mission_id: str = "",
    ) -> None:
        """Record a solved challenge."""
        self.add(
            key=f"solved:{challenge_name}",
            value=json.dumps({"flag": flag, "technique": technique}),
            category="solved",
            mission_id=mission_id,
        )

    def record_infra(self, key: str, value: str, mission_id: str = "") -> None:
        """Record shared infrastructure (cookies, URLs, tokens)."""
        self.add(key=f"infra:{key}", value=value, category="infra", mission_id=mission_id)

    def record_technique(self, technique: str, detail: str, mission_id: str = "") -> None:
        """Record a successful technique for cross-challenge reuse."""
        self.add(
            key=f"technique:{technique}",
            value=detail,
            category="technique",
            mission_id=mission_id,
        )

    def record_checkpoint(
        self,
        challenge_name: str,
        status: str,
        reason: str = "",
        mission_id: str = "",
    ) -> None:
        """Record a challenge checkpoint (timeout/failed/in_progress).

        Used by resume to skip challenges that already completed or timed out.
        """
        self.add(
            key=f"checkpoint:{challenge_name}",
            value=json.dumps({"status": status, "reason": reason}),
            category="checkpoint",
            mission_id=mission_id,
        )

    # ── Query ──────────────────────────────────────────────────────

    def get_solved(self) -> list[dict[str, str]]:
        """Get all solved challenges."""
        results = []
        for e in self.entries:
            if e.category == "solved":
                name = e.key.removeprefix("solved:")
                try:
                    data = json.loads(e.value)
                except Exception:
                    data = {"flag": e.value, "technique": ""}
                results.append({"name": name, **data})
        return results

    def get_by_category(self, category: str) -> list[CampaignEntry]:
        """Get entries by category."""
        return [e for e in self.entries if e.category == category]

    def is_solved(self, challenge_name: str) -> bool:
        """Check if a challenge has been solved in this campaign."""
        return any(e.key == f"solved:{challenge_name}" for e in self.entries)

    def get_checkpoint(self, challenge_name: str) -> dict[str, str] | None:
        """Get checkpoint status for a challenge (timeout/failed/etc)."""
        for e in self.entries:
            if e.key == f"checkpoint:{challenge_name}":
                try:
                    return json.loads(e.value)
                except Exception:
                    return {"status": e.value, "reason": ""}
        return None

    def clear_checkpoints(self) -> None:
        """Clear all checkpoint entries (for fresh retry)."""
        self.entries = [e for e in self.entries if e.category != "checkpoint"]
        self.save()

    # ── Context for LLM ───────────────────────────────────────────

    def to_context_prompt(self) -> str:
        """Serialize campaign knowledge for injection into phase prompts."""
        if not self.entries:
            return ""

        lines = ["\n## Campaign Knowledge (cross-mission)"]

        solved = self.get_solved()
        if solved:
            lines.append(f"\n### Previously Solved ({len(solved)})")
            for s in solved:
                lines.append(f"- {s['name']}: {s.get('technique', '?')}")

        infra = self.get_by_category("infra")
        if infra:
            lines.append(f"\n### Shared Infrastructure ({len(infra)})")
            for e in infra[-10:]:
                lines.append(f"- {e.key.removeprefix('infra:')}: {e.value[:80]}")

        techniques = self.get_by_category("technique")
        if techniques:
            lines.append(f"\n### Known Techniques ({len(techniques)})")
            for e in techniques[-10:]:
                lines.append(f"- {e.key.removeprefix('technique:')}: {e.value[:60]}")

        return "\n".join(lines)
