"""Tests for v2 optimizations: event regex, target detection, repos, logging, topology config."""

from __future__ import annotations

import os
import pytest

from miya.shared.types import Mission, MissionType, Target
from miya.topology.base import extract_events_from_output, _get_topology_config


# ═══════════════════════════════════════════════════════════════════
#  Event extraction regex improvements
# ═══════════════════════════════════════════════════════════════════


class TestEventExtractionRegex:
    """The regex should handle optional/missing spaces between type name and brace."""

    @pytest.fixture
    def mission(self):
        return Mission(
            mission_type=MissionType.ONEDAY,
            target=Target(uri="test.com", kind="service"),
        )

    def test_with_space(self, mission):
        output = '[EVENT:AssetDiscovered {"host": "a.com", "ip": "1.2.3.4", "ports": [80], "services": ["http"], "os": "Linux", "context": "recon"}]'
        events = extract_events_from_output(output, mission)
        assert len(events) == 1
        assert events[0].__class__.__name__ == "AssetDiscovered"

    def test_without_space(self, mission):
        """No space between type name and opening brace should also work."""
        output = '[EVENT:AssetDiscovered{"host": "b.com", "ip": "5.6.7.8", "ports": [443], "services": ["https"], "os": "Linux", "context": "recon"}]'
        events = extract_events_from_output(output, mission)
        assert len(events) == 1
        assert events[0].__class__.__name__ == "AssetDiscovered"

    def test_multiple_spaces(self, mission):
        output = '[EVENT:VulnerabilityFound   {"vuln_type": "XSS", "cwe_id": "CWE-79", "severity": "high", "context": "vuln"}]'
        events = extract_events_from_output(output, mission)
        assert len(events) == 1

    def test_multiple_events_mixed_spacing(self, mission):
        output = (
            'Found: [EVENT:AssetDiscovered {"host": "a.com", "ip": "1.1.1.1", "ports": [22], "services": ["ssh"], "os": "Linux"}] '
            'and [EVENT:VulnerabilityFound{"vuln_type": "SQLi", "cwe_id": "CWE-89", "severity": "critical"}]'
        )
        events = extract_events_from_output(output, mission)
        assert len(events) == 2

    def test_malformed_json_skipped(self, mission):
        output = '[EVENT:AssetDiscovered {"host": "bad", "ip": INVALID}]'
        events = extract_events_from_output(output, mission)
        assert len(events) == 0

    def test_unknown_event_type_skipped(self, mission):
        output = '[EVENT:NonExistentEvent {"field": "value"}]'
        events = extract_events_from_output(output, mission)
        assert len(events) == 0

    def test_unbalanced_braces_skipped(self, mission):
        output = '[EVENT:AssetDiscovered {"host": "broken"'
        events = extract_events_from_output(output, mission)
        assert len(events) == 0

    def test_nested_json(self, mission):
        """Events with nested JSON objects should parse correctly."""
        output = '[EVENT:AssetDiscovered {"host": "deep.com", "ip": "10.0.0.1", "ports": [80], "services": ["http"], "os": "Linux"}]'
        events = extract_events_from_output(output, mission)
        assert len(events) == 1

    def test_default_mission_context(self, mission):
        """Events should inherit mission context if not specified."""
        output = '[EVENT:AssetDiscovered {"host": "x.com", "ip": "2.2.2.2", "ports": [8080], "services": ["http"], "os": ""}]'
        events = extract_events_from_output(output, mission)
        assert len(events) == 1
        assert events[0].mission == "oneday"
        assert events[0].aggregate_id == mission.id


# ═══════════════════════════════════════════════════════════════════
#  Target kind detection
# ═══════════════════════════════════════════════════════════════════


class TestTargetKindDetection:
    def test_http_url(self):
        from miya.main import _detect_target_kind
        assert _detect_target_kind("http://example.com/chall") == "url"

    def test_https_url(self):
        from miya.main import _detect_target_kind
        assert _detect_target_kind("https://ctf.example.com") == "url"

    def test_absolute_path(self):
        from miya.main import _detect_target_kind
        assert _detect_target_kind("/tmp/nonexistent_chall") in ("binary", "source")

    def test_challenge_name(self):
        from miya.main import _detect_target_kind
        assert _detect_target_kind("baby_crypto") == "challenge"

    def test_relative_path(self):
        from miya.main import _detect_target_kind
        assert _detect_target_kind("./chall.py") in ("binary", "source")


# ═══════════════════════════════════════════════════════════════════
#  In-memory repository
# ═══════════════════════════════════════════════════════════════════


class TestInMemoryRepository:
    @pytest.mark.asyncio
    async def test_save_and_get(self):
        from miya.infra.repositories import InMemoryRepository
        from dataclasses import dataclass

        @dataclass
        class Dummy:
            id: str
            name: str

        repo = InMemoryRepository()
        item = Dummy(id="1", name="test")
        await repo.save(item)
        assert await repo.get("1") == item

    @pytest.mark.asyncio
    async def test_list_all_with_filter(self):
        from miya.infra.repositories import InMemoryRepository
        from dataclasses import dataclass

        @dataclass
        class Dummy:
            id: str
            category: str

        repo = InMemoryRepository()
        await repo.save(Dummy(id="1", category="web"))
        await repo.save(Dummy(id="2", category="pwn"))
        await repo.save(Dummy(id="3", category="web"))

        web_items = await repo.list_all(category="web")
        assert len(web_items) == 2

    @pytest.mark.asyncio
    async def test_delete(self):
        from miya.infra.repositories import InMemoryRepository
        from dataclasses import dataclass

        @dataclass
        class Dummy:
            id: str

        repo = InMemoryRepository()
        await repo.save(Dummy(id="1"))
        assert await repo.get("1") is not None
        await repo.delete("1")
        assert await repo.get("1") is None

    @pytest.mark.asyncio
    async def test_len(self):
        from miya.infra.repositories import InMemoryRepository
        from dataclasses import dataclass

        @dataclass
        class Dummy:
            id: str

        repo = InMemoryRepository()
        assert len(repo) == 0
        await repo.save(Dummy(id="1"))
        assert len(repo) == 1


# ═══════════════════════════════════════════════════════════════════
#  Topology configuration
# ═══════════════════════════════════════════════════════════════════


class TestTopologyConfig:
    def test_defaults(self, monkeypatch):
        monkeypatch.delenv("MIYA_OODA_MAX_ITERATIONS", raising=False)
        monkeypatch.delenv("MIYA_AG_MAX_STEPS", raising=False)
        monkeypatch.delenv("MIYA_MAX_TURNS", raising=False)
        cfg = _get_topology_config()
        assert cfg["ooda_max_iterations"] == 10
        assert cfg["ag_max_steps"] == 20
        assert cfg["max_turns"] == 30

    def test_custom_values(self, monkeypatch):
        monkeypatch.setenv("MIYA_OODA_MAX_ITERATIONS", "5")
        monkeypatch.setenv("MIYA_AG_MAX_STEPS", "15")
        monkeypatch.setenv("MIYA_MAX_TURNS", "50")
        cfg = _get_topology_config()
        assert cfg["ooda_max_iterations"] == 5
        assert cfg["ag_max_steps"] == 15
        assert cfg["max_turns"] == 50

    def test_invalid_values_use_defaults(self, monkeypatch):
        monkeypatch.setenv("MIYA_OODA_MAX_ITERATIONS", "not_a_number")
        cfg = _get_topology_config()
        assert cfg["ooda_max_iterations"] == 10


# ═══════════════════════════════════════════════════════════════════
#  Logging setup
# ═══════════════════════════════════════════════════════════════════


class TestLoggingSetup:
    def test_setup_logging_doesnt_crash(self):
        from miya.infra.logging_config import setup_logging
        setup_logging()  # should not raise

    def test_json_format(self, monkeypatch):
        monkeypatch.setenv("MIYA_LOG_FORMAT", "json")
        from miya.infra.logging_config import setup_logging
        setup_logging()  # should not raise
