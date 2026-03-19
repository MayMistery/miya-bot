"""Unit tests for miya.shared.types — value objects, enums, and mission lifecycle."""

from __future__ import annotations

import pytest
from miya.shared.types import (
    Severity,
    MissionType,
    OODAPhase,
    Target,
    Finding,
    Asset,
    Mission,
)


# ═══════════════════════════════════════════════════════════════════
#  Severity
# ═══════════════════════════════════════════════════════════════════


class TestSeverity:
    def test_score_ordering(self):
        assert Severity.CRITICAL.score == 5
        assert Severity.HIGH.score == 4
        assert Severity.MEDIUM.score == 3
        assert Severity.LOW.score == 2
        assert Severity.INFO.score == 1

    def test_comparison(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH >= Severity.HIGH
        assert not Severity.LOW > Severity.MEDIUM

    def test_string_value(self):
        assert Severity.CRITICAL.value == "critical"
        assert str(Severity.CRITICAL) == "Severity.CRITICAL"

    def test_from_string(self):
        assert Severity("critical") is Severity.CRITICAL
        assert Severity("info") is Severity.INFO


# ═══════════════════════════════════════════════════════════════════
#  MissionType & OODAPhase
# ═══════════════════════════════════════════════════════════════════


class TestMissionType:
    def test_values(self):
        assert MissionType.ZERODAY.value == "zeroday"
        assert MissionType.ONEDAY.value == "oneday"
        assert MissionType.CTF.value == "ctf"

    def test_from_string(self):
        assert MissionType("oneday") is MissionType.ONEDAY


class TestOODAPhase:
    def test_all_phases(self):
        phases = [p.value for p in OODAPhase]
        assert phases == ["observe", "orient", "decide", "act", "reflect"]


# ═══════════════════════════════════════════════════════════════════
#  Target
# ═══════════════════════════════════════════════════════════════════


class TestTarget:
    def test_immutable(self):
        t = Target(uri="192.168.1.1", kind="service")
        with pytest.raises(AttributeError):
            t.uri = "changed"  # type: ignore[misc]

    def test_str(self):
        t = Target(uri="192.168.1.1", kind="service")
        assert str(t) == "[service] 192.168.1.1"

    def test_with_meta(self):
        t = Target(uri="/app", kind="source", meta={"language": "python"})
        assert t.meta["language"] == "python"


# ═══════════════════════════════════════════════════════════════════
#  Finding
# ═══════════════════════════════════════════════════════════════════


class TestFinding:
    def test_oneliner(self):
        f = Finding(title="SQL Injection", severity=Severity.CRITICAL)
        assert "CRITICAL" in f.oneliner()
        assert "SQL Injection" in f.oneliner()

    def test_auto_id(self):
        f1 = Finding(title="a")
        f2 = Finding(title="b")
        assert f1.id != f2.id

    def test_auto_timestamp(self):
        f = Finding(title="test")
        assert f.timestamp is not None


# ═══════════════════════════════════════════════════════════════════
#  Asset
# ═══════════════════════════════════════════════════════════════════


class TestAsset:
    def test_address_ip(self):
        a = Asset(ip="10.0.0.1")
        assert a.address == "10.0.0.1"

    def test_address_host(self):
        a = Asset(host="example.com")
        assert a.address == "example.com"

    def test_address_prefers_ip(self):
        a = Asset(host="example.com", ip="10.0.0.1")
        assert a.address == "10.0.0.1"


# ═══════════════════════════════════════════════════════════════════
#  Mission
# ═══════════════════════════════════════════════════════════════════


class TestMission:
    def test_lifecycle(self):
        m = Mission(mission_type=MissionType.ONEDAY, target=Target(uri="10.0.0.1", kind="service"))
        assert m.status == "created"
        m.start()
        assert m.status == "running"
        m.complete()
        assert m.status == "completed"

    def test_fail(self):
        m = Mission()
        m.start()
        m.fail()
        assert m.status == "failed"

    def test_auto_id(self):
        m1 = Mission()
        m2 = Mission()
        assert m1.id != m2.id

    def test_default_topology(self):
        m = Mission()
        assert m.topology == "ooda"

    def test_double_start_raises(self):
        m = Mission()
        m.start()
        with pytest.raises(ValueError, match="Cannot start"):
            m.start()

    def test_complete_without_start_raises(self):
        m = Mission()
        with pytest.raises(ValueError, match="Cannot complete"):
            m.complete()

    def test_fail_completed_raises(self):
        m = Mission()
        m.start()
        m.complete()
        with pytest.raises(ValueError, match="Cannot fail"):
            m.fail()

    def test_fail_from_created(self):
        m = Mission()
        m.fail()
        assert m.status == "failed"


class TestSeverityComparison:
    def test_lt(self):
        assert Severity.LOW < Severity.HIGH
        assert not Severity.HIGH < Severity.LOW

    def test_le(self):
        assert Severity.HIGH <= Severity.HIGH
        assert Severity.LOW <= Severity.HIGH
        assert not Severity.CRITICAL <= Severity.HIGH

    def test_full_ordering(self):
        ordered = sorted(
            [Severity.HIGH, Severity.INFO, Severity.CRITICAL, Severity.LOW, Severity.MEDIUM]
        )
        assert ordered == [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
