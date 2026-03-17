"""Tests for shared kernel — types and events."""

from __future__ import annotations

import asyncio

import pytest

from miya.shared.types import Severity, Target, Finding
from miya.shared.events import (
    DomainEvent,
    EventBus,
    VulnDiscovered,
    ExploitSucceeded,
    ChallengeSolved,
)


class TestTarget:
    def test_creation(self):
        t = Target(uri="/tmp/app", kind="source")
        assert t.uri == "/tmp/app"
        assert t.kind == "source"

    def test_immutable(self):
        t = Target(uri="/tmp/app", kind="source")
        with pytest.raises(AttributeError):
            t.uri = "/other"  # type: ignore[misc]

    def test_str(self):
        t = Target(uri="http://target:8080", kind="service")
        assert "[service]" in str(t)


class TestFinding:
    def test_oneliner(self):
        f = Finding(
            title="SQL Injection in login",
            severity=Severity.CRITICAL,
            detail="Unsanitized input in SQL query",
            evidence="' OR 1=1 --",
            context="zeroday",
        )
        assert f.oneliner() == "[CRITICAL] SQL Injection in login"

    def test_immutable(self):
        f = Finding(
            title="XSS",
            severity=Severity.HIGH,
            detail="Reflected XSS",
            evidence="<script>alert(1)</script>",
            context="zeroday",
        )
        with pytest.raises(AttributeError):
            f.title = "changed"  # type: ignore[misc]


class TestEventBus:
    @pytest.mark.asyncio
    async def test_publish_subscribe(self):
        bus = EventBus()
        received = []

        async def handler(event: DomainEvent):
            received.append(event)

        bus.subscribe(VulnDiscovered, handler)
        event = VulnDiscovered(vuln_type="SQLi", location="app.py:42")
        await bus.publish(event)

        assert len(received) == 1
        assert received[0].vuln_type == "SQLi"

    @pytest.mark.asyncio
    async def test_type_isolation(self):
        bus = EventBus()
        vuln_received = []
        ctf_received = []

        async def vuln_handler(e: DomainEvent):
            vuln_received.append(e)

        async def ctf_handler(e: DomainEvent):
            ctf_received.append(e)

        bus.subscribe(VulnDiscovered, vuln_handler)
        bus.subscribe(ChallengeSolved, ctf_handler)

        await bus.publish(VulnDiscovered(vuln_type="BOF", location="main.c:10"))
        await bus.publish(ChallengeSolved(challenge="baby_pwn", flag="flag{got_it}"))

        assert len(vuln_received) == 1
        assert len(ctf_received) == 1

    @pytest.mark.asyncio
    async def test_publish_all(self):
        bus = EventBus()
        received = []

        async def handler(e: DomainEvent):
            received.append(e)

        bus.subscribe(ExploitSucceeded, handler)
        events = [
            ExploitSucceeded(cve_id="CVE-2024-1234", target="nginx"),
            ExploitSucceeded(cve_id="CVE-2024-5678", target="apache"),
        ]
        await bus.publish_all(events)
        assert len(received) == 2
