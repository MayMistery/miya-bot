"""Integration tests for SQLiteEventStore — persistence and retrieval."""

from __future__ import annotations

import pytest
import pytest_asyncio
from miya.infra.event_store import SQLiteEventStore, ConcurrencyError
from miya.shared.events import (
    MissionStarted,
    AssetDiscovered,
    VulnerabilityFound,
    ExploitSucceeded,
    ChallengeIdentified,
    ChallengeSolved,
)


@pytest_asyncio.fixture
async def store():
    """In-memory SQLite event store for testing."""
    s = SQLiteEventStore(":memory:")
    await s.initialize()
    yield s
    await s.close()


class TestSQLiteEventStore:
    @pytest.mark.asyncio
    async def test_append_and_count(self, store):
        event = MissionStarted(
            aggregate_id="mission-1",
            mission_type="oneday",
            target_uri="10.0.0.1",
            topology="ooda",
        )
        await store.append([event])
        count = await store.count()
        assert count == 1

    @pytest.mark.asyncio
    async def test_append_multiple(self, store):
        events = [
            AssetDiscovered(aggregate_id="asset-1", host="h1", ip="1.1.1.1", ports=(80,)),
            AssetDiscovered(aggregate_id="asset-2", host="h2", ip="2.2.2.2", ports=(443,)),
        ]
        await store.append(events)
        assert await store.count() == 2

    @pytest.mark.asyncio
    async def test_load_by_aggregate(self, store):
        events = [
            MissionStarted(aggregate_id="m-1", mission_type="oneday"),
            AssetDiscovered(aggregate_id="m-1", host="test"),
            VulnerabilityFound(aggregate_id="m-2", vuln_type="XSS"),
        ]
        await store.append(events)

        loaded = await store.load("m-1")
        assert len(loaded) == 2

    @pytest.mark.asyncio
    async def test_load_by_context(self, store):
        events = [
            AssetDiscovered(context="recon", mission="oneday", host="h1"),
            VulnerabilityFound(context="vuln", mission="oneday", vuln_type="SQLi"),
            AssetDiscovered(context="recon", mission="oneday", host="h2"),
        ]
        await store.append(events)

        recon_events = await store.load_by_context("recon")
        assert len(recon_events) == 2

        recon_oneday = await store.load_by_context("recon", mission="oneday")
        assert len(recon_oneday) == 2

    @pytest.mark.asyncio
    async def test_load_all(self, store):
        await store.append([MissionStarted(), AssetDiscovered(host="test")])
        all_events = await store.load_all()
        assert len(all_events) == 2

    @pytest.mark.asyncio
    async def test_load_by_type(self, store):
        await store.append([
            MissionStarted(aggregate_id="m-1"),
            AssetDiscovered(host="test"),
            MissionStarted(aggregate_id="m-2"),
        ])
        started = await store.load_by_type("mission.started")
        assert len(started) == 2

    @pytest.mark.asyncio
    async def test_roundtrip_preserves_data(self, store):
        original = AssetDiscovered(
            aggregate_id="a-1",
            host="example.com",
            ip="10.0.0.1",
            ports=(22, 80, 443, 8080),
            services=("ssh", "http", "https", "http-alt"),
            os="Ubuntu 22.04",
            context="recon",
            mission="oneday",
        )
        await store.append([original])

        loaded = await store.load("a-1")
        assert len(loaded) == 1
        restored = loaded[0]
        assert isinstance(restored, AssetDiscovered)
        assert restored.host == "example.com"
        assert restored.ports == (22, 80, 443, 8080)
        assert restored.services == ("ssh", "http", "https", "http-alt")
        assert restored.os == "Ubuntu 22.04"

    @pytest.mark.asyncio
    async def test_optimistic_concurrency(self, store):
        event1 = MissionStarted(aggregate_id="m-1", version=1)
        await store.append([event1])

        # This should fail: expected version 0 but current is 1
        event2 = AssetDiscovered(aggregate_id="m-1", host="test", version=2)
        with pytest.raises(ConcurrencyError):
            await store.append([event2], expected_version=0)

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        async with SQLiteEventStore(":memory:") as store:
            await store.append([MissionStarted()])
            assert await store.count() == 1


class TestEventStoreWithDomainScenario:
    """Test event store with realistic domain event sequences."""

    @pytest.mark.asyncio
    async def test_oneday_kill_chain_events(self, store):
        """Simulate a complete 1-day exploitation flow."""
        events = [
            MissionStarted(
                aggregate_id="mission-1",
                mission_type="oneday",
                target_uri="10.0.0.5",
                topology="ooda",
                mission="oneday",
            ),
            AssetDiscovered(
                aggregate_id="asset-1",
                host="10.0.0.5",
                ip="10.0.0.5",
                ports=(22, 80, 8080),
                services=("ssh", "http", "http-alt"),
                os="Ubuntu 20.04",
                context="recon",
                mission="oneday",
            ),
            VulnerabilityFound(
                aggregate_id="vuln-1",
                vuln_id="vuln-1",
                vuln_type="Remote Code Execution",
                cwe_id="CWE-94",
                severity="critical",
                location="10.0.0.5:8080/api",
                description="Log4Shell in Spring Boot app",
                context="vuln",
                mission="oneday",
            ),
            ExploitSucceeded(
                aggregate_id="exploit-1",
                cve_id="CVE-2021-44228",
                access_gained="user",
                evidence="uid=1000(tomcat) gid=1000(tomcat)",
                context="exploit",
                mission="oneday",
            ),
        ]
        await store.append(events)

        # Verify we can reconstruct the full mission
        all_events = await store.load_all()
        assert len(all_events) == 4

        recon = await store.load_by_context("recon")
        assert len(recon) == 1

        vuln = await store.load_by_context("vuln")
        assert len(vuln) == 1

    @pytest.mark.asyncio
    async def test_ctf_challenge_events(self, store):
        """Simulate a CTF challenge solve flow."""
        events = [
            ChallengeIdentified(
                aggregate_id="chall-1",
                challenge_name="Baby SQLi",
                category="web",
                points=100,
                context="ctf",
                mission="ctf",
            ),
            ChallengeSolved(
                aggregate_id="chall-1",
                challenge_name="Baby SQLi",
                flag="flag{un10n_1nj3ct10n_ftw}",
                approach="Union-based SQLi with information_schema enumeration",
                context="ctf",
                mission="ctf",
            ),
        ]
        await store.append(events)

        ctf_events = await store.load_by_context("ctf")
        assert len(ctf_events) == 2

        solved = await store.load_by_type("ctf.challenge_solved")
        assert len(solved) == 1
        assert isinstance(solved[0], ChallengeSolved)
        assert solved[0].flag == "flag{un10n_1nj3ct10n_ftw}"
