"""Integration tests for domain models — aggregate behavior and event emission."""

from __future__ import annotations

import pytest
from miya.oneday.exploit.domain import ExploitCampaign, Payload, ExploitResult
from miya.oneday.post.domain import PostSession, AccessLevel, LootItem, PivotTarget
from miya.shared.events import ExploitAttempted, ExploitSucceeded, ExploitFailed


class TestExploitCampaign:
    def test_attempt_exploit_emits_event(self):
        campaign = ExploitCampaign(target_host="10.0.0.5")
        attempt = campaign.attempt_exploit(
            cve_id="CVE-2021-44228",
            target_host="10.0.0.5",
            target_port=8080,
            module="exploit/multi/http/log4shell_header_injection",
            payload=Payload(payload_type="reverse_shell", platform="linux"),
        )

        events = campaign.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], ExploitAttempted)
        assert events[0].cve_id == "CVE-2021-44228"

    def test_success_records_session(self):
        campaign = ExploitCampaign(target_host="10.0.0.5")
        attempt = campaign.attempt_exploit(
            cve_id="CVE-2021-44228",
            target_host="10.0.0.5",
            target_port=8080,
            module="log4shell",
        )
        campaign.record_success(
            attempt.id,
            access_gained="user",
            session_id="1",
            evidence="uid=1000(tomcat)",
        )

        assert campaign.has_session()
        assert len(campaign.successful_attempts()) == 1

        events = campaign.collect_events()
        assert len(events) == 2  # attempted + succeeded
        assert isinstance(events[1], ExploitSucceeded)

    def test_failure_records_reason(self):
        campaign = ExploitCampaign(target_host="10.0.0.5")
        attempt = campaign.attempt_exploit(
            cve_id="CVE-2021-44228",
            target_host="10.0.0.5",
            target_port=8080,
            module="log4shell",
        )
        campaign.record_failure(attempt.id, reason="Target is patched")

        assert len(campaign.failed_attempts()) == 1
        events = campaign.collect_events()
        assert isinstance(events[1], ExploitFailed)
        assert events[1].reason == "Target is patched"

    def test_version_increments(self):
        campaign = ExploitCampaign()
        assert campaign.version == 0
        campaign.attempt_exploit(
            cve_id="CVE-1", target_host="h", target_port=80, module="m",
        )
        assert campaign.version == 1

    def test_event_sourcing_reconstitution(self):
        # Create and operate
        campaign = ExploitCampaign()
        campaign.attempt_exploit(
            cve_id="CVE-1", target_host="h", target_port=80, module="m",
        )
        events = campaign.collect_events()

        # Reconstitute from events
        restored = ExploitCampaign()
        for event in events:
            restored.apply(event)

        assert len(restored.attempts) == 1
        assert restored.attempts[0].cve_id == "CVE-1"


class TestPostSession:
    def test_escalate_privileges(self):
        session = PostSession(target_host="10.0.0.5")
        session.escalate_privileges(
            to_level="root",
            username="root",
            technique="SUID binary /usr/bin/find",
        )

        assert session.access_level.level == "root"
        assert session.access_level.is_privileged

        events = session.collect_events()
        assert len(events) == 1
        assert events[0].from_level == "none"
        assert events[0].to_level == "root"

    def test_collect_loot(self):
        session = PostSession(target_host="10.0.0.5")
        item = session.collect_loot(
            loot_type="credential",
            description="MySQL root password",
            content="root:SuperSecret123!",
            source="/var/www/.env",
        )

        assert len(session.loot) == 1
        assert item.loot_type == "credential"
        assert session.credentials() == [item]

    def test_pivot_targets(self):
        session = PostSession(target_host="10.0.0.5")
        session.add_pivot_target(PivotTarget(
            host="db-server",
            ip="10.0.0.10",
            port=3306,
            service="mysql",
            confidence="high",
        ))

        assert len(session.pivot_targets) == 1
        assert len(session.high_confidence_pivots()) == 1

    def test_access_level_value_object(self):
        al = AccessLevel(level="root", username="root", groups=("root", "docker"))
        assert al.is_privileged
        assert not AccessLevel(level="user").is_privileged
