"""Tests for v3 cleanup: submit_challenge_flag, CWE consolidation, dead code removal."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from miya.ctf.shared.domain import Flag, WriteUp
from miya.ctf.shared.service import submit_challenge_flag
from miya.infra.repositories import InMemoryRepository


# ═══════════════════════════════════════════════════════════════════
#  submit_challenge_flag shared helper
# ═══════════════════════════════════════════════════════════════════


@dataclass
class _FakeChallenge:
    """Minimal challenge stub for testing submit_challenge_flag."""

    id: str = "ch-1"
    name: str = "test_challenge"
    flag: Flag | None = None
    writeup: WriteUp | None = None
    status: str = "identified"

    def solve(self, flag: Flag, writeup: WriteUp | None = None) -> None:
        self.flag = flag
        self.status = "solved"
        if writeup:
            self.writeup = writeup


class TestSubmitChallengeFlag:
    @pytest.mark.asyncio
    async def test_submit_flag_success(self):
        repo: InMemoryRepository[_FakeChallenge] = InMemoryRepository()
        challenge = _FakeChallenge()
        await repo.save(challenge)

        ok, events = await submit_challenge_flag(repo, "ch-1", "flag{test_123}")

        assert ok is True
        assert len(events) == 1
        assert events[0].__class__.__name__ == "ChallengeSolved"
        assert events[0].flag == "flag{test_123}"
        assert events[0].challenge_name == "test_challenge"

        updated = await repo.get("ch-1")
        assert updated is not None
        assert updated.status == "solved"
        assert updated.flag is not None
        assert updated.flag.value == "flag{test_123}"

    @pytest.mark.asyncio
    async def test_submit_flag_with_writeup(self):
        repo: InMemoryRepository[_FakeChallenge] = InMemoryRepository()
        await repo.save(_FakeChallenge())

        writeup = WriteUp(summary="Used buffer overflow", steps=("leak libc", "ret2system"))
        ok, events = await submit_challenge_flag(
            repo, "ch-1", "flag{pwned}", approach="bof", writeup=writeup,
        )

        assert ok is True
        assert events[0].approach == "bof"

        updated = await repo.get("ch-1")
        assert updated is not None
        assert updated.writeup is not None
        assert updated.writeup.summary == "Used buffer overflow"

    @pytest.mark.asyncio
    async def test_submit_flag_challenge_not_found(self):
        repo: InMemoryRepository[_FakeChallenge] = InMemoryRepository()

        with pytest.raises(ValueError, match="not found"):
            await submit_challenge_flag(repo, "nonexistent", "flag{x}")

    @pytest.mark.asyncio
    async def test_submit_flag_empty_flag_rejected(self):
        repo: InMemoryRepository[_FakeChallenge] = InMemoryRepository()
        await repo.save(_FakeChallenge())

        with pytest.raises(ValueError, match="empty"):
            await submit_challenge_flag(repo, "ch-1", "")

    @pytest.mark.asyncio
    async def test_submit_flag_aggregate_type(self):
        """Event aggregate_type should be the challenge class name."""
        repo: InMemoryRepository[_FakeChallenge] = InMemoryRepository()
        await repo.save(_FakeChallenge())

        _, events = await submit_challenge_flag(repo, "ch-1", "flag{x}")
        assert events[0].aggregate_type == "_FakeChallenge"


# ═══════════════════════════════════════════════════════════════════
#  CWE mapping consolidation
# ═══════════════════════════════════════════════════════════════════


class TestCWEConsolidation:
    def test_acl_derives_from_dataflow_map(self):
        """ACL's _SINK_TYPE_TO_CWE should contain all entries from dataflow's _SINK_CWE_MAP."""
        from miya.zeroday.dataflow.service import _SINK_CWE_MAP
        from miya.zeroday.acl import _SINK_TYPE_TO_CWE

        for sink_type, cwe_id in _SINK_CWE_MAP.items():
            assert sink_type in _SINK_TYPE_TO_CWE, f"Missing {sink_type} in ACL map"
            acl_cwe_id, acl_cwe_name = _SINK_TYPE_TO_CWE[sink_type]
            assert acl_cwe_id == cwe_id, f"CWE mismatch for {sink_type}"
            assert acl_cwe_name, f"Empty CWE name for {sink_type}"

    def test_acl_has_crypto_key_extra(self):
        """ACL should have crypto_key entry not in the dataflow map."""
        from miya.zeroday.acl import _SINK_TYPE_TO_CWE

        assert "crypto_key" in _SINK_TYPE_TO_CWE
        assert _SINK_TYPE_TO_CWE["crypto_key"][0] == "CWE-321"


# ═══════════════════════════════════════════════════════════════════
#  Dead code removal verification
# ═══════════════════════════════════════════════════════════════════


class TestDeadCodeRemoval:
    def test_crypto_attack_no_rsa_attacks_classmethod(self):
        """CryptoAttack.rsa_attacks() was removed (superseded by service)."""
        from miya.ctf.crypto.domain import CryptoAttack

        assert not hasattr(CryptoAttack, "rsa_attacks")

    def test_plaintext_no_contains_flag(self):
        """PlainText.contains_flag was removed (unused)."""
        from miya.ctf.crypto.domain import PlainText

        pt = PlainText(value="flag{test}")
        assert not hasattr(pt, "contains_flag")

    def test_hidden_data_no_contains_flag(self):
        """HiddenData.contains_flag was removed (unused)."""
        from miya.ctf.misc.domain import HiddenData

        hd = HiddenData(data="flag{test}", extraction_method="strings")
        assert not hasattr(hd, "contains_flag")


# ═══════════════════════════════════════════════════════════════════
#  Import cleanup verification
# ═══════════════════════════════════════════════════════════════════


class TestImportCleanup:
    def test_oneday_services_importable(self):
        """All oneday services should still import cleanly after cleanup."""
        from miya.oneday.recon.service import ReconService
        from miya.oneday.scan.service import ScanService
        from miya.oneday.vuln.service import VulnService
        from miya.oneday.exploit.service import ExploitService

        assert ReconService is not None
        assert ScanService is not None
        assert VulnService is not None
        assert ExploitService is not None

    def test_ctf_services_importable(self):
        """All CTF services should still import cleanly after cleanup."""
        from miya.ctf.web.service import WebCTFService
        from miya.ctf.crypto.service import CryptoCTFService
        from miya.ctf.pwn.service import PwnCTFService
        from miya.ctf.reverse.service import ReverseCTFService
        from miya.ctf.misc.service import MiscCTFService

        assert WebCTFService is not None
        assert CryptoCTFService is not None
        assert PwnCTFService is not None
        assert ReverseCTFService is not None
        assert MiscCTFService is not None

    def test_attack_graph_topo_importable(self):
        """AttackGraphTopology should import cleanly with re at module level."""
        from miya.topology.attack_graph_topo import AttackGraphTopology

        assert AttackGraphTopology is not None
