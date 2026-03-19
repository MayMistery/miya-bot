"""Tests for CTF batch challenge registry, health probing, and writeup generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from miya.ctf.batch import (
    BatchRegistry,
    ChallengeEntry,
    TaskStatus,
    render_probe_report,
    render_task_board,
    generate_writeup,
    write_all_writeups,
    render_writeup_summary,
)


# ═══════════════════════════════════════════════════════════════════
#  BatchRegistry Parsing
# ═══════════════════════════════════════════════════════════════════


class TestBatchRegistryParsing:
    """Test parsing challenge definitions from user input."""

    def test_parse_basic_input(self):
        raw = '''solve these challenges [{"name": "Easy-Gin", "port": 16235}, {"name": "Easy-JWT", "port": 17855}] ip是10.37.225.178'''
        registry = BatchRegistry.from_user_input(raw)
        assert registry.ip == "10.37.225.178"
        assert registry.total == 2
        assert registry.challenges[0].name == "Easy-Gin"
        assert registry.challenges[0].port == 16235
        assert registry.challenges[1].name == "Easy-JWT"
        assert registry.challenges[1].port == 17855

    def test_parse_full_user_input(self):
        """Parse the exact user input from the requirement."""
        raw = '''切换到bench分支，删除所有更改。然后生成一个todolist，先确保5个环境可达，等待我确认后。是挖掘client和web这5道ctf题目的flag。生成5个writeup.md，文件名是题目名+flag名字。 [  { "status": "ok", "name": "Easy-Gin", "port": 16235, "flag": "" }, { "status": "ok", "name": "Easy-JWT", "port": 17855, "flag": "" }, { "status": "ok", "name": "Old-Gorm", "port": 49813, "flag": "" }, { "status": "ok", "name": "easy-nginx", "port": 20247, "flag": "" }, { "status": "ok", "name": "魔术链接挑战", "port": 26055, "flag": "" } ] ip是10.37.225.178'''

        registry = BatchRegistry.from_user_input(raw)
        assert registry.ip == "10.37.225.178"
        assert registry.total == 5

        names = [c.name for c in registry.challenges]
        assert names == ["Easy-Gin", "Easy-JWT", "Old-Gorm", "easy-nginx", "魔术链接挑战"]

        ports = [c.port for c in registry.challenges]
        assert ports == [16235, 17855, 49813, 20247, 26055]

    def test_parse_ip_variants(self):
        """IP can be specified in various formats."""
        for pattern in [
            "ip是192.168.1.1",
            "ip:192.168.1.1",
            "ip=192.168.1.1",
            "ip 192.168.1.1",
            "IP是192.168.1.1",
        ]:
            raw = f'[{{"name":"a","port":80}}] {pattern}'
            reg = BatchRegistry.from_user_input(raw)
            assert reg.ip == "192.168.1.1", f"Failed for pattern: {pattern}"

    def test_parse_no_json_raises(self):
        with pytest.raises(ValueError, match="No JSON"):
            BatchRegistry.from_user_input("solve the challenge at 10.0.0.1")

    def test_parse_invalid_json_raises(self):
        with pytest.raises(ValueError, match="No JSON|Invalid JSON"):
            BatchRegistry.from_user_input('[{"name": "broken ip是1.2.3.4')

    def test_challenge_url(self):
        entry = ChallengeEntry(name="test", port=8080, ip="10.0.0.1")
        assert entry.url == "http://10.0.0.1:8080"

    def test_challenge_writeup_filename(self):
        entry = ChallengeEntry(name="Easy-Gin", port=80, flag="flag{g1n_r0ut3r}")
        assert entry.writeup_filename == "Easy-Gin_g1n_r0ut3r.md"

    def test_challenge_writeup_filename_no_flag(self):
        entry = ChallengeEntry(name="Easy-Gin", port=80)
        assert entry.writeup_filename == "Easy-Gin_unsolved.md"

    def test_challenge_writeup_filename_chinese(self):
        entry = ChallengeEntry(name="魔术链接挑战", port=80, flag="flag{m4g1c_l1nk}")
        filename = entry.writeup_filename
        assert filename.endswith("m4g1c_l1nk.md")

    def test_registry_counts(self):
        reg = BatchRegistry(
            challenges=[
                ChallengeEntry(name="a", port=1, status=TaskStatus.SOLVED),
                ChallengeEntry(name="b", port=2, status=TaskStatus.FAILED),
                ChallengeEntry(name="c", port=3, status=TaskStatus.REACHABLE),
            ]
        )
        assert reg.total == 3
        assert reg.solved_count == 1


# ═══════════════════════════════════════════════════════════════════
#  Rendering
# ═══════════════════════════════════════════════════════════════════


class TestRendering:
    """Test probe report and task board rendering."""

    def _sample_registry(self) -> BatchRegistry:
        return BatchRegistry(
            ip="10.0.0.1",
            challenges=[
                ChallengeEntry(name="Web1", port=8080, ip="10.0.0.1",
                               status=TaskStatus.REACHABLE, http_code=200, probe_ms=1.5),
                ChallengeEntry(name="Pwn1", port=9090, ip="10.0.0.1",
                               status=TaskStatus.UNREACHABLE, error="timeout"),
                ChallengeEntry(name="Crypto1", port=7070, ip="10.0.0.1",
                               status=TaskStatus.SOLVED, flag="flag{test}"),
            ],
        )

    def test_probe_report_contains_all_challenges(self):
        reg = self._sample_registry()
        report = render_probe_report(reg)
        assert "Web1" in report
        assert "Pwn1" in report
        assert "Crypto1" in report
        assert "8080" in report
        assert "1/3" in report  # only REACHABLE status counts

    def test_task_board_shows_progress(self):
        reg = self._sample_registry()
        board = render_task_board(reg)
        assert "CTF Task Board" in board
        assert "Web1" in board
        assert "1/3" in board  # 1 solved out of 3

    def test_task_board_solved_shows_flag(self):
        reg = self._sample_registry()
        board = render_task_board(reg)
        assert "flag{test}" in board


# ═══════════════════════════════════════════════════════════════════
#  WriteUp Generation
# ═══════════════════════════════════════════════════════════════════


class TestWriteUpGeneration:
    """Test writeup markdown generation."""

    def test_generate_writeup_basic(self):
        entry = ChallengeEntry(
            name="Easy-Gin", port=8080, ip="10.0.0.1",
            flag="flag{g1n_r0ut3r}", category="web",
            approach="SQL injection via login form",
        )
        md = generate_writeup(entry)
        assert "# Easy-Gin" in md
        assert "flag{g1n_r0ut3r}" in md
        assert "SQL injection via login form" in md
        assert "web" in md

    def test_generate_writeup_custom_approach(self):
        entry = ChallengeEntry(
            name="Test", port=80, ip="1.2.3.4",
            flag="flag{x}", category="pwn",
        )
        md = generate_writeup(entry, approach_detail="Buffer overflow on stack")
        assert "Buffer overflow on stack" in md

    def test_write_all_writeups_creates_files(self, tmp_path: Path):
        reg = BatchRegistry(
            challenges=[
                ChallengeEntry(name="Web1", port=80, ip="1.2.3.4",
                               flag="flag{web1}", status=TaskStatus.SOLVED, category="web"),
                ChallengeEntry(name="Pwn1", port=81, ip="1.2.3.4",
                               status=TaskStatus.FAILED),  # no flag, should skip
                ChallengeEntry(name="Crypto1", port=82, ip="1.2.3.4",
                               flag="flag{c1}", status=TaskStatus.SOLVED, category="crypto"),
            ]
        )
        created = write_all_writeups(reg, output_dir=tmp_path)
        assert len(created) == 2

        # Check files exist and contain flags
        for f in created:
            assert f.exists()
            content = f.read_text()
            assert "flag{" in content

    def test_render_writeup_summary(self, tmp_path: Path):
        files = [tmp_path / "Web1_web1.md", tmp_path / "Crypto1_c1.md"]
        summary = render_writeup_summary(files)
        assert "Web1_web1.md" in summary
        assert "Crypto1_c1.md" in summary

    def test_render_writeup_summary_empty(self):
        summary = render_writeup_summary([])
        assert "No writeups" in summary
