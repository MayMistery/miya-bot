"""Tests for CTF writeup auto-generation."""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

import pytest

from miya.mission.service import _write_challenge_writeup


class TestWriteUpGeneration:
    """Test writeup markdown file generation."""

    def test_basic_writeup(self, tmp_path: Path):
        result = _write_challenge_writeup(
            "Easy-Gin", "flag{g1n_r0ut3r}", "SQL injection",
            "http://10.0.0.1:8080", output_dir=tmp_path,
        )
        assert result is not None
        assert result.exists()
        assert result.name == "Easy-Gin_g1n_r0ut3r.md"
        content = result.read_text()
        assert "# Easy-Gin" in content
        assert "flag{g1n_r0ut3r}" in content
        assert "SQL injection" in content
        assert "http://10.0.0.1:8080" in content

    def test_chinese_challenge_name(self, tmp_path: Path):
        result = _write_challenge_writeup(
            "魔术链接挑战", "flag{m4g1c}", "SSRF",
            "http://10.0.0.1:9090", output_dir=tmp_path,
        )
        assert result is not None
        assert "m4g1c" in result.name
        content = result.read_text()
        assert "魔术链接挑战" in content

    def test_empty_approach_uses_default(self, tmp_path: Path):
        result = _write_challenge_writeup(
            "Test", "flag{x}", "", "http://1.2.3.4:80", output_dir=tmp_path,
        )
        assert result is not None
        content = result.read_text()
        assert "Miya" in content

    def test_flag_without_braces(self, tmp_path: Path):
        result = _write_challenge_writeup(
            "Test", "raw_flag_value", "approach",
            "http://1.2.3.4:80", output_dir=tmp_path,
        )
        assert result is not None
        assert "raw_flag_value" in result.name

    def test_none_output_dir_skips(self):
        result = _write_challenge_writeup(
            "Test", "flag{x}", "approach", "http://1.2.3.4:80",
            output_dir=None,
        )
        assert result is None
