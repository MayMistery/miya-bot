"""Tests for CTF tools — real implementations."""

from __future__ import annotations

import base64

import pytest

from miya.ctf.tools import (
    handle_decode,
    handle_xor_analyze,
    handle_hash_utils,
    handle_pack_unpack,
    handle_freq_analysis,
)
from miya.ctf.domain import Flag, Challenge, Category, WriteUp


class TestDecode:
    @pytest.mark.asyncio
    async def test_base64(self):
        encoded = base64.b64encode(b"flag{test_decode}").decode()
        result = await handle_decode({"data": encoded, "encoding": "base64"})
        text = result["content"][0]["text"]
        assert "flag{test_decode}" in text

    @pytest.mark.asyncio
    async def test_hex(self):
        data = "666c61677b686578746573747d"
        result = await handle_decode({"data": data, "encoding": "hex"})
        text = result["content"][0]["text"]
        assert "flag{hextest}" in text

    @pytest.mark.asyncio
    async def test_rot13(self):
        result = await handle_decode({"data": "synt{ebg13}", "encoding": "rot13"})
        text = result["content"][0]["text"]
        assert "flag{rot13}" in text

    @pytest.mark.asyncio
    async def test_auto_detect(self):
        encoded = base64.b64encode(b"hello world").decode()
        result = await handle_decode({"data": encoded, "encoding": "auto"})
        text = result["content"][0]["text"]
        assert "hello world" in text

    @pytest.mark.asyncio
    async def test_unknown_encoding(self):
        result = await handle_decode({"data": "test", "encoding": "nonexistent"})
        text = result["content"][0]["text"]
        assert "Unknown encoding" in text


class TestXorAnalyze:
    @pytest.mark.asyncio
    async def test_single_byte_bruteforce(self):
        # XOR "Hello" with 0x01 — limited printable results expected
        data = bytes(b ^ 0x01 for b in b"Hello").hex()
        result = await handle_xor_analyze({"data": data, "mode": "bruteforce", "key": ""})
        text = result["content"][0]["text"]
        assert "key=0x01" in text
        assert "Hello" in text

    @pytest.mark.asyncio
    async def test_decrypt_with_key(self):
        plaintext = b"secret"
        key = b"\x42"
        encrypted = bytes(b ^ key[0] for b in plaintext).hex()
        result = await handle_xor_analyze({"data": encrypted, "mode": "decrypt", "key": "42"})
        text = result["content"][0]["text"]
        assert "secret" in text


class TestHashUtils:
    @pytest.mark.asyncio
    async def test_identify_md5(self):
        result = await handle_hash_utils({
            "data": "5d41402abc4b2a76b9719d911017c592",
            "action": "identify",
        })
        text = result["content"][0]["text"]
        assert "MD5" in text

    @pytest.mark.asyncio
    async def test_identify_sha256(self):
        result = await handle_hash_utils({
            "data": "a" * 64,
            "action": "identify",
        })
        text = result["content"][0]["text"]
        assert "SHA-256" in text

    @pytest.mark.asyncio
    async def test_generate(self):
        result = await handle_hash_utils({"data": "test", "action": "generate"})
        text = result["content"][0]["text"]
        assert "MD5:" in text
        assert "SHA-256:" in text


class TestPackUnpack:
    @pytest.mark.asyncio
    async def test_unpack_little_endian(self):
        import struct
        packed = struct.pack("<I", 0xDEADBEEF).hex()
        result = await handle_pack_unpack({"data": packed, "format": "<I", "action": "unpack"})
        text = result["content"][0]["text"]
        assert "deadbeef" in text.lower()

    @pytest.mark.asyncio
    async def test_pack(self):
        result = await handle_pack_unpack({"data": "255", "format": "<B", "action": "pack"})
        text = result["content"][0]["text"]
        assert "ff" in text.lower()


class TestFreqAnalysis:
    @pytest.mark.asyncio
    async def test_english_text(self):
        text_input = "the quick brown fox jumps over the lazy dog" * 10
        result = await handle_freq_analysis({"data": text_input})
        text = result["content"][0]["text"]
        assert "Total chars:" in text


class TestDomainModel:
    def test_flag_matches(self):
        f = Flag(value="flag{test123}", format="flag{...}")
        assert f.matches()

    def test_flag_custom_format(self):
        f = Flag(value="CTF{custom}", format="CTF{...}")
        assert f.matches("CTF{...}")

    def test_flag_no_match(self):
        f = Flag(value="wrong_format", format="flag{...}")
        assert not f.matches()

    def test_challenge_solve(self):
        c = Challenge(name="baby_web", category=Category.WEB, description="Find the flag")
        assert not c.is_solved

        flag = Flag(value="flag{found_it}")
        writeup = WriteUp(
            approach="SQLi in login form",
            steps=["Found input", "Tested SQLi", "Extracted flag"],
            tools_used=["decode"],
            flag=flag,
        )
        c.solve(flag, writeup)
        assert c.is_solved
        assert c.flag.value == "flag{found_it}"
