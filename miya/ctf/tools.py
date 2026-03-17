"""CTF tools — real implementations for decode, disassembly, and crypto solving."""

from __future__ import annotations

import base64
import codecs
import hashlib
import struct
import string
from typing import Any

from claude_agent_sdk import tool, create_sdk_mcp_server


# ════════════════════════════════════════════════════════════════════
#  Core logic (testable without SDK)
# ════════════════════════════════════════════════════════════════════

DECODERS: dict[str, Any] = {
    "base64": lambda d: base64.b64decode(d).decode("utf-8", errors="replace"),
    "base32": lambda d: base64.b32decode(d).decode("utf-8", errors="replace"),
    "hex": lambda d: bytes.fromhex(d.replace(" ", "").replace("0x", "")).decode(
        "utf-8", errors="replace"
    ),
    "rot13": lambda d: codecs.decode(d, "rot_13"),
    "url": lambda d: __import__("urllib.parse", fromlist=["unquote"]).unquote(d),
    "binary": lambda d: "".join(
        chr(int(b, 2)) for b in d.split() if len(b) == 8
    ),
    "decimal": lambda d: "".join(chr(int(x)) for x in d.split()),
    "reverse": lambda d: d[::-1],
}


def _auto_decode(data: str) -> list[tuple[str, str]]:
    results = []
    for name, fn in DECODERS.items():
        try:
            decoded = fn(data)
            if decoded and decoded != data and all(
                c in string.printable for c in decoded[:50]
            ):
                results.append((name, decoded))
        except Exception:
            continue
    return results


async def handle_decode(args: dict[str, Any]) -> dict[str, Any]:
    data = args["data"]
    encoding = args.get("encoding", "auto").lower()

    if encoding == "auto":
        results = _auto_decode(data)
        if not results:
            text = "No successful decodings found. Data may be encrypted or in an unknown format."
        else:
            lines = [f"[{name}] → {decoded}" for name, decoded in results]
            text = "\n".join(lines)
    elif encoding in DECODERS:
        try:
            text = f"[{encoding}] → {DECODERS[encoding](data)}"
        except Exception as e:
            text = f"Decode error ({encoding}): {e}"
    else:
        text = f"Unknown encoding '{encoding}'. Available: {', '.join(DECODERS.keys())}, auto"

    return {"content": [{"type": "text", "text": text}]}


async def handle_xor_analyze(args: dict[str, Any]) -> dict[str, Any]:
    data_hex = args["data"].replace(" ", "")
    mode = args.get("mode", "bruteforce")
    key = args.get("key", "")

    try:
        raw = bytes.fromhex(data_hex)
    except ValueError:
        raw = args["data"].encode()

    if mode == "bruteforce":
        results = []
        for k in range(256):
            decoded = bytes(b ^ k for b in raw)
            try:
                text = decoded.decode("ascii")
                printable_ratio = sum(c in string.printable for c in text) / len(text)
                if printable_ratio > 0.85:
                    results.append(f"key=0x{k:02x}: {text[:80]}")
            except UnicodeDecodeError:
                continue
        text = "\n".join(results[:20]) if results else "No printable results found."
    elif mode == "decrypt":
        key_bytes = bytes.fromhex(key) if all(c in "0123456789abcdef" for c in key.lower()) else key.encode()
        decrypted = bytes(raw[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(raw)))
        text = f"Decrypted: {decrypted.decode('utf-8', errors='replace')}"
    else:
        text = f"Unknown mode '{mode}'. Available: bruteforce, decrypt"

    return {"content": [{"type": "text", "text": text}]}


async def handle_hash_utils(args: dict[str, Any]) -> dict[str, Any]:
    data = args["data"]
    action = args.get("action", "identify")

    if action == "identify":
        length = len(data)
        candidates = {
            32: "MD5", 40: "SHA-1", 56: "SHA-224",
            64: "SHA-256", 96: "SHA-384", 128: "SHA-512",
        }
        if all(c in "0123456789abcdef" for c in data.lower()):
            name = candidates.get(length, f"Unknown hash (length={length})")
            text = f"Likely: {name} (hex, {length} chars)"
        else:
            text = f"Not a hex hash. Length: {length}"
    elif action == "generate":
        hashes = {
            "MD5": hashlib.md5(data.encode()).hexdigest(),
            "SHA-1": hashlib.sha1(data.encode()).hexdigest(),
            "SHA-256": hashlib.sha256(data.encode()).hexdigest(),
        }
        text = "\n".join(f"{name}: {h}" for name, h in hashes.items())
    else:
        text = f"Unknown action '{action}'. Available: identify, generate"

    return {"content": [{"type": "text", "text": text}]}


async def handle_pack_unpack(args: dict[str, Any]) -> dict[str, Any]:
    fmt = args.get("format", "<Q")
    action = args.get("action", "unpack")
    data = args["data"]

    try:
        if action == "unpack":
            raw = bytes.fromhex(data.replace(" ", ""))
            values = struct.unpack(fmt, raw[:struct.calcsize(fmt)])
            text = f"Format '{fmt}' → {values}"
            if len(values) == 1:
                v = values[0]
                text += f"\n  hex: 0x{v:x}" if isinstance(v, int) else ""
        elif action == "pack":
            values = [int(x, 0) for x in data.split(",")]
            packed = struct.pack(fmt, *values)
            text = f"Packed: {packed.hex()} ({len(packed)} bytes)"
        else:
            text = "Unknown action. Available: pack, unpack"
    except Exception as e:
        text = f"Error: {e}"

    return {"content": [{"type": "text", "text": text}]}


async def handle_freq_analysis(args: dict[str, Any]) -> dict[str, Any]:
    data = args["data"]
    total = len(data)
    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1

    sorted_freq = sorted(freq.items(), key=lambda x: -x[1])
    lines = [f"Total chars: {total}", ""]
    for char, count in sorted_freq[:30]:
        pct = count / total * 100
        bar = "█" * int(pct / 2)
        display = repr(char) if not char.isprintable() else char
        lines.append(f"  {display:>5s}: {count:4d} ({pct:5.1f}%) {bar}")

    english_order = "etaoinshrdlcumwfgypbvkjxqz"
    data_order = "".join(c for c, _ in sorted_freq if c.isalpha()).lower()
    if data_order:
        lines.append(f"\nData letter order:    {data_order[:26]}")
        lines.append(f"English letter order: {english_order}")

    return {"content": [{"type": "text", "text": "\n".join(lines)}]}


# ════════════════════════════════════════════════════════════════════
#  MCP tool wrappers (thin layer over handlers)
# ════════════════════════════════════════════════════════════════════

@tool("decode", "Multi-layer decode: base64, base32, hex, rot13, URL, binary, decimal, reverse. Use encoding='auto' to try all.", {
    "data": str, "encoding": str,
})
async def decode(args: dict[str, Any]) -> dict[str, Any]:
    return await handle_decode(args)


@tool("xor_analyze", "XOR analysis: single-byte brute force, known-key decrypt, crib drag", {
    "data": str, "mode": str, "key": str,
})
async def xor_analyze(args: dict[str, Any]) -> dict[str, Any]:
    return await handle_xor_analyze(args)


@tool("hash_utils", "Hash identification, generation, and common hash lookups", {
    "data": str, "action": str,
})
async def hash_utils(args: dict[str, Any]) -> dict[str, Any]:
    return await handle_hash_utils(args)


@tool("pack_unpack", "Pack/unpack binary data using Python struct formats. Useful for pwn challenges.", {
    "data": str, "format": str, "action": str,
})
async def pack_unpack(args: dict[str, Any]) -> dict[str, Any]:
    return await handle_pack_unpack(args)


@tool("freq_analysis", "Character/byte frequency analysis for classical cipher identification", {
    "data": str,
})
async def freq_analysis(args: dict[str, Any]) -> dict[str, Any]:
    return await handle_freq_analysis(args)


# ── MCP Server ─────────────────────────────────────────────────────

def ctf_mcp_server():
    """Create the CTF tools MCP server."""
    return create_sdk_mcp_server(
        name="ctf_tools",
        tools=[decode, xor_analyze, hash_utils, pack_unpack, freq_analysis],
    )
