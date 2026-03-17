"""Miya — DDD Pentest Agent.

Usage:
    miya "Audit this Go project for vulnerabilities"
    miya "Find and exploit CVEs in nginx 1.18.0"
    miya "Solve this crypto CTF challenge"
    miya --interactive
"""

from __future__ import annotations

import asyncio
import sys

from claude_agent_sdk import query, AssistantMessage, ResultMessage, TextBlock, ToolUseBlock

from miya.coordinator.agent import build_coordinator


BANNER = r"""
    ╔══════════════════════════════════════╗
    ║  ███╗   ███╗██╗██╗   ██╗ █████╗     ║
    ║  ████╗ ████║██║╚██╗ ██╔╝██╔══██╗    ║
    ║  ██╔████╔██║██║ ╚████╔╝ ███████║    ║
    ║  ██║╚██╔╝██║██║  ╚██╔╝  ██╔══██║    ║
    ║  ██║ ╚═╝ ██║██║   ██║   ██║  ██║    ║
    ║  ╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝    ║
    ║                                      ║
    ║   DDD Pentest Agent                  ║
    ║   0day · 1day · CTF                  ║
    ╚══════════════════════════════════════╝
"""


def print_message(message) -> None:
    """Format and print agent messages."""
    if isinstance(message, AssistantMessage):
        for block in message.content:
            if isinstance(block, TextBlock):
                print(block.text, end="", flush=True)
            elif isinstance(block, ToolUseBlock):
                print(f"\n  ⚡ {block.name}", end="", flush=True)
    elif isinstance(message, ResultMessage):
        print()  # newline after assistant stream


async def run(prompt: str, cwd: str | None = None) -> None:
    """Run Miya with a single prompt."""
    options = build_coordinator(cwd=cwd)
    async for message in query(prompt=prompt, options=options):
        print_message(message)
    print()


async def interactive() -> None:
    """Interactive REPL mode."""
    print(BANNER)
    print("  Type your task. Ctrl+C to exit.\n")

    while True:
        try:
            prompt = input("miya> ").strip()
            if not prompt:
                continue
            if prompt.lower() in ("exit", "quit", "q"):
                break
            await run(prompt)
            print()
        except (KeyboardInterrupt, EOFError):
            print("\n  Bye.")
            break


def cli() -> None:
    """CLI entry point (registered in pyproject.toml)."""
    args = sys.argv[1:]

    if not args or args[0] == "--interactive":
        asyncio.run(interactive())
    else:
        prompt = " ".join(args)
        asyncio.run(run(prompt))


if __name__ == "__main__":
    cli()
