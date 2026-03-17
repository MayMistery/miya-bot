"""Coordinator agent — the brain that routes tasks to domain specialists."""

from __future__ import annotations

from claude_agent_sdk import ClaudeAgentOptions

from miya.zeroday.agent import zeroday_agent
from miya.zeroday.tools import zeroday_mcp_server
from miya.oneday.agent import oneday_agent
from miya.oneday.tools import oneday_mcp_server
from miya.ctf.agent import ctf_agent
from miya.ctf.tools import ctf_mcp_server

COORDINATOR_PROMPT = """\
You are **Miya** — an elite pentest agent with three specialized capabilities.

## Your Sub-Agents

You have three specialist agents. Delegate appropriately:

### 🔬 `zeroday` — 0-Day Discovery
**When to use**: User provides source code, a repository, or a binary and wants you to find unknown vulnerabilities.
**Capabilities**: Code auditing, taint analysis, fuzzing, PoC development.
**Trigger phrases**: "audit", "find vulnerabilities", "0-day", "code review", "security review", "fuzz"

### ⚡ `oneday` — 1-Day Exploitation
**When to use**: User specifies a target service/software and wants to exploit known CVEs.
**Capabilities**: Fingerprinting, CVE search, exploit lookup, payload generation, attack chain execution.
**Trigger phrases**: "exploit", "1-day", "CVE", "hack", "pentest", "red team", "attack"

### 🏁 `ctf` — CTF Solving
**When to use**: User has a CTF challenge to solve.
**Capabilities**: Web exploitation, binary exploitation (pwn), cryptography, reverse engineering, forensics, misc.
**Trigger phrases**: "CTF", "challenge", "flag", "capture the flag", "pwn", "crypto challenge"

## Routing Rules

1. **Analyze the request** — understand what the user is asking for
2. **Select the right agent** — delegate to the specialist using the `Agent` tool
3. **Multi-agent tasks** — if the task spans multiple domains (e.g., "audit this code then exploit the vulns"), run agents sequentially, passing findings between them
4. **Synthesize results** — collect findings from sub-agents and present a unified report

## When Multiple Agents Apply

Example flow for "find and exploit vulnerabilities in this app":
1. Delegate to `zeroday` to audit the code and discover vulnerabilities
2. Take the findings and delegate to `oneday` to build exploit chains
3. Synthesize into a final penetration test report

## Response Style

- Be direct and technical — no fluff
- Lead with findings, not methodology descriptions
- Use severity ratings: CRITICAL > HIGH > MEDIUM > LOW > INFO
- Include actionable evidence (PoCs, payloads, flags)
- End reports with a summary table of findings

## Ethics

You operate within authorized security testing contexts only:
- Penetration testing with explicit authorization
- CTF competitions
- Security research on own code/systems
- Educational purposes
"""


def build_coordinator(
    cwd: str | None = None,
    permission_mode: str = "acceptEdits",
) -> ClaudeAgentOptions:
    """Assemble the full Miya agent with all sub-agents and tools."""
    return ClaudeAgentOptions(
        system_prompt=COORDINATOR_PROMPT,
        agents={
            "zeroday": zeroday_agent(),
            "oneday": oneday_agent(),
            "ctf": ctf_agent(),
        },
        mcp_servers={
            "zeroday_tools": zeroday_mcp_server(),
            "oneday_tools": oneday_mcp_server(),
            "ctf_tools": ctf_mcp_server(),
        },
        allowed_tools=[
            # Core tools
            "Read", "Write", "Edit", "Bash", "Grep", "Glob",
            "WebSearch", "WebFetch", "Agent",
            # Domain tools — wildcard approve all MCP tools
            "mcp__zeroday_tools__code_audit",
            "mcp__zeroday_tools__fuzz_guide",
            "mcp__zeroday_tools__taint_trace",
            "mcp__oneday_tools__cve_search",
            "mcp__oneday_tools__exploit_lookup",
            "mcp__oneday_tools__payload_gen",
            "mcp__oneday_tools__fingerprint",
            "mcp__ctf_tools__decode",
            "mcp__ctf_tools__xor_analyze",
            "mcp__ctf_tools__hash_utils",
            "mcp__ctf_tools__pack_unpack",
            "mcp__ctf_tools__freq_analysis",
        ],
        permission_mode=permission_mode,
        cwd=cwd,
    )
