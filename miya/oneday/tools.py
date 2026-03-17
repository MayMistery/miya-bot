"""1-day exploitation tools — CVE search, exploit lookup, payload generation.

These are smart orchestrators that leverage Bash/WebFetch for heavy lifting.
The tools provide structure, caching, and domain-aware processing.
"""

from __future__ import annotations

import json
from typing import Any

from claude_agent_sdk import tool, create_sdk_mcp_server


@tool("cve_search", "Search for known CVEs affecting a specific software/version. Queries NVD and returns structured results.", {
    "software": str,
    "version": str,
    "severity_filter": str,
})
async def cve_search(args: dict[str, Any]) -> dict[str, Any]:
    software = args["software"]
    version = args.get("version", "")
    severity = args.get("severity_filter", "all").upper()

    query = f"{software} {version}".strip()

    # Build NVD API query guidance
    instructions = f"""Search for CVEs affecting: {query}

## Recommended approach:
1. Use WebSearch to find: "{software} {version} CVE vulnerability"
2. Use WebFetch on NVD: https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={software.replace(' ', '+')}
3. Parse results and filter by:
   - Affected version: {version or 'any'}
   - Severity: {severity if severity != 'ALL' else 'any'}

## Output format for each CVE:
- CVE ID
- CVSS score and severity
- Description
- Affected versions
- Known exploits (if any)
- References

Sort by CVSS score descending. Focus on CVEs with known public exploits."""

    return {"content": [{"type": "text", "text": instructions}]}


@tool("exploit_lookup", "Find public exploits for a given CVE ID. Searches ExploitDB, GitHub, PacketStorm, and Metasploit.", {
    "cve_id": str,
})
async def exploit_lookup(args: dict[str, Any]) -> dict[str, Any]:
    cve_id = args["cve_id"]

    instructions = f"""Find public exploits for: {cve_id}

## Search strategy (execute in order):
1. **ExploitDB**: WebSearch "{cve_id} site:exploit-db.com"
2. **GitHub PoCs**: WebSearch "{cve_id} PoC exploit github"
3. **Metasploit**: WebSearch "{cve_id} metasploit module"
4. **PacketStorm**: WebSearch "{cve_id} site:packetstormsecurity.com"
5. **Nuclei templates**: WebSearch "{cve_id} nuclei template"

## For each exploit found, report:
- Source (ExploitDB / GitHub / Metasploit / etc.)
- URL
- Language/platform
- Requirements (auth needed? network access? specific config?)
- Reliability assessment (PoC vs weaponized vs unreliable)
- Relevant code snippet or module path

## Priority:
1. Weaponized, reliable exploits with RCE
2. Authenticated RCE
3. Pre-auth info leaks that enable further exploitation
4. DoS (lowest priority)"""

    return {"content": [{"type": "text", "text": instructions}]}


@tool("payload_gen", "Generate or adapt an exploit payload for a specific target environment.", {
    "exploit_type": str,
    "target_os": str,
    "target_arch": str,
    "callback_host": str,
    "callback_port": str,
    "options": str,
})
async def payload_gen(args: dict[str, Any]) -> dict[str, Any]:
    exploit_type = args["exploit_type"]
    target_os = args.get("target_os", "linux")
    target_arch = args.get("target_arch", "x86_64")
    callback_host = args.get("callback_host", "ATTACKER_IP")
    callback_port = args.get("callback_port", "4444")
    options = args.get("options", "")

    instructions = f"""Generate a payload for:
- Type: {exploit_type}
- Target: {target_os}/{target_arch}
- Callback: {callback_host}:{callback_port}
- Options: {options or 'none'}

## Guidelines:
1. **Reverse shell payloads** — generate for the target's available interpreters:
   - Python, Bash, PHP, PowerShell, Perl, Ruby, Netcat
   - Prefer encrypted/obfuscated variants when stealth is needed

2. **Web exploit payloads** — adapt for the specific vulnerability:
   - SQLi: craft injection for the target DBMS (MySQL, PostgreSQL, SQLite, MSSQL)
   - SSTI: detect template engine and craft RCE payload
   - Deserialization: generate gadget chain for the target framework
   - SSRF: chain to internal services (metadata, Redis, etc.)

3. **Binary exploit payloads**:
   - Generate shellcode using pwntools pattern
   - Account for protections: ASLR, NX, PIE, stack canaries
   - Include ROP chain if NX is enabled

4. **Environment adaptation**:
   - Handle character restrictions (null bytes, bad chars)
   - Encode/compress as needed
   - Test with `Bash` tool when possible

Output the complete, ready-to-use payload with usage instructions."""

    return {"content": [{"type": "text", "text": instructions}]}


@tool("fingerprint", "Fingerprint a remote service to identify software, version, and technologies.", {
    "target": str,
})
async def fingerprint(args: dict[str, Any]) -> dict[str, Any]:
    target = args["target"]

    instructions = f"""Fingerprint the target: {target}

## Techniques (use Bash tool to execute):
1. **HTTP headers**: `curl -sI {target}` — check Server, X-Powered-By, Set-Cookie
2. **HTML analysis**: Look for generator meta tags, known framework patterns
3. **Common paths**: Try /robots.txt, /sitemap.xml, /.well-known/, /wp-admin/, /admin/
4. **SSL/TLS**: `openssl s_client -connect <host>:443` if HTTPS
5. **Banner grab**: `nc -w3 <host> <port>` for non-HTTP services
6. **DNS**: `dig <host>` for infrastructure info

## Output:
- Software name and version (as precise as possible)
- Web framework / CMS (if applicable)
- Server OS (from headers/behavior)
- Interesting endpoints found
- Technologies detected (programming language, database hints)
- Potential attack surface"""

    return {"content": [{"type": "text", "text": instructions}]}


# ── MCP Server ─────────────────────────────────────────────────────

def oneday_mcp_server():
    """Create the 1-day exploitation tools MCP server."""
    return create_sdk_mcp_server(
        name="oneday_tools",
        tools=[cve_search, exploit_lookup, payload_gen, fingerprint],
    )
