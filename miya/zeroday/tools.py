"""0-day discovery tools — code audit, fuzzing, taint analysis.

Smart orchestrators that guide Claude's reasoning and delegate to
static analysis tools via Bash.
"""

from __future__ import annotations

from typing import Any

from claude_agent_sdk import tool, create_sdk_mcp_server


@tool("code_audit", "Deep source code audit for vulnerability patterns. Guides systematic review by CWE category.", {
    "target_path": str,
    "language": str,
    "focus": str,
})
async def code_audit(args: dict[str, Any]) -> dict[str, Any]:
    target = args["target_path"]
    language = args.get("language", "auto")
    focus = args.get("focus", "all")

    vuln_patterns = {
        "injection": {
            "python": [
                "os.system(", "subprocess.call(", "eval(", "exec(",
                "cursor.execute(.*%", 'f".*{.*}.*SELECT', "render_template_string(",
                "__import__(",
            ],
            "javascript": [
                "eval(", "child_process.exec(", "innerHTML", "document.write(",
                "$.html(", "dangerouslySetInnerHTML", "new Function(",
            ],
            "go": [
                'fmt.Sprintf("SELECT', "exec.Command(", "template.HTML(",
                'db.Query(.*".*+', "os.Exec(",
            ],
            "c": [
                "system(", "popen(", "execve(", "sprintf(buf",
                "strcpy(", "strcat(", "gets(",
            ],
        },
        "memory": {
            "c": [
                "malloc(.*free(", "strcpy(", "strncpy(", "memcpy(",
                "sprintf(", "gets(", "scanf(%s", "alloca(",
            ],
        },
        "logic": {
            "_any": [
                "isAdmin", "is_admin", "role.*==", "token.*=",
                "password.*==", "bypass", "DEBUG.*True", "verify.*False",
            ],
        },
        "crypto": {
            "_any": [
                "MD5", "SHA1", "DES", "ECB", "hardcoded.*key",
                "random.random()", "Math.random()", "rand()",
                "PKCS1v15", "password.*=.*\"",
            ],
        },
    }

    # Build audit guidance
    if focus == "all":
        categories = list(vuln_patterns.keys())
    else:
        categories = [f for f in focus.split(",") if f.strip() in vuln_patterns]
        if not categories:
            categories = list(vuln_patterns.keys())

    lines = [
        f"# Code Audit Plan: {target}",
        f"Language: {language}",
        f"Focus: {', '.join(categories)}",
        "",
        "## Step 1: Reconnaissance",
        f"Use `Glob` to map the project structure under `{target}`.",
        "Identify entry points: main files, route handlers, API endpoints.",
        "",
        "## Step 2: Pattern-Based Search",
        "Use `Grep` to search for these vulnerability indicators:",
        "",
    ]

    for cat in categories:
        patterns = vuln_patterns.get(cat, {})
        lang_patterns = patterns.get(language, patterns.get("_any", []))
        if lang_patterns:
            lines.append(f"### {cat.upper()}")
            for p in lang_patterns:
                lines.append(f"  - `{p}`")
            lines.append("")

    lines.extend([
        "## Step 3: Taint Analysis",
        "For each suspicious pattern found:",
        "1. Trace the data flow: Where does the input come from? (source)",
        "2. Is it sanitized/validated before reaching the sink?",
        "3. Can an attacker control the input?",
        "4. What's the impact if exploited?",
        "",
        "## Step 4: Proof of Concept",
        "For confirmed vulnerabilities:",
        "1. Construct a minimal PoC input that triggers the bug",
        "2. Describe the exact attack scenario",
        "3. Assess severity (CVSS-like: access required, impact, complexity)",
        "",
        "## Step 5: Report",
        "For each finding: CWE ID, location, description, PoC, severity, remediation.",
    ])

    return {"content": [{"type": "text", "text": "\n".join(lines)}]}


@tool("fuzz_guide", "Generate fuzzing strategy and harness for a target function or endpoint.", {
    "target": str,
    "target_type": str,
    "language": str,
})
async def fuzz_guide(args: dict[str, Any]) -> dict[str, Any]:
    target = args["target"]
    target_type = args.get("target_type", "function")  # function, endpoint, binary
    language = args.get("language", "auto")

    lines = [
        f"# Fuzzing Strategy: {target}",
        f"Type: {target_type} | Language: {language}",
        "",
    ]

    if target_type == "function":
        lines.extend([
            "## Approach: Function-level fuzzing",
            "",
            "### 1. Harness Generation",
            f"Read the function `{target}` and understand its input types.",
            "Write a fuzzing harness that:",
            "- Accepts arbitrary bytes from stdin or a file",
            "- Transforms bytes into valid input types for the function",
            "- Calls the target function",
            "- Catches and reports crashes",
            "",
            "### 2. Seed Corpus",
            "Generate initial test cases:",
            "- Valid inputs (happy path)",
            "- Boundary values (empty, max-length, type boundaries)",
            "- Known-bad inputs (format strings, SQL, shell metacharacters)",
            "",
            "### 3. Execution",
            "For Python: use `atheris` or `hypothesis`",
            "For C/C++: use `AFL++` or `libFuzzer`",
            "For Go: use `go-fuzz`",
            "For JavaScript: use `jsfuzz`",
            "",
            "### 4. Triage",
            "For each crash: minimize input, identify root cause, classify (CWE).",
        ])
    elif target_type == "endpoint":
        lines.extend([
            "## Approach: HTTP endpoint fuzzing",
            "",
            f"### Target: {target}",
            "",
            "### 1. Parameter Discovery",
            "- Identify all input vectors: URL params, POST body, headers, cookies",
            "- Map expected types and constraints",
            "",
            "### 2. Fuzz Vectors",
            "For each parameter, test with:",
            "- Type confusion: string where int expected, arrays, objects",
            "- Injection: SQLi, XSS, SSTI, CMDi, path traversal payloads",
            "- Boundary: empty, null, very long, Unicode, special chars",
            "- Format strings: %s, %x, %n, {0}, ${7*7}",
            "",
            "### 3. Using Bash",
            "Generate curl commands or a Python script (requests/httpx) that",
            "systematically tests each parameter with each fuzz vector.",
            "Monitor for: 500 errors, timeouts, unexpected responses, error messages leaking info.",
        ])
    elif target_type == "binary":
        lines.extend([
            "## Approach: Binary fuzzing",
            "",
            f"### Target: {target}",
            "",
            "### 1. Recon",
            "Run `file`, `checksec`, `strings`, `ltrace`/`strace` on the binary.",
            "Identify: input methods (stdin, file, network), libraries, protections.",
            "",
            "### 2. Harness",
            "If the binary reads from file: use AFL++ with `afl-fuzz -i seeds/ -o out/ -- ./binary @@`",
            "If stdin: pipe input `afl-fuzz -i seeds/ -o out/ -- ./binary`",
            "If network: use `afl-fuzz` with network mode or `boofuzz` for protocol fuzzing.",
            "",
            "### 3. Seed Corpus",
            "Create valid inputs, then mutate.",
            "Use `radamsa` for smart mutation.",
        ])

    return {"content": [{"type": "text", "text": "\n".join(lines)}]}


@tool("taint_trace", "Trace data flow from untrusted source to dangerous sink in source code.", {
    "source_pattern": str,
    "sink_pattern": str,
    "target_path": str,
})
async def taint_trace(args: dict[str, Any]) -> dict[str, Any]:
    source = args["source_pattern"]
    sink = args["sink_pattern"]
    target = args["target_path"]

    instructions = f"""# Taint Trace: {source} → {sink}
Target: {target}

## Procedure:

### 1. Find Sources
Use `Grep` to find all occurrences of the source pattern: `{source}`
in `{target}`. These are where untrusted data enters.

### 2. Find Sinks
Use `Grep` to find all occurrences of the sink pattern: `{sink}`
in `{target}`. These are dangerous operations.

### 3. Trace Data Flow
For each source, trace the variable through assignments, function calls,
and transformations until it reaches a sink (or gets sanitized).

Key questions:
- Is the data validated/sanitized between source and sink?
- Does it pass through any encoding/escaping functions?
- Are there conditional paths where sanitization is skipped?
- Can the data flow through multiple functions/files?

### 4. Common Source → Sink Pairs
| Source | Sink | Vuln Type |
|--------|------|-----------|
| request.GET/POST | cursor.execute() | SQL Injection |
| request.* | os.system/popen | Command Injection |
| request.* | render_template_string | SSTI |
| request.* | innerHTML/document.write | XSS |
| file.read() | yaml.load/pickle.loads | Deserialization |
| user input | redirect/open | SSRF/Open Redirect |
| recv()/read() | memcpy/strcpy | Buffer Overflow |

### 5. Report
For each confirmed taint flow:
- Source location (file:line)
- Sink location (file:line)
- Intermediate steps (variable assignments, function calls)
- Sanitization status (none / insufficient / bypassed)
- Exploitability assessment"""

    return {"content": [{"type": "text", "text": instructions}]}


# ── MCP Server ─────────────────────────────────────────────────────

def zeroday_mcp_server():
    """Create the 0-day discovery tools MCP server."""
    return create_sdk_mcp_server(
        name="zeroday_tools",
        tools=[code_audit, fuzz_guide, taint_trace],
    )
