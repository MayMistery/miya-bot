"""Sink context — domain service.

Orchestrates sink analysis and exploitability assessment using ports.
"""

from __future__ import annotations

from miya.shared.events import DomainEvent
from miya.shared.ports import CodeAnalyzerPort

from .domain import Exploitability, SinkAnalysis, SinkPattern
from .ports import SinkClassifierPort


# Well-known CWE sink patterns
_KNOWN_PATTERNS: dict[str, SinkPattern] = {
    "CWE-89": SinkPattern(
        cwe_id="CWE-89", cwe_name="SQL Injection",
        function_pattern="execute($QUERY)", description="Unsanitized SQL query construction",
    ),
    "CWE-78": SinkPattern(
        cwe_id="CWE-78", cwe_name="OS Command Injection",
        function_pattern="system($CMD)", description="Shell command with user input",
    ),
    "CWE-79": SinkPattern(
        cwe_id="CWE-79", cwe_name="Cross-site Scripting (XSS)",
        function_pattern="render($HTML)", description="Unescaped user data in HTML output",
    ),
    "CWE-22": SinkPattern(
        cwe_id="CWE-22", cwe_name="Path Traversal",
        function_pattern="open($PATH)", description="User-controlled file path",
    ),
    "CWE-502": SinkPattern(
        cwe_id="CWE-502", cwe_name="Deserialization of Untrusted Data",
        function_pattern="loads($DATA)", description="Deserialization of user-controlled data",
    ),
    "CWE-918": SinkPattern(
        cwe_id="CWE-918", cwe_name="Server-Side Request Forgery (SSRF)",
        function_pattern="request($URL)", description="HTTP request to user-controlled URL",
    ),
    "CWE-94": SinkPattern(
        cwe_id="CWE-94", cwe_name="Code Injection",
        function_pattern="eval($CODE)", description="Dynamic code evaluation with user input",
    ),
    "CWE-611": SinkPattern(
        cwe_id="CWE-611", cwe_name="XML External Entity (XXE)",
        function_pattern="parse($XML)", description="XML parsing without disabling external entities",
    ),
    "CWE-601": SinkPattern(
        cwe_id="CWE-601", cwe_name="Open Redirect",
        function_pattern="redirect($URL)", description="Redirect to user-controlled URL",
    ),
    "CWE-1336": SinkPattern(
        cwe_id="CWE-1336", cwe_name="Server-Side Template Injection (SSTI)",
        function_pattern="Template($TMPL)", description="Template rendering with user input",
    ),
}


class SinkService:
    """Domain service for sink classification and exploitability assessment.

    Uses CodeAnalyzerPort (Semgrep) for pattern matching and optionally
    SinkClassifierPort for deeper CWE classification.
    """

    def __init__(
        self,
        code_analyzer: CodeAnalyzerPort,
        classifier: SinkClassifierPort | None = None,
    ) -> None:
        self._analyzer = code_analyzer
        self._classifier = classifier

    async def analyze_sink(
        self,
        analysis: SinkAnalysis,
        code_context: str = "",
        language: str = "",
    ) -> list[DomainEvent]:
        """Analyze a sink to determine CWE classification and exploitability.

        Uses static analysis rules and optionally the classifier port
        for deeper assessment.
        """
        if self._classifier is not None:
            result = await self._classifier.classify_sink(
                function_signature=analysis.sink_function,
                code_context=code_context,
                language=language,
            )
            cwe_id = result.get("cwe_id", "")
            pattern = _KNOWN_PATTERNS.get(cwe_id, SinkPattern(
                cwe_id=cwe_id,
                cwe_name=result.get("cwe_name", "Unknown"),
                function_pattern=analysis.sink_function,
                description=result.get("description", ""),
            ))
            exploitability = Exploitability(
                attack_vector=result.get("attack_vector", "network"),  # type: ignore[arg-type]
                attack_complexity=result.get("attack_complexity", "low"),  # type: ignore[arg-type]
                privileges_required=result.get("privileges_required", "none"),  # type: ignore[arg-type]
                user_interaction=result.get("user_interaction", "none"),  # type: ignore[arg-type]
                impact_confidentiality=result.get("impact_confidentiality", "high"),  # type: ignore[arg-type]
                impact_integrity=result.get("impact_integrity", "high"),  # type: ignore[arg-type]
                impact_availability=result.get("impact_availability", "low"),  # type: ignore[arg-type]
            )
        else:
            # Fall back to static analysis
            findings = await self._analyzer.scan(
                target_path=analysis.file_path,
                rules=["cwe-top-25", "owasp-top-10"],
                language=language or None,
            )
            pattern, exploitability = self._classify_from_findings(
                analysis.sink_function, findings,
            )

        if pattern is not None:
            analysis.confirm_sink(pattern, exploitability)
        else:
            analysis.mark_false_positive("No matching CWE pattern found")

        return analysis.collect_events()

    async def batch_analyze(
        self,
        analyses: list[SinkAnalysis],
        language: str = "",
    ) -> list[DomainEvent]:
        """Analyze multiple sinks in batch. Returns all emitted events."""
        all_events: list[DomainEvent] = []
        for analysis in analyses:
            events = await self.analyze_sink(analysis, language=language)
            all_events.extend(events)
        return all_events

    @staticmethod
    def _classify_from_findings(
        sink_function: str,
        findings: list[dict],
    ) -> tuple[SinkPattern | None, Exploitability]:
        """Derive CWE pattern and exploitability from static analysis findings."""
        for finding in findings:
            cwe_id = finding.get("cwe_id", finding.get("metadata", {}).get("cwe", ""))
            if cwe_id and cwe_id in _KNOWN_PATTERNS:
                pattern = _KNOWN_PATTERNS[cwe_id]
                exploitability = Exploitability(
                    attack_complexity="low" if finding.get("severity", "") in ("ERROR", "WARNING") else "high",
                )
                return pattern, exploitability

        return None, Exploitability()
