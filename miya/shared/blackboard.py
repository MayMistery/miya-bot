"""Blackboard — shared knowledge base projected from EventStore.

The Blackboard is a materialized view of all domain events. It provides
structured access to the current state of knowledge about the target,
without agents needing to query the event store directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar

from miya.shared.types import Asset, Credential, Finding, Severity
from miya.shared.attack_graph import AttackGraph, GraphNode
from miya.shared.events import (
    DomainEvent,
    AssetDiscovered,
    FingerprintCompleted,
    ScanCompleted,
    VulnerabilityFound,
    CVEMatched,
    ExploitSucceeded,
    ExploitFailed,
    ExploitAttempted,
    EntryPointDiscovered,
    TaintPathTraced,
    SinkConfirmed,
    PoCValidated,
    ChallengeIdentified,
    ChallengeSolved,
    ChallengeClassified,
    FlagSubmitted,
    PrivilegeEscalated,
    LootCollected,
    PhaseTransition,
    ReflectionCompleted,
    OperatorMessage,
)


def _parse_severity(raw: str) -> Severity:
    """Parse severity string with fallback to MEDIUM."""
    try:
        return Severity(raw.lower())
    except (ValueError, AttributeError):
        return Severity.MEDIUM


# ═══════════════════════════════════════════════════════════════════
#  Projection Value Objects — typed alternatives to dict[str, Any]
# ═══════════════════════════════════════════════════════════════════


@dataclass
class CVEMatchView:
    """Projected CVE match for blackboard display."""

    cve_id: str = ""
    cvss: float = 0.0
    affected: str = ""
    exploit_available: bool = False


@dataclass(frozen=True)
class EntryPointView:
    """Projected entry point for blackboard display."""

    endpoint: str = ""
    input_vectors: tuple[str, ...] = ()
    framework: str = ""


@dataclass(frozen=True)
class TaintPathView:
    """Projected taint path for blackboard display."""

    source: str = ""
    sink: str = ""
    path: tuple[str, ...] = ()
    sanitized: bool = False


@dataclass(frozen=True)
class SinkView:
    """Projected confirmed sink for blackboard display."""

    sink_type: str = ""
    cwe_id: str = ""
    exploitability: str = ""


@dataclass(frozen=True)
class PoCView:
    """Projected PoC for blackboard display."""

    vuln_type: str = ""
    poc_code: str = ""
    result: str = ""


@dataclass(frozen=True)
class ChallengeView:
    """Projected CTF challenge for blackboard display."""

    name: str = ""
    category: str = ""
    points: int = 0
    difficulty: str = ""
    technology_stack: tuple[str, ...] = ()
    file_paths: tuple[str, ...] = ()
    target_url: str = ""


@dataclass(frozen=True)
class SolvedFlagView:
    """Projected solved flag for blackboard display."""

    challenge: str = ""
    flag: str = ""
    approach: str = ""


@dataclass(frozen=True)
class ClassificationView:
    """Projected challenge classification for blackboard display."""

    category: str = ""
    confidence: float = 0.0
    reasoning: str = ""


@dataclass(frozen=True)
class FlagSubmissionView:
    """Projected flag submission result for blackboard display."""

    challenge: str = ""
    flag: str = ""
    accepted: bool = False
    response: str = ""


@dataclass(frozen=True)
class PhaseRecord:
    """Projected phase transition for blackboard display."""

    from_phase: str = ""
    to_phase: str = ""
    reason: str = ""


@dataclass(frozen=True)
class ReflectionRecord:
    """Projected reflection result for blackboard display."""

    assessment: str = ""
    decision: str = ""
    insights: str = ""
    next_focus: str = ""


@dataclass
class ExploitAttemptView:
    """Projected exploit attempt for blackboard display."""

    cve_id: str = ""
    technique: str = ""
    payload: str = ""
    status: str = "attempted"  # "attempted", "succeeded", "failed"


# ═══════════════════════════════════════════════════════════════════
#  Blackboard
# ═══════════════════════════════════════════════════════════════════


@dataclass
class Blackboard:
    """Cross-agent shared knowledge base.

    Built by projecting domain events. Each agent reads from and contributes
    to the blackboard through events.
    """

    # ── Discovered knowledge ──────────────────────────────────────
    assets: dict[str, Asset] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    cve_matches: list[CVEMatchView] = field(default_factory=list)

    # ── Attack state ──────────────────────────────────────────────
    attack_graph: AttackGraph = field(default_factory=AttackGraph)
    current_access_level: str = "none"  # "none", "user", "root", "system"

    # ── 0-day specific ────────────────────────────────────────────
    entry_points: list[EntryPointView] = field(default_factory=list)
    taint_paths: list[TaintPathView] = field(default_factory=list)
    confirmed_sinks: list[SinkView] = field(default_factory=list)
    validated_pocs: list[PoCView] = field(default_factory=list)

    # ── CTF specific ──────────────────────────────────────────────
    challenges: list[ChallengeView] = field(default_factory=list)
    solved_flags: list[SolvedFlagView] = field(default_factory=list)
    classification: ClassificationView | None = None
    flag_submissions: list[FlagSubmissionView] = field(default_factory=list)

    # ── Execution trace ───────────────────────────────────────────
    events: list[DomainEvent] = field(default_factory=list)
    phase_history: list[PhaseRecord] = field(default_factory=list)
    reflections: list[ReflectionRecord] = field(default_factory=list)
    exploit_attempts: list[ExploitAttemptView] = field(default_factory=list)

    # ── Operator (HITL) ───────────────────────────────────────────
    operator_messages: list[str] = field(default_factory=list)

    # ── Projectors ────────────────────────────────────────────────

    def apply(self, event: DomainEvent) -> None:
        """Project a single event into the blackboard state."""
        self.events.append(event)
        self._dispatch(event)

    def apply_all(self, events: list[DomainEvent]) -> None:
        for event in events:
            self.apply(event)

    def _dispatch(self, event: DomainEvent) -> None:
        """Route event to the appropriate projector method."""
        projector = getattr(self, f"_on_{event.__class__.__name__}", None)
        if projector:
            projector(event)

    # ── Individual projectors ─────────────────────────────────────

    def _on_AssetDiscovered(self, e: AssetDiscovered) -> None:
        asset = Asset(
            id=e.aggregate_id or e.event_id,
            host=e.host,
            ip=e.ip,
            ports=e.ports,
            services=e.services,
            os=e.os,
        )
        self.assets[asset.id] = asset
        # Add to attack graph
        node = GraphNode(
            id=asset.id,
            label=f"{e.host or e.ip}",
            node_type="asset",
            properties={"ports": list(e.ports), "services": list(e.services)},
        )
        self.attack_graph.add_node(node)

    def _on_FingerprintCompleted(self, e: FingerprintCompleted) -> None:
        if e.asset_id in self.assets:
            old = self.assets[e.asset_id]
            fp = dict(old.fingerprint)
            fp["software"] = e.software
            fp["version"] = e.software_version
            fp["technology_stack"] = ", ".join(e.technology_stack)
            self.assets[e.asset_id] = Asset(
                id=old.id, host=old.host, ip=old.ip,
                ports=old.ports, services=old.services, os=old.os,
                fingerprint=fp,
            )

    def _on_VulnerabilityFound(self, e: VulnerabilityFound) -> None:
        finding = Finding(
            id=e.vuln_id or e.event_id,
            title=f"{e.cwe_id} {e.vuln_type}",
            severity=_parse_severity(e.severity),
            detail=e.description,
            evidence=e.location,
            context=e.context,
            mission=e.mission,
        )
        if not self._is_duplicate_finding(finding):
            self.findings.append(finding)
        # Add vulnerability node to attack graph
        vuln_node = GraphNode(
            id=finding.id,
            label=finding.title,
            node_type="vulnerability",
            properties={"cwe": e.cwe_id, "severity": e.severity},
        )
        self.attack_graph.add_node(vuln_node)

    def _on_CVEMatched(self, e: CVEMatched) -> None:
        # Deduplicate by CVE ID — update if higher CVSS or new exploit info
        for existing in self.cve_matches:
            if existing.cve_id == e.cve_id:
                if e.cvss > existing.cvss:
                    existing.cvss = e.cvss
                if e.exploit_available:
                    existing.exploit_available = True
                return
        self.cve_matches.append(CVEMatchView(
            cve_id=e.cve_id,
            cvss=e.cvss,
            affected=e.affected_software,
            exploit_available=e.exploit_available,
        ))

    def _on_ScanCompleted(self, e: ScanCompleted) -> None:
        self.findings.append(Finding(
            title=f"Scan completed: {e.target_host}",
            severity=Severity.INFO,
            detail=f"Scanner {e.scanner} found {e.findings_count} issue(s) on ports {list(e.target_ports)}",
            evidence=f"{e.scanner}:{e.target_host}",
            context=e.context,
            mission=e.mission,
        ))

    def _on_ExploitAttempted(self, e: ExploitAttempted) -> None:
        self.exploit_attempts.append(ExploitAttemptView(
            cve_id=e.cve_id,
            technique=e.technique,
            payload=e.payload_summary,
            status="attempted",
        ))

    # Access level ordering for monotonic escalation
    _ACCESS_RANK: ClassVar[dict[str, int]] = {
        "": 0, "none": 0, "user": 1, "admin": 2,
        "data_read": 1, "rce": 3, "root": 4, "system": 4,
    }

    def _on_ExploitSucceeded(self, e: ExploitSucceeded) -> None:
        # Only upgrade access level, never downgrade
        new_rank = self._ACCESS_RANK.get(e.access_gained.lower(), 1)
        old_rank = self._ACCESS_RANK.get(self.current_access_level.lower(), 0)
        if new_rank >= old_rank:
            self.current_access_level = e.access_gained
        self.findings.append(Finding(
            title=f"Exploit succeeded: {e.cve_id}",
            severity=Severity.CRITICAL,
            detail=f"Gained {e.access_gained} access",
            evidence=e.evidence,
            context=e.context,
            mission=e.mission,
        ))
        # Update matching attempt status
        for attempt in reversed(self.exploit_attempts):
            if attempt.cve_id == e.cve_id and attempt.status == "attempted":
                attempt.status = "succeeded"
                break

    def _on_ExploitFailed(self, e: ExploitFailed) -> None:
        self.findings.append(Finding(
            title=f"Exploit failed: {e.cve_id}",
            severity=Severity.INFO,
            detail=e.reason,
            evidence="",
            context=e.context,
            mission=e.mission,
        ))
        # Update matching attempt status
        for attempt in reversed(self.exploit_attempts):
            if attempt.cve_id == e.cve_id and attempt.status == "attempted":
                attempt.status = "failed"
                break

    def _on_EntryPointDiscovered(self, e: EntryPointDiscovered) -> None:
        ep = EntryPointView(
            endpoint=e.endpoint,
            input_vectors=e.input_vectors,
            framework=e.framework,
        )
        if not self._is_duplicate_entry_point(ep):
            self.entry_points.append(ep)

    def _on_TaintPathTraced(self, e: TaintPathTraced) -> None:
        tp = TaintPathView(
            source=e.source,
            sink=e.sink,
            path=e.path,
            sanitized=e.sanitized,
        )
        if not self._is_duplicate_taint_path(tp):
            self.taint_paths.append(tp)

    def _on_SinkConfirmed(self, e: SinkConfirmed) -> None:
        self.confirmed_sinks.append(SinkView(
            sink_type=e.sink_type,
            cwe_id=e.cwe_id,
            exploitability=e.exploitability,
        ))

    def _on_PoCValidated(self, e: PoCValidated) -> None:
        self.validated_pocs.append(PoCView(
            vuln_type=e.vuln_type,
            poc_code=e.poc_code,
            result=e.result,
        ))

    def _on_ChallengeIdentified(self, e: ChallengeIdentified) -> None:
        self.challenges.append(ChallengeView(
            name=e.challenge_name,
            category=e.category,
            points=e.points,
            difficulty=e.difficulty,
            technology_stack=e.technology_stack,
            file_paths=e.file_paths,
            target_url=e.target_url,
        ))

    def _on_ChallengeSolved(self, e: ChallengeSolved) -> None:
        self.solved_flags.append(SolvedFlagView(
            challenge=e.challenge_name,
            flag=e.flag,
            approach=e.approach,
        ))

    def _on_ChallengeClassified(self, e: ChallengeClassified) -> None:
        self.classification = ClassificationView(
            category=e.category,
            confidence=e.confidence,
            reasoning=e.reasoning,
        )

    def _on_FlagSubmitted(self, e: FlagSubmitted) -> None:
        self.flag_submissions.append(FlagSubmissionView(
            challenge=e.challenge_name,
            flag=e.flag,
            accepted=e.accepted,
            response=e.response,
        ))

    def _on_PrivilegeEscalated(self, e: PrivilegeEscalated) -> None:
        new_rank = self._ACCESS_RANK.get(e.to_level.lower(), 1)
        old_rank = self._ACCESS_RANK.get(self.current_access_level.lower(), 0)
        if new_rank >= old_rank:
            self.current_access_level = e.to_level

    def _on_LootCollected(self, e: LootCollected) -> None:
        if e.loot_type in ("credential", "credentials"):
            self.credentials.append(Credential(
                username="",
                secret=e.value or e.description,
                secret_type="password",
            ))
        # Always record as finding for visibility
        self.findings.append(Finding(
            title=f"Loot: {e.loot_type}",
            severity=Severity.HIGH,
            detail=e.description,
            evidence=e.value or "",
            context=e.context,
            mission=e.mission,
        ))

    def _on_PhaseTransition(self, e: PhaseTransition) -> None:
        self.phase_history.append(PhaseRecord(
            from_phase=e.from_phase,
            to_phase=e.to_phase,
            reason=e.reason,
        ))

    def _on_ReflectionCompleted(self, e: ReflectionCompleted) -> None:
        self.reflections.append(ReflectionRecord(
            assessment=e.assessment,
            decision=e.decision,
            insights=e.insights,
            next_focus=getattr(e, "next_focus", ""),
        ))

    def _on_OperatorMessage(self, e: OperatorMessage) -> None:
        self.operator_messages.append(e.content)

    # ── Deduplication helpers ─────────────────────────────────────

    def _is_duplicate_finding(self, finding: Finding) -> bool:
        """Check if a finding is a duplicate based on title + context + severity."""
        for existing in self.findings:
            if (
                existing.title == finding.title
                and existing.context == finding.context
                and existing.severity == finding.severity
            ):
                return True
        return False

    def _is_duplicate_entry_point(self, ep: EntryPointView) -> bool:
        for existing in self.entry_points:
            if existing.endpoint == ep.endpoint:
                return True
        return False

    def _is_duplicate_taint_path(self, tp: TaintPathView) -> bool:
        for existing in self.taint_paths:
            if existing.source == tp.source and existing.sink == tp.sink:
                return True
        return False

    # ── Compaction ─────────────────────────────────────────────────

    def compact(
        self,
        *,
        max_findings: int = 200,
        max_events: int = 500,
        max_phase_history: int = 50,
        max_reflections: int = 20,
        max_exploit_attempts: int = 50,
        max_entry_points: int = 100,
        max_taint_paths: int = 100,
        max_confirmed_sinks: int = 50,
        max_challenges: int = 200,
    ) -> dict[str, int]:
        """Compact the blackboard by trimming unbounded lists.

        Keeps the most important items: critical findings over info,
        recent events over old, etc. Returns a dict of {list_name: items_removed}.

        Call this periodically (e.g. between OODA iterations) to prevent
        unbounded memory growth on long-running missions.
        """
        removed: dict[str, int] = {}

        def _trim_list(lst: list, max_size: int, name: str, *, keep_tail: bool = True) -> None:
            """Trim list in-place, keeping tail (most recent) by default."""
            if len(lst) <= max_size:
                return
            excess = len(lst) - max_size
            if keep_tail:
                del lst[:excess]
            else:
                del lst[max_size:]
            removed[name] = excess

        # Findings: keep most severe, then most recent within same severity
        if len(self.findings) > max_findings:
            sorted_findings = sorted(
                self.findings,
                key=lambda f: (-f.severity.score, self.findings.index(f)),
            )
            excess = len(self.findings) - max_findings
            self.findings[:] = sorted_findings[:max_findings]
            removed["findings"] = excess

        # Events: keep most recent
        _trim_list(self.events, max_events, "events")

        # Execution trace lists: keep most recent
        _trim_list(self.phase_history, max_phase_history, "phase_history")
        _trim_list(self.reflections, max_reflections, "reflections")
        _trim_list(self.exploit_attempts, max_exploit_attempts, "exploit_attempts")

        # 0-day lists
        _trim_list(self.entry_points, max_entry_points, "entry_points")
        _trim_list(self.taint_paths, max_taint_paths, "taint_paths")
        _trim_list(self.confirmed_sinks, max_confirmed_sinks, "confirmed_sinks")

        # CTF lists
        _trim_list(self.challenges, max_challenges, "challenges")
        # Never compact solved_flags or credentials — these are high-value outputs

        return removed

    # ── Query helpers ─────────────────────────────────────────────

    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity >= Severity.HIGH]

    def summary(self) -> dict[str, Any]:
        return {
            "assets": len(self.assets),
            "findings": len(self.findings),
            "critical": len(self.critical_findings()),
            "credentials": len(self.credentials),
            "cve_matches": len(self.cve_matches),
            "exploit_attempts": len(self.exploit_attempts),
            "access_level": self.current_access_level,
            "events": len(self.events),
            "attack_graph": self.attack_graph.summary(),
        }

    def to_context_prompt(
        self,
        *,
        max_findings: int = 30,
        recent_detail: int = 8,
    ) -> str:
        """Serialize blackboard state into a context string for LLM prompts.

        Uses context windowing: recent items in full detail, older items as
        one-line summaries. This prevents context bloat on later iterations.

        Args:
            max_findings: Cap on findings shown (most severe first).
            recent_detail: Number of most-recent findings shown in full.
                           Older findings are compressed to one-liners.
        """
        lines = ["## Blackboard"]

        if self.assets:
            lines.append(f"\n### Assets ({len(self.assets)})")
            for a in self.assets.values():
                ports_str = ", ".join(str(p) for p in a.ports) if a.ports else "?"
                lines.append(f"- {a.address}: ports=[{ports_str}] svc={list(a.services)} os={a.os}")

        if self.findings:
            sorted_findings = sorted(self.findings, key=lambda x: -x.severity.score)
            shown = sorted_findings[:max_findings]
            omitted = len(sorted_findings) - len(shown)
            lines.append(f"\n### Findings ({len(self.findings)})")
            # Recent findings: full detail + evidence snippet
            for idx, f in enumerate(shown[:recent_detail]):
                line = f"- {f.oneliner()}: {f.detail[:100]}"
                if idx < 3 and f.evidence:
                    line += f" | evidence: {f.evidence[:80]}"
                lines.append(line)
            # Older findings: compressed one-liner
            if len(shown) > recent_detail:
                lines.append(f"  (older {len(shown) - recent_detail}:)")
                for f in shown[recent_detail:]:
                    lines.append(f"  · {f.severity.value.upper()}: {f.title[:60]}")
            if omitted:
                lines.append(f"  ... +{omitted} more")

        if self.cve_matches:
            lines.append(f"\n### CVEs ({len(self.cve_matches)})")
            for c in self.cve_matches:
                exploit_tag = " [EXPLOIT]" if c.exploit_available else ""
                lines.append(f"- {c.cve_id} CVSS={c.cvss}{exploit_tag}")

        if self.entry_points:
            lines.append(f"\n### Entry Points ({len(self.entry_points)})")
            for ep in self.entry_points[:10]:
                lines.append(f"- {ep.endpoint}: {list(ep.input_vectors)}")
            if len(self.entry_points) > 10:
                lines.append(f"  ... +{len(self.entry_points) - 10} more")

        if self.taint_paths:
            unsanitized = [t for t in self.taint_paths if not t.sanitized]
            if unsanitized:
                lines.append(f"\n### Unsanitized Taint Paths ({len(unsanitized)})")
                for t in unsanitized[:5]:
                    lines.append(f"- {t.source} → {t.sink}")

        if self.confirmed_sinks:
            lines.append(f"\n### Sinks ({len(self.confirmed_sinks)})")
            for s in self.confirmed_sinks[:5]:
                lines.append(f"- {s.sink_type} {s.cwe_id}")

        if self.validated_pocs:
            lines.append(f"\n### PoCs ({len(self.validated_pocs)})")
            for p in self.validated_pocs:
                lines.append(f"- {p.vuln_type}: {p.result[:60]}")

        if self.challenges:
            solved_names = {s.challenge for s in self.solved_flags}
            unsolved = [c for c in self.challenges if c.name not in solved_names]
            solved = [c for c in self.challenges if c.name in solved_names]
            lines.append(f"\n### Challenges ({len(self.challenges)}, {len(solved)} solved)")
            for c in unsolved:
                files = f" files={list(c.file_paths)}" if c.file_paths else ""
                lines.append(f"- [TODO] {c.name} ({c.category}){files}")
            for c in solved:
                lines.append(f"- [DONE] {c.name} ({c.category})")

        if self.solved_flags:
            lines.append(f"\n### Flags ({len(self.solved_flags)})")
            for sf in self.solved_flags:
                lines.append(f"- {sf.challenge}: {sf.flag}")

        if self.exploit_attempts:
            recent = self.exploit_attempts[-5:]
            lines.append(f"\n### Recent Exploits ({len(self.exploit_attempts)} total)")
            for ea in recent:
                lines.append(f"- {ea.cve_id or '?'}: {ea.technique} [{ea.status}]")

        if self.operator_messages:
            lines.append(f"\n### Operator ({len(self.operator_messages)})")
            for msg in self.operator_messages[-3:]:
                lines.append(f"- {msg}")

        lines.append(f"\nAccess: {self.current_access_level} | Graph: {self.attack_graph.summary()}")

        return "\n".join(lines)
