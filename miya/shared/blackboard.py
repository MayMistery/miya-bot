"""Blackboard — shared knowledge base projected from EventStore.

The Blackboard is a materialized view of all domain events. It provides
structured access to the current state of knowledge about the target,
without agents needing to query the event store directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from miya.shared.types import Asset, Credential, Finding, Severity
from miya.shared.attack_graph import AttackGraph, GraphNode, GraphEdge
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
    PrivilegeEscalated,
    LootCollected,
    PhaseTransition,
    ReflectionCompleted,
)


def _parse_severity(raw: str) -> Severity:
    """Parse severity string with fallback to MEDIUM."""
    try:
        return Severity(raw.lower())
    except (ValueError, AttributeError):
        return Severity.MEDIUM


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
    cve_matches: list[dict[str, Any]] = field(default_factory=list)

    # ── Attack state ──────────────────────────────────────────────
    attack_graph: AttackGraph = field(default_factory=AttackGraph)
    current_access_level: str = "none"  # "none", "user", "root", "system"

    # ── 0-day specific ────────────────────────────────────────────
    entry_points: list[dict[str, Any]] = field(default_factory=list)
    taint_paths: list[dict[str, Any]] = field(default_factory=list)
    confirmed_sinks: list[dict[str, Any]] = field(default_factory=list)
    validated_pocs: list[dict[str, Any]] = field(default_factory=list)

    # ── CTF specific ──────────────────────────────────────────────
    challenges: list[dict[str, Any]] = field(default_factory=list)
    solved_flags: list[dict[str, Any]] = field(default_factory=list)

    # ── Execution trace ───────────────────────────────────────────
    events: list[DomainEvent] = field(default_factory=list)
    phase_history: list[dict[str, str]] = field(default_factory=list)
    reflections: list[dict[str, str]] = field(default_factory=list)
    exploit_attempts: list[dict[str, Any]] = field(default_factory=list)

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
            fp["version"] = e.version
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
            if existing["cve_id"] == e.cve_id:
                if e.cvss > existing.get("cvss", 0):
                    existing["cvss"] = e.cvss
                if e.exploit_available:
                    existing["exploit_available"] = True
                return
        self.cve_matches.append({
            "cve_id": e.cve_id,
            "cvss": e.cvss,
            "affected": e.affected_software,
            "exploit_available": e.exploit_available,
        })

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
        self.exploit_attempts.append({
            "cve_id": e.cve_id,
            "technique": e.technique,
            "payload": e.payload_summary,
            "status": "attempted",
        })

    def _on_ExploitSucceeded(self, e: ExploitSucceeded) -> None:
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
            if attempt.get("cve_id") == e.cve_id and attempt.get("status") == "attempted":
                attempt["status"] = "succeeded"
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
            if attempt.get("cve_id") == e.cve_id and attempt.get("status") == "attempted":
                attempt["status"] = "failed"
                break

    def _on_EntryPointDiscovered(self, e: EntryPointDiscovered) -> None:
        self.entry_points.append({
            "endpoint": e.endpoint,
            "input_vectors": list(e.input_vectors),
            "framework": e.framework,
        })

    def _on_TaintPathTraced(self, e: TaintPathTraced) -> None:
        self.taint_paths.append({
            "source": e.source,
            "sink": e.sink,
            "path": list(e.path),
            "sanitized": e.sanitized,
        })

    def _on_SinkConfirmed(self, e: SinkConfirmed) -> None:
        self.confirmed_sinks.append({
            "sink_type": e.sink_type,
            "cwe_id": e.cwe_id,
            "exploitability": e.exploitability,
        })

    def _on_PoCValidated(self, e: PoCValidated) -> None:
        self.validated_pocs.append({
            "vuln_type": e.vuln_type,
            "poc_code": e.poc_code,
            "result": e.result,
        })

    def _on_ChallengeIdentified(self, e: ChallengeIdentified) -> None:
        self.challenges.append({
            "name": e.challenge_name,
            "category": e.category,
            "points": e.points,
        })

    def _on_ChallengeSolved(self, e: ChallengeSolved) -> None:
        self.solved_flags.append({
            "challenge": e.challenge_name,
            "flag": e.flag,
            "approach": e.approach,
        })

    def _on_PrivilegeEscalated(self, e: PrivilegeEscalated) -> None:
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
        self.phase_history.append({
            "from": e.from_phase,
            "to": e.to_phase,
            "reason": e.reason,
        })

    def _on_ReflectionCompleted(self, e: ReflectionCompleted) -> None:
        self.reflections.append({
            "assessment": e.assessment,
            "decision": e.decision,
            "insights": e.insights,
        })

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

    def to_context_prompt(self, *, max_findings: int = 30) -> str:
        """Serialize blackboard state into a context string for LLM prompts.

        Args:
            max_findings: Cap on findings shown (most severe first).
                          Keeps the prompt from ballooning on large engagements.
        """
        lines = ["## Current Knowledge Base (Blackboard)"]

        if self.assets:
            lines.append(f"\n### Assets ({len(self.assets)})")
            for a in self.assets.values():
                ports_str = ", ".join(str(p) for p in a.ports) if a.ports else "unknown"
                lines.append(f"- {a.address}: ports=[{ports_str}] services={list(a.services)} os={a.os}")
                if a.fingerprint:
                    lines.append(f"  fingerprint: {a.fingerprint}")

        if self.findings:
            sorted_findings = sorted(self.findings, key=lambda x: -x.severity.score)
            shown = sorted_findings[:max_findings]
            omitted = len(sorted_findings) - len(shown)
            lines.append(f"\n### Findings ({len(self.findings)})")
            for f in shown:
                lines.append(f"- {f.oneliner()}: {f.detail[:100]}")
            if omitted:
                lines.append(f"  ... and {omitted} more (lower severity)")

        if self.cve_matches:
            lines.append(f"\n### CVE Matches ({len(self.cve_matches)})")
            for c in self.cve_matches:
                exploit_tag = " [EXPLOIT AVAILABLE]" if c.get("exploit_available") else ""
                lines.append(f"- {c['cve_id']} (CVSS {c['cvss']}){exploit_tag}: {c['affected']}")

        if self.entry_points:
            lines.append(f"\n### Entry Points ({len(self.entry_points)})")
            for ep in self.entry_points:
                lines.append(f"- {ep['endpoint']}: inputs={ep['input_vectors']}")

        if self.taint_paths:
            unsanitized = [t for t in self.taint_paths if not t["sanitized"]]
            lines.append(f"\n### Taint Paths ({len(self.taint_paths)}, {len(unsanitized)} unsanitized)")
            for t in unsanitized[:10]:
                lines.append(f"- {t['source']} → {t['sink']} (UNSANITIZED)")

        if self.confirmed_sinks:
            lines.append(f"\n### Confirmed Sinks ({len(self.confirmed_sinks)})")
            for s in self.confirmed_sinks:
                lines.append(f"- {s['sink_type']} ({s.get('cwe_id', '')}): {s.get('exploitability', '')}")

        if self.validated_pocs:
            lines.append(f"\n### Validated PoCs ({len(self.validated_pocs)})")
            for p in self.validated_pocs:
                lines.append(f"- {p['vuln_type']}: {p['result'][:80]}")

        if self.challenges:
            solved_names = {s["challenge"] for s in self.solved_flags}
            lines.append(f"\n### Challenges ({len(self.challenges)}, {len(solved_names)} solved)")
            for c in self.challenges:
                status = "SOLVED" if c["name"] in solved_names else "unsolved"
                lines.append(f"- [{status}] {c['name']} ({c['category']}, {c['points']}pts)")

        if self.exploit_attempts:
            lines.append(f"\n### Exploit Attempts ({len(self.exploit_attempts)})")
            for ea in self.exploit_attempts[-5:]:
                lines.append(f"- {ea['cve_id']}: {ea['technique']} [{ea.get('status', '?')}]")

        lines.append(f"\n### Current Access: {self.current_access_level}")
        lines.append(f"### Attack Graph: {self.attack_graph.summary()}")

        return "\n".join(lines)
