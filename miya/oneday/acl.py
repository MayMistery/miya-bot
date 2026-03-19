"""Anti-Corruption Layer for the 1-day mission kill chain.

Translates domain objects between bounded contexts, preventing direct coupling.
Each translation function converts upstream context outputs into downstream
context inputs.

Flow: Recon -> Scan -> Vuln -> Exploit -> Post
"""

from __future__ import annotations

from typing import Any

# ── Recon types ───────────────────────────────────────────────────
from miya.oneday.recon.domain import (
    Asset as ReconAsset,
    Fingerprint as ReconFingerprint,
    ReconMission,
)

# ── Scan types ────────────────────────────────────────────────────
from miya.oneday.scan.domain import ScanTarget, ScanResult, ScanTask

# ── Vuln types ────────────────────────────────────────────────────
from miya.oneday.vuln.domain import (
    VulnAssessment,
    VulnMatch,
)

# ── Exploit types ─────────────────────────────────────────────────
from miya.oneday.exploit.domain import (
    ExploitCampaign,
    ExploitAttempt,
)

# ── Post types ────────────────────────────────────────────────────
from miya.oneday.post.domain import (
    PivotTarget,
)


# ═══════════════════════════════════════════════════════════════════
#  Recon → Scan
# ═══════════════════════════════════════════════════════════════════


def recon_asset_to_scan_target(asset: ReconAsset) -> ScanTarget:
    """Translate a Recon Asset into a Scan Target.

    The Scan context does not need the full Asset entity — it only needs
    addressing information and service hints to choose scan templates.
    """
    return ScanTarget(
        host=asset.host,
        ip=asset.ip,
        ports=asset.ports,
        services=asset.services,
        asset_id=asset.id,
    )


def recon_mission_to_scan_targets(mission: ReconMission) -> list[ScanTarget]:
    """Translate all assets in a ReconMission into ScanTargets."""
    return [recon_asset_to_scan_target(asset) for asset in mission.assets.values()]


# ═══════════════════════════════════════════════════════════════════
#  Scan → Vuln
# ═══════════════════════════════════════════════════════════════════


def scan_result_to_vuln_input(result: ScanResult) -> dict[str, Any]:
    """Translate a Scan Result into input for the Vuln context.

    The Vuln context needs CVE IDs and software information to perform
    CVE matching and exploit availability checks.
    """
    return {
        "scan_result_id": result.id,
        "name": result.name,
        "severity": result.severity,
        "matched_at": result.matched_at,
        "description": result.description,
        "cve_ids": result.cve_ids,
        "cwe_ids": result.cwe_ids,
        "reference": result.reference,
    }


def scan_task_to_vuln_inputs(task: ScanTask) -> list[dict[str, Any]]:
    """Translate all results from a ScanTask into Vuln context inputs."""
    return [scan_result_to_vuln_input(r) for r in task.results]


def recon_fingerprint_to_vuln_query(
    asset_id: str,
    fingerprint: ReconFingerprint,
) -> dict[str, Any]:
    """Translate a Recon Fingerprint into a CVE query for the Vuln context."""
    return {
        "asset_id": asset_id,
        "software": fingerprint.software,
        "version": fingerprint.version,
        "os": fingerprint.os,
        "technology_stack": list(fingerprint.technology_stack),
    }


# ═══════════════════════════════════════════════════════════════════
#  Vuln → Exploit
# ═══════════════════════════════════════════════════════════════════


def vuln_match_to_exploit_input(
    match: VulnMatch,
    target_host: str,
    target_port: int = 0,
) -> dict[str, Any]:
    """Translate a VulnMatch into input for the Exploit context.

    The Exploit context needs CVE ID, exploit module information,
    and target addressing to configure and run exploits.
    """
    result: dict[str, Any] = {
        "cve_id": match.cve.cve_id,
        "cvss": match.cve.cvss,
        "severity": match.cve.severity,
        "target_host": target_host,
        "target_port": target_port,
        "software": match.software,
        "version": match.version,
    }

    if match.exploit_availability:
        result["exploit_db_id"] = match.exploit_availability.exploit_db_id
        result["metasploit_module"] = match.exploit_availability.metasploit_module
        result["exploit_type"] = match.exploit_availability.exploit_type
        result["verified"] = match.exploit_availability.verified

    return result


def vuln_assessment_to_exploit_targets(
    assessment: VulnAssessment,
    host_map: dict[str, tuple[str, int]],  # asset_id -> (host, port)
) -> list[dict[str, Any]]:
    """Translate exploitable VulnMatches into Exploit targets.

    Only includes matches that have known public exploits, sorted by CVSS
    score (highest first) for optimal exploitation order.
    """
    targets: list[dict[str, Any]] = []
    exploitable = assessment.exploitable_matches()

    # Sort by CVSS descending — attack the most critical first
    exploitable.sort(key=lambda m: m.cve.cvss, reverse=True)

    for match in exploitable:
        host, port = host_map.get(match.asset_id, ("", 0))
        if host:
            targets.append(vuln_match_to_exploit_input(match, host, port))

    return targets


# ═══════════════════════════════════════════════════════════════════
#  Exploit → Post
# ═══════════════════════════════════════════════════════════════════


def exploit_success_to_post_session(
    attempt: ExploitAttempt,
) -> dict[str, Any]:
    """Translate a successful ExploitAttempt into Post session init data.

    The Post context needs the session ID, target host, and initial
    access level to begin post-exploitation operations.
    """
    return {
        "session_id": attempt.result.session_id,
        "target_host": attempt.target_host,
        "initial_access": attempt.result.access_gained,
        "exploit_cve": attempt.cve_id,
        "exploit_module": attempt.module,
    }


def exploit_campaign_to_post_sessions(
    campaign: ExploitCampaign,
) -> list[dict[str, Any]]:
    """Translate all successful exploits into Post session candidates.

    Returns one session init dict per successful attempt that established
    an active session.
    """
    sessions: list[dict[str, Any]] = []
    for attempt in campaign.successful_attempts():
        if attempt.result.session_id:
            sessions.append(exploit_success_to_post_session(attempt))
    return sessions


# ═══════════════════════════════════════════════════════════════════
#  Post → Recon (pivot loop)
# ═══════════════════════════════════════════════════════════════════


def pivot_target_to_recon_scope(pivot: PivotTarget) -> str:
    """Translate a PivotTarget back into a recon scope string.

    This closes the kill chain loop — discovered internal hosts become
    new recon targets for the next iteration.
    """
    return pivot.ip or pivot.host
