"""Vuln bounded context — domain service.

Orchestrates CVE matching, exploit availability checking, and vulnerability assessment.
"""

from __future__ import annotations

from typing import Any

from miya.shared.events import DomainEvent
from miya.shared.ports import (
    EventStorePort,
    ExploitDBPort,
    CVEDatabasePort,
)
from miya.oneday.vuln.domain import (
    VulnAssessment,
    VulnMatch,
    CVE,
    ExploitAvailability,
)


class VulnService:
    """Domain service for the vuln bounded context.

    Coordinates CVE lookup, exploit database search, and vulnerability
    assessment for fingerprinted assets.
    """

    def __init__(
        self,
        event_store: EventStorePort,
        cve_database: CVEDatabasePort | None = None,
        exploit_db: ExploitDBPort | None = None,
    ) -> None:
        self._event_store = event_store
        self._cve_db = cve_database
        self._exploit_db = exploit_db

    async def create_assessment(self) -> VulnAssessment:
        """Create a new vulnerability assessment session."""
        return VulnAssessment()

    async def match_cves_for_software(
        self,
        assessment: VulnAssessment,
        asset_id: str,
        software: str,
        version: str,
        correlation_id: str = "",
    ) -> list[VulnMatch]:
        """Search CVE databases for vulnerabilities affecting specific software."""
        matches: list[VulnMatch] = []

        if self._cve_db:
            cve_results = await self._cve_db.search(
                software=software,
                version=version,
            )

            for cve_data in cve_results:
                cve = CVE(
                    cve_id=cve_data.get("cve_id", ""),
                    cvss=cve_data.get("cvss", 0.0),
                    severity=cve_data.get("severity", "medium"),
                    description=cve_data.get("description", ""),
                    affected_software=software,
                    affected_versions=cve_data.get("affected_versions", ""),
                    references=tuple(cve_data.get("references", [])),
                    published=cve_data.get("published", ""),
                )

                # Check exploit availability
                exploit_avail = await self._check_exploit_availability(cve.cve_id)

                match = assessment.register_cve_match(
                    asset_id=asset_id,
                    software=software,
                    version=version,
                    cve=cve,
                    exploit_availability=exploit_avail,
                    matched_by="version_match",
                    correlation_id=correlation_id,
                )
                matches.append(match)

        # Persist events
        events = assessment.collect_events()
        if events:
            await self._event_store.append(events)

        return matches

    async def _check_exploit_availability(
        self,
        cve_id: str,
    ) -> ExploitAvailability | None:
        """Check if a public exploit exists for a CVE."""
        if not self._exploit_db:
            return None

        results = await self._exploit_db.search(cve_id=cve_id)
        if not results:
            return None

        # Take the first (most relevant) result
        exploit = results[0]
        return ExploitAvailability(
            cve_id=cve_id,
            exploit_db_id=exploit.get("edb_id", ""),
            metasploit_module=exploit.get("metasploit_module", ""),
            github_url=exploit.get("github_url", ""),
            exploit_type=exploit.get("type", ""),
            verified=exploit.get("verified", False),
        )

    async def assess_scan_results(
        self,
        assessment: VulnAssessment,
        scan_findings: list[dict[str, Any]],
        correlation_id: str = "",
    ) -> None:
        """Process scan findings and enrich with CVE/exploit data."""
        for finding in scan_findings:
            cve_ids = finding.get("cve_ids", [])
            for cve_id in cve_ids:
                if self._cve_db:
                    cve_data = await self._cve_db.get(cve_id)
                    if cve_data:
                        cve = CVE(
                            cve_id=cve_id,
                            cvss=cve_data.get("cvss", 0.0),
                            severity=cve_data.get("severity", "medium"),
                            description=cve_data.get("description", ""),
                            affected_software=cve_data.get("affected_software", ""),
                        )
                        exploit_avail = await self._check_exploit_availability(cve_id)

                        assessment.register_cve_match(
                            asset_id=finding.get("asset_id", ""),
                            software=cve_data.get("affected_software", ""),
                            version=cve_data.get("affected_versions", ""),
                            cve=cve,
                            exploit_availability=exploit_avail,
                            matched_by="nuclei_scan",
                            correlation_id=correlation_id,
                        )

            # Also record as a vulnerability finding
            if finding.get("cwe_ids"):
                assessment.record_vulnerability(
                    vuln_type=finding.get("name", ""),
                    cwe_id=finding["cwe_ids"][0],
                    severity=finding.get("severity", "medium"),
                    location=finding.get("matched_at", ""),
                    description=finding.get("description", ""),
                    correlation_id=correlation_id,
                )

        events = assessment.collect_events()
        if events:
            await self._event_store.append(events)

    async def load_assessment(self, assessment_id: str) -> VulnAssessment:
        """Reconstitute a VulnAssessment from the event store."""
        events = await self._event_store.load(assessment_id)
        assessment = VulnAssessment(id=assessment_id)
        for event in events:
            assessment.apply(event)
        return assessment
