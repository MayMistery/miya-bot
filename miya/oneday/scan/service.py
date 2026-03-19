"""Scan bounded context — domain service.

Orchestrates vulnerability scanning using Nuclei and other scanning tools.
"""

from __future__ import annotations

from miya.shared.ports import EventStorePort, VulnScannerPort
from miya.oneday.scan.domain import ScanTask, ScanTarget, ScanResult


class ScanService:
    """Domain service for the scan bounded context.

    Coordinates vulnerability scanning against targets discovered by recon.
    """

    def __init__(
        self,
        event_store: EventStorePort,
        vuln_scanner: VulnScannerPort | None = None,
    ) -> None:
        self._event_store = event_store
        self._scanner = vuln_scanner

    async def create_scan(
        self,
        targets: list[ScanTarget],
        templates: list[str] | None = None,
        severity_filter: str = "",
        scanner: str = "nuclei",
    ) -> ScanTask:
        """Create a new scan task for the given targets."""
        task = ScanTask(
            scanner=scanner,
            templates=templates or [],
            severity_filter=severity_filter,
        )
        for target in targets:
            task.add_target(target)
        return task

    async def execute_scan(
        self,
        task: ScanTask,
        correlation_id: str = "",
    ) -> list[ScanResult]:
        """Execute the scan task against all targets."""
        task.start()
        results: list[ScanResult] = []

        if self._scanner:
            for target in task.targets:
                scan_target = target.ip or target.host
                if target.ports:
                    # Scan specific ports
                    for port in target.ports:
                        url = f"{scan_target}:{port}"
                        findings = await self._scanner.scan(
                            target=url,
                            templates=task.templates or None,
                            severity=task.severity_filter,
                        )
                        for finding in findings:
                            result = task.record_result(
                                template_id=finding.get("template_id", ""),
                                name=finding.get("name", "Unknown"),
                                severity=finding.get("severity", "info"),
                                matched_at=finding.get("matched_at", url),
                                description=finding.get("description", ""),
                                cve_ids=finding.get("cve_ids", []),
                                cwe_ids=finding.get("cwe_ids", []),
                                reference=finding.get("reference", []),
                                raw_output=finding.get("raw", ""),
                                correlation_id=correlation_id,
                            )
                            results.append(result)
                else:
                    findings = await self._scanner.scan(
                        target=scan_target,
                        templates=task.templates or None,
                        severity=task.severity_filter,
                    )
                    for finding in findings:
                        result = task.record_result(
                            template_id=finding.get("template_id", ""),
                            name=finding.get("name", "Unknown"),
                            severity=finding.get("severity", "info"),
                            matched_at=finding.get("matched_at", scan_target),
                            description=finding.get("description", ""),
                            cve_ids=finding.get("cve_ids", []),
                            cwe_ids=finding.get("cwe_ids", []),
                            reference=finding.get("reference", []),
                            raw_output=finding.get("raw", ""),
                            correlation_id=correlation_id,
                        )
                        results.append(result)

        task.complete(correlation_id=correlation_id)

        # Persist events
        events = task.collect_events()
        if events:
            await self._event_store.append(events)

        return results

    async def load_task(self, task_id: str) -> ScanTask:
        """Reconstitute a ScanTask from the event store."""
        events = await self._event_store.load(task_id)
        task = ScanTask(id=task_id)
        for event in events:
            task.apply(event)
        return task
