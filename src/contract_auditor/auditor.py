"""Main contract auditor orchestrating all components."""

from __future__ import annotations

import hashlib
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from contract_auditor.models import (
    AuditConfig,
    AuditResult,
    AuditStats,
    ContractInfo,
    Severity,
)
from contract_auditor.analyzer import SlitherAnalyzer, create_analyzer
from contract_auditor.enricher import VulnerabilityEnricher, create_enricher
from contract_auditor.poc_generator import PoCGenerator, create_poc_generator

logger = structlog.get_logger()


class ContractAuditor:
    """Main auditor that orchestrates the full audit pipeline."""

    def __init__(
        self,
        config: AuditConfig,
        analyzer: SlitherAnalyzer | None = None,
        enricher: VulnerabilityEnricher | None = None,
        poc_generator: PoCGenerator | None = None,
    ) -> None:
        """Initialize the contract auditor.

        Args:
            config: Audit configuration
            analyzer: Optional Slither analyzer (created if not provided)
            enricher: Optional vulnerability enricher (created if not provided)
            poc_generator: Optional PoC generator (created if not provided)
        """
        self.config = config
        self.analyzer = analyzer or create_analyzer(config)
        self.enricher = enricher or create_enricher(config)
        self.poc_generator = poc_generator or create_poc_generator(config)

        self._stats = AuditStats()

    async def audit_file(self, file_path: str) -> AuditResult:
        """Audit a single Solidity file.

        Args:
            file_path: Path to the Solidity file

        Returns:
            Complete audit result
        """
        logger.info("starting_audit", file_path=file_path)
        start_time = time.time()

        # Load contract info
        contract = self._load_contract(file_path)

        # Run the audit pipeline
        result = await self._run_audit_pipeline([contract])

        duration = time.time() - start_time
        logger.info("audit_completed", duration=duration, findings=result.total_findings)

        return AuditResult(
            audit_id=result.audit_id,
            contracts=result.contracts,
            slither_findings=result.slither_findings,
            vulnerabilities=result.vulnerabilities,
            poc_exploits=result.poc_exploits,
            total_findings=result.total_findings,
            critical_count=result.critical_count,
            high_count=result.high_count,
            medium_count=result.medium_count,
            low_count=result.low_count,
            informational_count=result.informational_count,
            started_at=result.started_at,
            completed_at=datetime.now(),
            duration_seconds=duration,
            verified_vulnerabilities=result.verified_vulnerabilities,
            successful_exploits=result.successful_exploits,
        )

    async def audit_directory(self, dir_path: str) -> AuditResult:
        """Audit all Solidity files in a directory.

        Args:
            dir_path: Path to the directory

        Returns:
            Complete audit result
        """
        logger.info("starting_directory_audit", dir_path=dir_path)
        start_time = time.time()

        # Find all Solidity files
        sol_files = list(Path(dir_path).glob("**/*.sol"))

        if len(sol_files) > self.config.max_contracts:
            logger.warning(
                "too_many_contracts",
                found=len(sol_files),
                max=self.config.max_contracts,
            )
            sol_files = sol_files[: self.config.max_contracts]

        # Load contracts
        contracts = [self._load_contract(str(f)) for f in sol_files]

        # Run audit
        result = await self._run_audit_pipeline(contracts)

        duration = time.time() - start_time

        return AuditResult(
            audit_id=result.audit_id,
            contracts=result.contracts,
            slither_findings=result.slither_findings,
            vulnerabilities=result.vulnerabilities,
            poc_exploits=result.poc_exploits,
            total_findings=result.total_findings,
            critical_count=result.critical_count,
            high_count=result.high_count,
            medium_count=result.medium_count,
            low_count=result.low_count,
            informational_count=result.informational_count,
            started_at=result.started_at,
            completed_at=datetime.now(),
            duration_seconds=duration,
            verified_vulnerabilities=result.verified_vulnerabilities,
            successful_exploits=result.successful_exploits,
        )

    async def audit_source(self, source_code: str, name: str = "Contract") -> AuditResult:
        """Audit Solidity source code directly.

        Args:
            source_code: Solidity source code
            name: Contract name

        Returns:
            Complete audit result
        """
        logger.info("starting_source_audit", name=name)
        start_time = time.time()

        contract = ContractInfo(
            name=name,
            file_path="",
            source_code=source_code,
            contract_hash=hashlib.sha256(source_code.encode()).hexdigest()[:16],
        )

        result = await self._run_audit_pipeline([contract])
        duration = time.time() - start_time

        return AuditResult(
            audit_id=result.audit_id,
            contracts=result.contracts,
            slither_findings=result.slither_findings,
            vulnerabilities=result.vulnerabilities,
            poc_exploits=result.poc_exploits,
            total_findings=result.total_findings,
            critical_count=result.critical_count,
            high_count=result.high_count,
            medium_count=result.medium_count,
            low_count=result.low_count,
            informational_count=result.informational_count,
            started_at=result.started_at,
            completed_at=datetime.now(),
            duration_seconds=duration,
            verified_vulnerabilities=result.verified_vulnerabilities,
            successful_exploits=result.successful_exploits,
        )

    async def _run_audit_pipeline(self, contracts: list[ContractInfo]) -> AuditResult:
        """Run the full audit pipeline.

        Args:
            contracts: List of contracts to audit

        Returns:
            Audit result
        """
        audit_id = hashlib.sha256(
            f"{datetime.now().isoformat()}:{len(contracts)}".encode()
        ).hexdigest()[:12]

        started_at = datetime.now()

        # Step 1: Run Slither analysis
        logger.info("running_static_analysis", contracts=len(contracts))
        all_findings = []

        for contract in contracts:
            findings = await self.analyzer.analyze_contract(contract)
            all_findings.extend(findings)

        logger.info("static_analysis_complete", findings=len(all_findings))

        # Step 2: Enrich findings with AI
        logger.info("enriching_findings", count=len(all_findings))
        vulnerabilities = await self.enricher.batch_enrich(all_findings)

        # Step 3: Generate PoCs (if enabled)
        poc_exploits = []
        if self.config.generate_poc:
            logger.info("generating_pocs", count=len(vulnerabilities))

            # Only generate PoCs for high/critical vulnerabilities
            high_severity_vulns = [
                v
                for v in vulnerabilities
                if v.finding.severity in [Severity.HIGH, Severity.CRITICAL]
            ]

            for vuln in high_severity_vulns:
                poc = await self.poc_generator.generate_and_verify(vuln)
                poc_exploits.append(poc)

        # Count severities
        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFORMATIONAL: 0,
        }

        for finding in all_findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        # Count successful exploits
        successful_exploits = sum(1 for poc in poc_exploits if poc.success)
        verified_vulnerabilities = sum(1 for poc in poc_exploits if poc.executed and poc.success)

        return AuditResult(
            audit_id=audit_id,
            contracts=list(contracts),
            slither_findings=all_findings,
            vulnerabilities=vulnerabilities,
            poc_exploits=poc_exploits,
            total_findings=len(all_findings),
            critical_count=severity_counts[Severity.CRITICAL],
            high_count=severity_counts[Severity.HIGH],
            medium_count=severity_counts[Severity.MEDIUM],
            low_count=severity_counts[Severity.LOW],
            informational_count=severity_counts[Severity.INFORMATIONAL],
            started_at=started_at,
            verified_vulnerabilities=verified_vulnerabilities,
            successful_exploits=successful_exploits,
        )

    def _load_contract(self, file_path: str) -> ContractInfo:
        """Load contract information from a file.

        Args:
            file_path: Path to Solidity file

        Returns:
            ContractInfo object
        """
        path = Path(file_path)

        source_code = ""
        if path.exists():
            source_code = path.read_text()

        return ContractInfo(
            name=path.stem,
            file_path=str(path.absolute()),
            source_code=source_code,
            contract_hash=hashlib.sha256(source_code.encode()).hexdigest()[:16]
            if source_code
            else "",
        )

    def get_stats(self) -> AuditStats:
        """Get current audit statistics.

        Returns:
            Audit statistics
        """
        return self._stats

    def generate_report(self, result: AuditResult, format: str = "markdown") -> str:
        """Generate a formatted audit report.

        Args:
            result: Audit result to format
            format: Output format (markdown, json, html)

        Returns:
            Formatted report string
        """
        if format == "json":
            return result.model_dump_json(indent=2)

        # Markdown format
        lines = [
            "# Smart Contract Security Audit Report",
            "",
            f"**Audit ID:** {result.audit_id}",
            f"**Date:** {result.started_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Duration:** {result.duration_seconds:.2f} seconds",
            "",
            "## Summary",
            "",
            f"- **Total Findings:** {result.total_findings}",
            f"- **Critical:** {result.critical_count}",
            f"- **High:** {result.high_count}",
            f"- **Medium:** {result.medium_count}",
            f"- **Low:** {result.low_count}",
            f"- **Informational:** {result.informational_count}",
            "",
            f"- **Verified Vulnerabilities:** {result.verified_vulnerabilities}",
            f"- **Successful Exploits:** {result.successful_exploits}",
            "",
            "## Contracts Audited",
            "",
        ]

        for contract in result.contracts:
            lines.append(f"- {contract.name} (`{contract.file_path}`)")

        lines.extend(["", "## Vulnerabilities", ""])

        for i, vuln in enumerate(result.vulnerabilities, 1):
            lines.extend(
                [
                    f"### {i}. {vuln.title}",
                    "",
                    f"**Severity:** {vuln.finding.severity.value.upper()}",
                    f"**Type:** {vuln.vulnerability_type.value}",
                    f"**Contract:** {vuln.finding.contract_name}",
                    f"**Function:** {vuln.finding.function_name}",
                    "",
                    "**Description:**",
                    vuln.detailed_description,
                    "",
                    "**Impact:**",
                    vuln.impact,
                    "",
                    "**Remediation:**",
                    vuln.remediation,
                    "",
                    "---",
                    "",
                ]
            )

        return "\n".join(lines)


def create_auditor(
    config: AuditConfig | None = None,
    **kwargs: Any,
) -> ContractAuditor:
    """Factory function to create ContractAuditor.

    Args:
        config: Optional audit configuration
        **kwargs: Additional configuration options

    Returns:
        Configured ContractAuditor instance
    """
    if config is None:
        config = AuditConfig(**kwargs)

    return ContractAuditor(config)
