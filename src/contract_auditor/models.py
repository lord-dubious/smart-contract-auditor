"""Data models for Smart Contract Auditor."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Severity(StrEnum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class VulnerabilityType(StrEnum):
    """Common smart contract vulnerability types."""

    REENTRANCY = "reentrancy"
    INTEGER_OVERFLOW = "integer-overflow"
    INTEGER_UNDERFLOW = "integer-underflow"
    UNCHECKED_CALL = "unchecked-call"
    ACCESS_CONTROL = "access-control"
    FRONT_RUNNING = "front-running"
    TIMESTAMP_DEPENDENCE = "timestamp-dependence"
    DOS = "denial-of-service"
    FLASH_LOAN = "flash-loan"
    ORACLE_MANIPULATION = "oracle-manipulation"
    UNINITIALIZED_STORAGE = "uninitialized-storage"
    DELEGATECALL = "delegatecall"
    SELFDESTRUCT = "selfdestruct"
    TX_ORIGIN = "tx-origin"
    ARBITRARY_SEND = "arbitrary-send"
    LOCKED_ETHER = "locked-ether"
    OTHER = "other"


class AuditConfig(BaseSettings):
    """Configuration for the smart contract auditor."""

    model_config = SettingsConfigDict(
        env_prefix="AUDIT_",
        env_file=".env",
        extra="ignore",
    )

    # Gemini settings
    gemini_api_key: str = Field(default="", description="Gemini API key")
    gemini_model: str = Field(default="gemini-2.0-flash", description="Gemini model to use")

    # Slither settings
    slither_path: str = Field(default="slither", description="Path to Slither binary")
    slither_timeout: int = Field(default=300, description="Slither analysis timeout in seconds")

    # Foundry settings
    forge_path: str = Field(default="forge", description="Path to Forge binary")
    foundry_project_path: str = Field(
        default="./foundry-project", description="Foundry project path"
    )

    # Audit settings
    max_contracts: int = Field(default=10, description="Max contracts per audit")
    severity_threshold: Severity = Field(
        default=Severity.MEDIUM, description="Min severity to report"
    )
    generate_poc: bool = Field(default=True, description="Generate PoC exploits")
    mock_mode: bool = Field(default=False, description="Use mock mode for testing")


def create_config(**kwargs: Any) -> AuditConfig:
    """Factory function to create AuditConfig."""
    return AuditConfig(**kwargs)


class ContractInfo(BaseModel):
    """Information about a smart contract."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Contract name")
    file_path: str = Field(description="Path to the Solidity file")
    source_code: str = Field(default="", description="Contract source code")
    compiler_version: str = Field(default="", description="Solidity compiler version")
    contract_hash: str = Field(default="", description="Hash of the source code")

    def compute_hash(self) -> str:
        """Compute hash of the source code."""
        return hashlib.sha256(self.source_code.encode()).hexdigest()[:16]


class SlitherFinding(BaseModel):
    """A finding from Slither static analysis."""

    model_config = ConfigDict(frozen=True)

    detector: str = Field(description="Slither detector name")
    check: str = Field(description="Check type")
    severity: Severity = Field(description="Finding severity")
    confidence: str = Field(default="High", description="Confidence level")
    description: str = Field(description="Finding description")
    elements: list[dict[str, Any]] = Field(default_factory=list, description="Code elements")
    first_markdown_element: str = Field(default="", description="First markdown element")
    source_lines: list[str] = Field(default_factory=list, description="Affected source lines")
    function_name: str = Field(default="", description="Affected function")
    contract_name: str = Field(default="", description="Affected contract")


class VulnerabilityReport(BaseModel):
    """Detailed vulnerability report with enrichment metadata."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(description="Unique vulnerability ID")
    finding: SlitherFinding = Field(description="Original Slither finding")
    vulnerability_type: VulnerabilityType = Field(description="Classified vulnerability type")

    # AI-enriched fields
    title: str = Field(description="Human-readable title")
    detailed_description: str = Field(description="AI-generated detailed description")
    impact: str = Field(description="Potential impact description")
    root_cause: str = Field(description="Root cause analysis")
    affected_functions: list[str] = Field(default_factory=list, description="Affected functions")

    # Remediation
    remediation: str = Field(description="Recommended fix")
    remediation_code: str = Field(default="", description="Example fix code")

    # Risk assessment
    exploitability: str = Field(default="", description="How easy to exploit")
    attack_vector: str = Field(default="", description="Attack vector description")

    # Metadata
    created_at: datetime = Field(default_factory=datetime.now, description="Report creation time")
    verified: bool = Field(default=False, description="Whether vulnerability is verified")
    enrichment_source: str = Field(default="gemini", description="Source of enrichment content")
    enrichment_error: str = Field(default="", description="Reason enrichment fell back")


def create_vulnerability_report(
    finding: SlitherFinding,
    vulnerability_type: VulnerabilityType,
    title: str,
    detailed_description: str,
    impact: str,
    root_cause: str,
    remediation: str,
    **kwargs: Any,
) -> VulnerabilityReport:
    """Factory function to create VulnerabilityReport."""
    vuln_id = hashlib.sha256(
        f"{finding.detector}:{finding.contract_name}:{finding.function_name}".encode()
    ).hexdigest()[:12]

    return VulnerabilityReport(
        id=vuln_id,
        finding=finding,
        vulnerability_type=vulnerability_type,
        title=title,
        detailed_description=detailed_description,
        impact=impact,
        root_cause=root_cause,
        remediation=remediation,
        **kwargs,
    )


class ExploitPoC(BaseModel):
    """Proof of Concept exploit and generation metadata."""

    model_config = ConfigDict(frozen=True)

    vulnerability_id: str = Field(description="Related vulnerability ID")
    name: str = Field(description="PoC test name")
    description: str = Field(description="What this PoC demonstrates")

    # Foundry test code
    solidity_code: str = Field(description="Foundry test in Solidity")
    setup_code: str = Field(default="", description="Test setup code")

    # Execution results
    executed: bool = Field(default=False, description="Whether PoC was executed")
    success: bool = Field(default=False, description="Whether exploit succeeded")
    execution_output: str = Field(default="", description="Forge test output")
    gas_used: int = Field(default=0, description="Gas used by exploit")
    generation_source: str = Field(default="gemini", description="Source of PoC content")
    generation_error: str = Field(default="", description="Reason PoC generation fell back")

    # Attack details
    attack_steps: list[str] = Field(default_factory=list, description="Step-by-step attack")
    prerequisites: list[str] = Field(default_factory=list, description="Required conditions")


class AuditResult(BaseModel):
    """Complete audit result for a contract or set of contracts."""

    model_config = ConfigDict(frozen=True)

    audit_id: str = Field(description="Unique audit ID")
    contracts: list[ContractInfo] = Field(description="Audited contracts")

    # Findings
    slither_findings: list[SlitherFinding] = Field(
        default_factory=list, description="Raw Slither findings"
    )
    vulnerabilities: list[VulnerabilityReport] = Field(
        default_factory=list, description="Enriched reports"
    )
    poc_exploits: list[ExploitPoC] = Field(default_factory=list, description="Generated PoCs")

    # Summary
    total_findings: int = Field(default=0, description="Total findings count")
    critical_count: int = Field(default=0, description="Critical severity count")
    high_count: int = Field(default=0, description="High severity count")
    medium_count: int = Field(default=0, description="Medium severity count")
    low_count: int = Field(default=0, description="Low severity count")
    informational_count: int = Field(default=0, description="Informational count")

    # Metadata
    started_at: datetime = Field(default_factory=datetime.now, description="Audit start time")
    completed_at: datetime | None = Field(default=None, description="Audit completion time")
    duration_seconds: float = Field(default=0.0, description="Audit duration")

    # Verification
    verified_vulnerabilities: int = Field(default=0, description="Count of verified vulns")
    successful_exploits: int = Field(default=0, description="Count of successful PoCs")
    analysis_warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal tool/model failures that affected audit confidence",
    )


class FoundryTestResult(BaseModel):
    """Result from running a Foundry test."""

    model_config = ConfigDict(frozen=True)

    test_name: str = Field(description="Test function name")
    passed: bool = Field(description="Whether test passed")
    gas_used: int = Field(default=0, description="Gas consumed")
    logs: list[str] = Field(default_factory=list, description="Test logs")
    error_message: str = Field(default="", description="Error if failed")
    execution_time_ms: int = Field(default=0, description="Execution time")


class AuditStats(BaseModel):
    """Statistics from the auditing process."""

    model_config = ConfigDict(frozen=True)

    contracts_analyzed: int = Field(default=0, description="Contracts analyzed")
    slither_findings_total: int = Field(default=0, description="Total Slither findings")
    vulnerabilities_enriched: int = Field(default=0, description="Vulnerabilities enriched")
    pocs_generated: int = Field(default=0, description="PoCs generated")
    pocs_successful: int = Field(default=0, description="Successful PoCs")
    analysis_time_seconds: float = Field(default=0.0, description="Total analysis time")
    enrichment_time_seconds: float = Field(default=0.0, description="AI enrichment time")
    poc_generation_time_seconds: float = Field(default=0.0, description="PoC generation time")
