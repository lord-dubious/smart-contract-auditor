"""Smart Contract Auditor - AI-powered security auditing for Solidity contracts.

This package provides tools for analyzing smart contracts using Slither static analysis
combined with Gemini AI for intelligent vulnerability detection and PoC generation.
"""

from contract_auditor.models import (
    AuditConfig,
    ContractInfo,
    SlitherFinding,
    VulnerabilityReport,
    ExploitPoC,
    AuditResult,
    Severity,
    VulnerabilityType,
    create_config,
    create_vulnerability_report,
)
from contract_auditor.analyzer import SlitherAnalyzer, create_analyzer
from contract_auditor.enricher import VulnerabilityEnricher, create_enricher
from contract_auditor.poc_generator import PoCGenerator, create_poc_generator
from contract_auditor.auditor import ContractAuditor, create_auditor

__version__ = "0.1.0"

__all__ = [
    # Config
    "AuditConfig",
    "create_config",
    # Models
    "ContractInfo",
    "SlitherFinding",
    "VulnerabilityReport",
    "ExploitPoC",
    "AuditResult",
    "Severity",
    "VulnerabilityType",
    "create_vulnerability_report",
    # Analyzer
    "SlitherAnalyzer",
    "create_analyzer",
    # Enricher
    "VulnerabilityEnricher",
    "create_enricher",
    # PoC Generator
    "PoCGenerator",
    "create_poc_generator",
    # Auditor
    "ContractAuditor",
    "create_auditor",
]
