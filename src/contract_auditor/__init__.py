"""Smart Contract Auditor - experimental checks for Solidity contracts.

This package provides tools for analyzing smart contracts using Slither static analysis
combined with optional Gemini enrichment and Foundry PoC generation.
"""

from contract_auditor.analyzer import SlitherAnalyzer, create_analyzer
from contract_auditor.auditor import ContractAuditor, create_auditor
from contract_auditor.enricher import VulnerabilityEnricher, create_enricher
from contract_auditor.models import (
    AuditConfig,
    AuditResult,
    ContractInfo,
    ExploitPoC,
    Severity,
    SlitherFinding,
    VulnerabilityReport,
    VulnerabilityType,
    create_config,
    create_vulnerability_report,
)
from contract_auditor.poc_generator import PoCGenerator, create_poc_generator

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
