"""Tests for data models."""

import pytest
from datetime import datetime

from contract_auditor.models import (
    AuditConfig,
    ContractInfo,
    SlitherFinding,
    VulnerabilityReport,
    ExploitPoC,
    AuditResult,
    Severity,
    VulnerabilityType,
    FoundryTestResult,
    AuditStats,
    create_config,
    create_vulnerability_report,
)


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Test all severity values exist."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFORMATIONAL.value == "informational"

    def test_severity_from_string(self):
        """Test creating severity from string."""
        assert Severity("high") == Severity.HIGH
        assert Severity("critical") == Severity.CRITICAL


class TestVulnerabilityType:
    """Tests for VulnerabilityType enum."""

    def test_vulnerability_types_exist(self):
        """Test common vulnerability types exist."""
        assert VulnerabilityType.REENTRANCY.value == "reentrancy"
        assert VulnerabilityType.INTEGER_OVERFLOW.value == "integer-overflow"
        assert VulnerabilityType.UNCHECKED_CALL.value == "unchecked-call"
        assert VulnerabilityType.ACCESS_CONTROL.value == "access-control"

    def test_all_vulnerability_types(self):
        """Test all vulnerability types are defined."""
        types = [
            VulnerabilityType.REENTRANCY,
            VulnerabilityType.INTEGER_OVERFLOW,
            VulnerabilityType.INTEGER_UNDERFLOW,
            VulnerabilityType.UNCHECKED_CALL,
            VulnerabilityType.ACCESS_CONTROL,
            VulnerabilityType.FRONT_RUNNING,
            VulnerabilityType.TIMESTAMP_DEPENDENCE,
            VulnerabilityType.DOS,
            VulnerabilityType.FLASH_LOAN,
            VulnerabilityType.ORACLE_MANIPULATION,
            VulnerabilityType.UNINITIALIZED_STORAGE,
            VulnerabilityType.DELEGATECALL,
            VulnerabilityType.SELFDESTRUCT,
            VulnerabilityType.TX_ORIGIN,
            VulnerabilityType.ARBITRARY_SEND,
            VulnerabilityType.LOCKED_ETHER,
            VulnerabilityType.OTHER,
        ]
        assert len(types) == 17


class TestAuditConfig:
    """Tests for AuditConfig."""

    def test_default_config(self, mock_config):
        """Test default configuration values."""
        config = AuditConfig(mock_mode=True)
        assert config.mock_mode is True
        assert config.generate_poc is True
        assert config.severity_threshold == Severity.MEDIUM

    def test_config_with_values(self):
        """Test configuration with custom values."""
        config = AuditConfig(
            gemini_api_key="test-key",
            slither_path="/usr/bin/slither",
            severity_threshold=Severity.HIGH,
            mock_mode=True,
        )
        assert config.gemini_api_key == "test-key"
        assert config.slither_path == "/usr/bin/slither"
        assert config.severity_threshold == Severity.HIGH

    def test_create_config_factory(self):
        """Test create_config factory function."""
        config = create_config(mock_mode=True, max_contracts=5)
        assert config.mock_mode is True
        assert config.max_contracts == 5


class TestContractInfo:
    """Tests for ContractInfo model."""

    def test_contract_info_creation(self, sample_contract):
        """Test creating contract info."""
        assert sample_contract.name == "VulnerableVault"
        assert "withdraw" in sample_contract.source_code

    def test_contract_hash_computation(self):
        """Test computing contract hash."""
        contract = ContractInfo(
            name="Test",
            file_path="/test.sol",
            source_code="contract Test {}",
        )
        hash_val = contract.compute_hash()
        assert len(hash_val) == 16

    def test_contract_info_immutable(self, sample_contract):
        """Test that ContractInfo is immutable."""
        with pytest.raises(Exception):
            sample_contract.name = "NewName"


class TestSlitherFinding:
    """Tests for SlitherFinding model."""

    def test_slither_finding_creation(self, sample_finding):
        """Test creating a Slither finding."""
        assert sample_finding.detector == "reentrancy-eth"
        assert sample_finding.severity == Severity.HIGH
        assert sample_finding.function_name == "withdraw"

    def test_slither_finding_defaults(self):
        """Test Slither finding default values."""
        finding = SlitherFinding(
            detector="test",
            check="test",
            severity=Severity.LOW,
            description="Test finding",
        )
        assert finding.confidence == "High"
        assert finding.elements == []
        assert finding.source_lines == []

    def test_slither_finding_with_elements(self):
        """Test finding with code elements."""
        finding = SlitherFinding(
            detector="reentrancy-eth",
            check="reentrancy-eth",
            severity=Severity.HIGH,
            description="Reentrancy",
            elements=[{"type": "function", "name": "withdraw"}],
            source_lines=["10", "11", "12"],
        )
        assert len(finding.elements) == 1
        assert len(finding.source_lines) == 3


class TestVulnerabilityReport:
    """Tests for VulnerabilityReport model."""

    def test_vulnerability_report_creation(self, sample_finding):
        """Test creating vulnerability report."""
        report = create_vulnerability_report(
            finding=sample_finding,
            vulnerability_type=VulnerabilityType.REENTRANCY,
            title="Reentrancy in withdraw",
            detailed_description="Detailed description",
            impact="Funds can be drained",
            root_cause="External call before state update",
            remediation="Use ReentrancyGuard",
        )
        assert report.id is not None
        assert report.vulnerability_type == VulnerabilityType.REENTRANCY
        assert report.title == "Reentrancy in withdraw"

    def test_vulnerability_report_with_remediation_code(self, sample_finding):
        """Test report with remediation code."""
        report = create_vulnerability_report(
            finding=sample_finding,
            vulnerability_type=VulnerabilityType.REENTRANCY,
            title="Test",
            detailed_description="Test",
            impact="Test",
            root_cause="Test",
            remediation="Test",
            remediation_code="// Fix code here",
        )
        assert report.remediation_code == "// Fix code here"

    def test_vulnerability_report_timestamp(self, sample_finding):
        """Test report has creation timestamp."""
        report = create_vulnerability_report(
            finding=sample_finding,
            vulnerability_type=VulnerabilityType.REENTRANCY,
            title="Test",
            detailed_description="Test",
            impact="Test",
            root_cause="Test",
            remediation="Test",
        )
        assert report.created_at is not None
        assert isinstance(report.created_at, datetime)


class TestExploitPoC:
    """Tests for ExploitPoC model."""

    def test_exploit_poc_creation(self):
        """Test creating PoC exploit."""
        poc = ExploitPoC(
            vulnerability_id="abc123",
            name="test_exploitReentrancy",
            description="Demonstrates reentrancy attack",
            solidity_code="// Solidity code",
        )
        assert poc.vulnerability_id == "abc123"
        assert poc.name == "test_exploitReentrancy"
        assert poc.executed is False
        assert poc.success is False

    def test_exploit_poc_with_results(self):
        """Test PoC with execution results."""
        poc = ExploitPoC(
            vulnerability_id="abc123",
            name="test_exploit",
            description="Test",
            solidity_code="// Code",
            executed=True,
            success=True,
            execution_output="[PASS] test_exploit",
            gas_used=150000,
        )
        assert poc.executed is True
        assert poc.success is True
        assert poc.gas_used == 150000

    def test_exploit_poc_attack_steps(self):
        """Test PoC with attack steps."""
        poc = ExploitPoC(
            vulnerability_id="abc123",
            name="test",
            description="Test",
            solidity_code="// Code",
            attack_steps=["Step 1", "Step 2", "Step 3"],
            prerequisites=["Has funds"],
        )
        assert len(poc.attack_steps) == 3
        assert len(poc.prerequisites) == 1


class TestAuditResult:
    """Tests for AuditResult model."""

    def test_audit_result_creation(self, sample_contract):
        """Test creating audit result."""
        result = AuditResult(
            audit_id="test123",
            contracts=[sample_contract],
            total_findings=5,
            critical_count=1,
            high_count=2,
            medium_count=1,
            low_count=1,
        )
        assert result.audit_id == "test123"
        assert len(result.contracts) == 1
        assert result.total_findings == 5

    def test_audit_result_defaults(self, sample_contract):
        """Test audit result default values."""
        result = AuditResult(
            audit_id="test",
            contracts=[sample_contract],
        )
        assert result.slither_findings == []
        assert result.vulnerabilities == []
        assert result.poc_exploits == []
        assert result.total_findings == 0

    def test_audit_result_with_duration(self, sample_contract):
        """Test audit result with timing info."""
        result = AuditResult(
            audit_id="test",
            contracts=[sample_contract],
            started_at=datetime.now(),
            completed_at=datetime.now(),
            duration_seconds=5.5,
        )
        assert result.duration_seconds == 5.5


class TestFoundryTestResult:
    """Tests for FoundryTestResult model."""

    def test_foundry_result_passed(self):
        """Test passed Foundry test result."""
        result = FoundryTestResult(
            test_name="test_exploit",
            passed=True,
            gas_used=100000,
            logs=["Exploit successful"],
        )
        assert result.passed is True
        assert result.gas_used == 100000

    def test_foundry_result_failed(self):
        """Test failed Foundry test result."""
        result = FoundryTestResult(
            test_name="test_exploit",
            passed=False,
            error_message="Assertion failed",
        )
        assert result.passed is False
        assert result.error_message == "Assertion failed"


class TestAuditStats:
    """Tests for AuditStats model."""

    def test_audit_stats_creation(self):
        """Test creating audit stats."""
        stats = AuditStats(
            contracts_analyzed=10,
            slither_findings_total=25,
            vulnerabilities_enriched=20,
            pocs_generated=5,
            pocs_successful=3,
        )
        assert stats.contracts_analyzed == 10
        assert stats.pocs_successful == 3

    def test_audit_stats_defaults(self):
        """Test audit stats defaults."""
        stats = AuditStats()
        assert stats.contracts_analyzed == 0
        assert stats.analysis_time_seconds == 0.0
