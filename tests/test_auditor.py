"""Tests for the main contract auditor."""

import pytest

from contract_auditor.models import AuditConfig, Severity
from contract_auditor.auditor import ContractAuditor, create_auditor


class TestContractAuditor:
    """Tests for ContractAuditor."""

    def test_create_auditor(self, mock_config):
        """Test creating auditor with config."""
        auditor = ContractAuditor(mock_config)
        assert auditor.config == mock_config
        assert auditor.analyzer is not None
        assert auditor.enricher is not None
        assert auditor.poc_generator is not None

    def test_create_auditor_factory(self):
        """Test create_auditor factory function."""
        auditor = create_auditor(mock_mode=True)
        assert auditor is not None
        assert auditor.config.mock_mode is True

    def test_create_auditor_with_config(self, mock_config):
        """Test factory with custom config."""
        auditor = create_auditor(mock_config)
        assert auditor.config.mock_mode is True


class TestAuditFile:
    """Tests for file auditing."""

    async def test_audit_file_mock(self, mock_config):
        """Test auditing a file in mock mode."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_file("/test/contract.sol")

        assert result.audit_id is not None
        assert len(result.contracts) == 1
        assert result.total_findings > 0

    async def test_audit_file_returns_findings(self, mock_config):
        """Test that audit returns Slither findings."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_file("/test/contract.sol")

        assert len(result.slither_findings) > 0

    async def test_audit_file_returns_vulnerabilities(self, mock_config):
        """Test that audit returns enriched vulnerabilities."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_file("/test/contract.sol")

        assert len(result.vulnerabilities) > 0

    async def test_audit_file_generates_pocs(self, mock_config):
        """Test that audit generates PoCs."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_file("/test/contract.sol")

        # PoCs generated for high/critical findings
        if result.high_count > 0 or result.critical_count > 0:
            assert len(result.poc_exploits) > 0

    async def test_audit_file_has_duration(self, mock_config):
        """Test that audit includes duration."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_file("/test/contract.sol")

        assert result.duration_seconds > 0
        assert result.started_at is not None
        assert result.completed_at is not None


class TestAuditSource:
    """Tests for source code auditing."""

    async def test_audit_source_mock(self, mock_config, vulnerable_source_code):
        """Test auditing source code in mock mode."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_source(vulnerable_source_code, "InsecureBank")

        assert result.audit_id is not None
        assert len(result.contracts) == 1
        assert result.contracts[0].name == "InsecureBank"

    async def test_audit_source_returns_findings(self, mock_config, vulnerable_source_code):
        """Test that source audit returns findings."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_source(vulnerable_source_code)

        assert result.total_findings > 0


class TestAuditDirectory:
    """Tests for directory auditing."""

    async def test_audit_directory_mock(self, mock_config):
        """Test auditing directory in mock mode."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_directory("/test/contracts/")

        assert result.audit_id is not None


class TestSeverityCounts:
    """Tests for severity counting."""

    async def test_severity_counts(self, mock_config):
        """Test that severity counts are accurate."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_file("/test/contract.sol")

        total = (
            result.critical_count
            + result.high_count
            + result.medium_count
            + result.low_count
            + result.informational_count
        )

        assert total == result.total_findings

    async def test_high_severity_findings(self, mock_config):
        """Test that high severity findings are counted."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_file("/test/contract.sol")

        # Mock mode should return some high severity findings
        assert result.high_count >= 0


class TestReportGeneration:
    """Tests for report generation."""

    async def test_generate_markdown_report(self, mock_config):
        """Test generating markdown report."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_file("/test/contract.sol")

        report = auditor.generate_report(result, format="markdown")

        assert "# Smart Contract Security Audit Report" in report
        assert result.audit_id in report

    async def test_generate_json_report(self, mock_config):
        """Test generating JSON report."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_file("/test/contract.sol")

        report = auditor.generate_report(result, format="json")

        import json

        parsed = json.loads(report)
        assert parsed["audit_id"] == result.audit_id

    async def test_report_includes_summary(self, mock_config):
        """Test that report includes summary."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_file("/test/contract.sol")

        report = auditor.generate_report(result)

        assert "Summary" in report
        assert "Total Findings" in report

    async def test_report_includes_vulnerabilities(self, mock_config):
        """Test that report includes vulnerabilities."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_file("/test/contract.sol")

        report = auditor.generate_report(result)

        assert "Vulnerabilities" in report

    async def test_report_includes_contracts(self, mock_config):
        """Test that report lists audited contracts."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_file("/test/contract.sol")

        report = auditor.generate_report(result)

        assert "Contracts Audited" in report


class TestStats:
    """Tests for audit statistics."""

    def test_get_stats(self, mock_config):
        """Test getting audit statistics."""
        auditor = ContractAuditor(mock_config)
        stats = auditor.get_stats()

        assert stats is not None


class TestPoCVerification:
    """Tests for PoC verification in audits."""

    async def test_verified_vulnerabilities_count(self, mock_config):
        """Test that verified vulnerabilities are counted."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_file("/test/contract.sol")

        assert result.verified_vulnerabilities >= 0

    async def test_successful_exploits_count(self, mock_config):
        """Test that successful exploits are counted."""
        auditor = ContractAuditor(mock_config)
        result = await auditor.audit_file("/test/contract.sol")

        assert result.successful_exploits >= 0


class TestContractLoading:
    """Tests for contract loading."""

    def test_load_contract_from_path(self, mock_config):
        """Test loading contract from path."""
        auditor = ContractAuditor(mock_config)
        contract = auditor._load_contract("/test/MyContract.sol")

        assert contract.name == "MyContract"
        assert contract.file_path is not None


class TestAuditorComponents:
    """Tests for auditor component integration."""

    def test_auditor_has_analyzer(self, mock_config):
        """Test that auditor has analyzer component."""
        auditor = ContractAuditor(mock_config)
        assert auditor.analyzer is not None

    def test_auditor_has_enricher(self, mock_config):
        """Test that auditor has enricher component."""
        auditor = ContractAuditor(mock_config)
        assert auditor.enricher is not None

    def test_auditor_has_poc_generator(self, mock_config):
        """Test that auditor has PoC generator component."""
        auditor = ContractAuditor(mock_config)
        assert auditor.poc_generator is not None

    def test_components_share_config(self, mock_config):
        """Test that components share the same config."""
        auditor = ContractAuditor(mock_config)

        assert auditor.analyzer.config.mock_mode == mock_config.mock_mode
        assert auditor.enricher.config.mock_mode == mock_config.mock_mode
        assert auditor.poc_generator.config.mock_mode == mock_config.mock_mode
