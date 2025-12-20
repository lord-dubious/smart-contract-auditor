"""Tests for PoC generator."""

import pytest

from contract_auditor.models import (
    AuditConfig,
    SlitherFinding,
    Severity,
    VulnerabilityType,
    create_vulnerability_report,
)
from contract_auditor.poc_generator import PoCGenerator, create_poc_generator


class TestPoCGenerator:
    """Tests for PoCGenerator."""

    def test_create_poc_generator(self, mock_config):
        """Test creating PoC generator with config."""
        generator = PoCGenerator(mock_config)
        assert generator.config == mock_config

    def test_create_poc_generator_factory(self):
        """Test create_poc_generator factory function."""
        generator = create_poc_generator()
        assert generator is not None

    def test_create_poc_generator_with_config(self, mock_config):
        """Test factory with custom config."""
        generator = create_poc_generator(mock_config)
        assert generator.config.mock_mode is True


class TestPoCGeneration:
    """Tests for PoC generation."""

    async def test_generate_mock_mode(self, mock_config, sample_finding):
        """Test generating PoC in mock mode."""
        generator = PoCGenerator(mock_config)

        report = create_vulnerability_report(
            finding=sample_finding,
            vulnerability_type=VulnerabilityType.REENTRANCY,
            title="Test",
            detailed_description="Test",
            impact="Test",
            root_cause="Test",
            remediation="Test",
        )

        poc = await generator.generate(report)

        assert poc is not None
        assert poc.vulnerability_id == report.id
        assert len(poc.solidity_code) > 0

    async def test_generate_reentrancy_poc(self, mock_config, sample_finding):
        """Test generating reentrancy PoC."""
        generator = PoCGenerator(mock_config)

        report = create_vulnerability_report(
            finding=sample_finding,
            vulnerability_type=VulnerabilityType.REENTRANCY,
            title="Reentrancy",
            detailed_description="Reentrancy vulnerability",
            impact="Funds can be drained",
            root_cause="External call before state update",
            remediation="Use ReentrancyGuard",
        )

        poc = await generator.generate(report)

        assert "reentrancy" in poc.name.lower()
        assert "Attacker" in poc.solidity_code or "attacker" in poc.solidity_code.lower()
        assert len(poc.attack_steps) > 0

    async def test_generate_unchecked_call_poc(self, mock_config):
        """Test generating unchecked call PoC."""
        finding = SlitherFinding(
            detector="unchecked-transfer",
            check="unchecked-transfer",
            severity=Severity.MEDIUM,
            description="Unchecked transfer",
            function_name="transfer",
            contract_name="Token",
        )

        report = create_vulnerability_report(
            finding=finding,
            vulnerability_type=VulnerabilityType.UNCHECKED_CALL,
            title="Unchecked Call",
            detailed_description="Transfer not checked",
            impact="Silent failures",
            root_cause="Missing return check",
            remediation="Check return value",
        )

        generator = PoCGenerator(mock_config)
        poc = await generator.generate(report)

        assert poc.vulnerability_id == report.id
        assert len(poc.solidity_code) > 0

    async def test_generate_generic_poc(self, mock_config):
        """Test generating generic PoC for unknown vulnerability."""
        finding = SlitherFinding(
            detector="unknown-detector",
            check="unknown",
            severity=Severity.LOW,
            description="Unknown issue",
            function_name="func",
            contract_name="Contract",
        )

        report = create_vulnerability_report(
            finding=finding,
            vulnerability_type=VulnerabilityType.OTHER,
            title="Unknown Issue",
            detailed_description="Unknown",
            impact="Unknown",
            root_cause="Unknown",
            remediation="Review code",
        )

        generator = PoCGenerator(mock_config)
        poc = await generator.generate(report)

        assert poc is not None
        assert "TODO" in poc.solidity_code or "Placeholder" in poc.solidity_code


class TestPoCVerification:
    """Tests for PoC verification."""

    async def test_generate_and_verify_mock(self, mock_config, sample_finding):
        """Test generate and verify in mock mode."""
        generator = PoCGenerator(mock_config)

        report = create_vulnerability_report(
            finding=sample_finding,
            vulnerability_type=VulnerabilityType.REENTRANCY,
            title="Test",
            detailed_description="Test",
            impact="Test",
            root_cause="Test",
            remediation="Test",
        )

        poc = await generator.generate_and_verify(report)

        assert poc.executed is True
        assert poc.success is True
        assert poc.gas_used > 0

    async def test_batch_generate(self, mock_config, sample_findings):
        """Test batch PoC generation."""
        generator = PoCGenerator(mock_config)

        reports = [
            create_vulnerability_report(
                finding=f,
                vulnerability_type=VulnerabilityType.REENTRANCY,
                title=f"Test {i}",
                detailed_description="Test",
                impact="Test",
                root_cause="Test",
                remediation="Test",
            )
            for i, f in enumerate(sample_findings)
        ]

        pocs = await generator.batch_generate(reports)

        assert len(pocs) == len(sample_findings)


class TestFoundryTestRunner:
    """Tests for Foundry test execution."""

    def test_run_foundry_test_mock(self, mock_config):
        """Test running Foundry test in mock mode."""
        generator = PoCGenerator(mock_config)

        result = generator.run_foundry_test("/test/test.sol", "test_exploit")

        assert result.test_name == "test_exploit"
        assert result.passed is True
        assert result.gas_used > 0

    def test_run_foundry_test_logs(self, mock_config):
        """Test that mock test returns logs."""
        generator = PoCGenerator(mock_config)

        result = generator.run_foundry_test("/test.sol", "test_exploit")

        assert len(result.logs) > 0


class TestPoCContent:
    """Tests for PoC content quality."""

    async def test_poc_has_pragma(self, mock_config, sample_finding):
        """Test that PoC has Solidity pragma."""
        generator = PoCGenerator(mock_config)

        report = create_vulnerability_report(
            finding=sample_finding,
            vulnerability_type=VulnerabilityType.REENTRANCY,
            title="Test",
            detailed_description="Test",
            impact="Test",
            root_cause="Test",
            remediation="Test",
        )

        poc = await generator.generate(report)

        assert "pragma solidity" in poc.solidity_code

    async def test_poc_has_license(self, mock_config, sample_finding):
        """Test that PoC has SPDX license."""
        generator = PoCGenerator(mock_config)

        report = create_vulnerability_report(
            finding=sample_finding,
            vulnerability_type=VulnerabilityType.REENTRANCY,
            title="Test",
            detailed_description="Test",
            impact="Test",
            root_cause="Test",
            remediation="Test",
        )

        poc = await generator.generate(report)

        assert "SPDX-License-Identifier" in poc.solidity_code

    async def test_poc_imports_test(self, mock_config, sample_finding):
        """Test that PoC imports Foundry Test."""
        generator = PoCGenerator(mock_config)

        report = create_vulnerability_report(
            finding=sample_finding,
            vulnerability_type=VulnerabilityType.REENTRANCY,
            title="Test",
            detailed_description="Test",
            impact="Test",
            root_cause="Test",
            remediation="Test",
        )

        poc = await generator.generate(report)

        assert "forge-std/Test.sol" in poc.solidity_code or "Test" in poc.solidity_code

    async def test_poc_has_test_function(self, mock_config, sample_finding):
        """Test that PoC has test function."""
        generator = PoCGenerator(mock_config)

        report = create_vulnerability_report(
            finding=sample_finding,
            vulnerability_type=VulnerabilityType.REENTRANCY,
            title="Test",
            detailed_description="Test",
            impact="Test",
            root_cause="Test",
            remediation="Test",
        )

        poc = await generator.generate(report)

        assert "function test" in poc.solidity_code

    async def test_poc_attack_steps_documented(self, mock_config, sample_finding):
        """Test that attack steps are documented."""
        generator = PoCGenerator(mock_config)

        report = create_vulnerability_report(
            finding=sample_finding,
            vulnerability_type=VulnerabilityType.REENTRANCY,
            title="Test",
            detailed_description="Test",
            impact="Test",
            root_cause="Test",
            remediation="Test",
        )

        poc = await generator.generate(report)

        assert len(poc.attack_steps) >= 2


class TestJsonExtraction:
    """Tests for JSON extraction."""

    def test_extract_json_from_code_block(self, mock_config):
        """Test extracting JSON from code block."""
        generator = PoCGenerator(mock_config)

        text = """
        ```json
        {"test_name": "test_exploit", "description": "Test"}
        ```
        """

        result = generator._extract_json(text)
        assert result["test_name"] == "test_exploit"

    def test_extract_raw_json(self, mock_config):
        """Test extracting raw JSON."""
        generator = PoCGenerator(mock_config)

        text = '{"test_name": "test", "solidity_code": "// code"}'

        result = generator._extract_json(text)
        assert result["test_name"] == "test"

    def test_extract_invalid_json(self, mock_config):
        """Test handling invalid JSON."""
        generator = PoCGenerator(mock_config)

        result = generator._extract_json("not valid json")
        assert result == {}
