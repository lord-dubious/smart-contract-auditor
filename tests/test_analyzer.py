"""Tests for Slither analyzer."""

import pytest

from contract_auditor.models import AuditConfig, Severity
from contract_auditor.analyzer import SlitherAnalyzer, create_analyzer


class TestSlitherAnalyzer:
    """Tests for SlitherAnalyzer."""

    def test_create_analyzer(self, mock_config):
        """Test creating analyzer with config."""
        analyzer = SlitherAnalyzer(mock_config)
        assert analyzer.config == mock_config

    def test_create_analyzer_factory(self):
        """Test create_analyzer factory function."""
        analyzer = create_analyzer()
        assert analyzer is not None
        assert analyzer.config is not None

    def test_create_analyzer_with_config(self, mock_config):
        """Test factory with custom config."""
        analyzer = create_analyzer(mock_config)
        assert analyzer.config.mock_mode is True

    async def test_analyze_file_mock(self, mock_config):
        """Test analyzing file in mock mode."""
        analyzer = SlitherAnalyzer(mock_config)
        findings = await analyzer.analyze_file("/test/contract.sol")

        assert len(findings) > 0
        assert findings[0].detector == "reentrancy-eth"

    async def test_analyze_contract_mock(self, mock_config, sample_contract):
        """Test analyzing contract in mock mode."""
        analyzer = SlitherAnalyzer(mock_config)
        findings = await analyzer.analyze_contract(sample_contract)

        assert len(findings) > 0

    async def test_analyze_directory_mock(self, mock_config):
        """Test analyzing directory in mock mode."""
        analyzer = SlitherAnalyzer(mock_config)
        findings = await analyzer.analyze_directory("/test/contracts/")

        assert len(findings) > 0

    def test_set_mock_findings(self, mock_config):
        """Test setting custom mock findings."""
        analyzer = SlitherAnalyzer(mock_config)

        custom_findings = [
            {
                "detector": "custom-detector",
                "severity": "high",
                "description": "Custom finding",
                "function_name": "customFunc",
                "contract_name": "CustomContract",
            }
        ]

        analyzer.set_mock_findings(custom_findings)
        assert len(analyzer._mock_findings) == 1

    async def test_custom_mock_findings(self, mock_config):
        """Test analyzing with custom mock findings."""
        analyzer = SlitherAnalyzer(mock_config)

        analyzer.set_mock_findings(
            [
                {
                    "detector": "test-detector",
                    "severity": "medium",
                    "description": "Test vulnerability",
                    "function_name": "testFunc",
                    "contract_name": "TestContract",
                }
            ]
        )

        findings = await analyzer.analyze_file("/test.sol")

        assert len(findings) == 1
        assert findings[0].detector == "test-detector"
        assert findings[0].severity == Severity.MEDIUM

    def test_get_detector_info(self, mock_config):
        """Test getting detector information."""
        analyzer = SlitherAnalyzer(mock_config)

        info = analyzer.get_detector_info("reentrancy-eth")
        assert info["name"] == "Reentrancy ETH"
        assert "wiki" in info

    def test_get_unknown_detector_info(self, mock_config):
        """Test getting info for unknown detector."""
        analyzer = SlitherAnalyzer(mock_config)

        info = analyzer.get_detector_info("unknown-detector")
        assert info["name"] == "unknown-detector"


class TestSlitherParsing:
    """Tests for Slither output parsing."""

    def test_parse_slither_output(self, mock_config):
        """Test parsing Slither JSON output."""
        analyzer = SlitherAnalyzer(mock_config)

        output = """
        {
            "results": {
                "detectors": [
                    {
                        "check": "reentrancy-eth",
                        "impact": "High",
                        "confidence": "Medium",
                        "description": "Reentrancy in Contract.func()",
                        "elements": []
                    }
                ]
            }
        }
        """

        findings = analyzer._parse_slither_output(output)
        assert len(findings) == 1
        assert findings[0].detector == "reentrancy-eth"

    def test_parse_invalid_json(self, mock_config):
        """Test parsing invalid JSON."""
        analyzer = SlitherAnalyzer(mock_config)

        findings = analyzer._parse_slither_output("not valid json")
        assert findings == []

    def test_parse_empty_results(self, mock_config):
        """Test parsing empty results."""
        analyzer = SlitherAnalyzer(mock_config)

        output = '{"results": {"detectors": []}}'
        findings = analyzer._parse_slither_output(output)
        assert findings == []

    def test_severity_filtering(self, mock_config):
        """Test that findings are filtered by severity threshold."""
        config = AuditConfig(mock_mode=True, severity_threshold=Severity.HIGH)
        analyzer = SlitherAnalyzer(config)

        output = """
        {
            "results": {
                "detectors": [
                    {
                        "check": "low-severity",
                        "impact": "Low",
                        "description": "Low severity issue"
                    },
                    {
                        "check": "high-severity",
                        "impact": "High",
                        "description": "High severity issue"
                    }
                ]
            }
        }
        """

        findings = analyzer._parse_slither_output(output)
        # Low severity should be filtered out
        assert all(f.severity in [Severity.HIGH, Severity.CRITICAL] for f in findings)


class TestMockFindings:
    """Tests for mock findings generation."""

    async def test_default_mock_findings(self, mock_config):
        """Test default mock findings are generated."""
        analyzer = SlitherAnalyzer(mock_config)
        findings = await analyzer.analyze_file("/test.sol")

        assert len(findings) >= 3

        detectors = [f.detector for f in findings]
        assert "reentrancy-eth" in detectors
        assert "unchecked-transfer" in detectors

    async def test_mock_finding_properties(self, mock_config):
        """Test mock findings have correct properties."""
        analyzer = SlitherAnalyzer(mock_config)
        findings = await analyzer.analyze_file("/test.sol")

        reentrancy = next(f for f in findings if f.detector == "reentrancy-eth")
        assert reentrancy.severity == Severity.HIGH
        assert reentrancy.confidence == "High"
        assert reentrancy.function_name == "withdraw"
        assert reentrancy.contract_name == "Vault"
