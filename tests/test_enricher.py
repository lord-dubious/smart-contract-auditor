"""Tests for vulnerability enricher."""

from contract_auditor.enricher import (
    DETECTOR_TO_VULN_TYPE,
    VulnerabilityEnricher,
    create_enricher,
)
from contract_auditor.models import (
    AuditConfig,
    Severity,
    SlitherFinding,
    VulnerabilityType,
)


class TestVulnerabilityEnricher:
    """Tests for VulnerabilityEnricher."""

    def test_create_enricher(self, mock_config):
        """Test creating enricher with config."""
        enricher = VulnerabilityEnricher(mock_config)
        assert enricher.config == mock_config

    def test_create_enricher_factory(self):
        """Test create_enricher factory function."""
        enricher = create_enricher()
        assert enricher is not None

    def test_create_enricher_with_config(self, mock_config):
        """Test factory with custom config."""
        enricher = create_enricher(mock_config)
        assert enricher.config.mock_mode is True

    async def test_enrich_mock_mode(self, mock_config, sample_finding):
        """Test enriching in mock mode."""
        enricher = VulnerabilityEnricher(mock_config)
        report = await enricher.enrich(sample_finding)

        assert report is not None
        assert report.finding == sample_finding
        assert report.vulnerability_type == VulnerabilityType.REENTRANCY

    async def test_enrich_reentrancy(self, mock_config):
        """Test enriching reentrancy vulnerability."""
        enricher = VulnerabilityEnricher(mock_config)

        finding = SlitherFinding(
            detector="reentrancy-eth",
            check="reentrancy-eth",
            severity=Severity.HIGH,
            description="Reentrancy in withdraw",
            function_name="withdraw",
            contract_name="Vault",
        )

        report = await enricher.enrich(finding)

        assert "reentrancy" in report.title.lower()
        assert "withdraw" in report.title.lower() or "Vault" in report.title
        assert len(report.detailed_description) > 0
        assert len(report.impact) > 0
        assert len(report.remediation) > 0

    async def test_enrich_unchecked_call(self, mock_config):
        """Test enriching unchecked call vulnerability."""
        enricher = VulnerabilityEnricher(mock_config)

        finding = SlitherFinding(
            detector="unchecked-transfer",
            check="unchecked-transfer",
            severity=Severity.MEDIUM,
            description="Unchecked transfer",
            function_name="transfer",
            contract_name="Token",
        )

        report = await enricher.enrich(finding)

        assert report.vulnerability_type == VulnerabilityType.UNCHECKED_CALL
        assert "unchecked" in report.title.lower() or "transfer" in report.title.lower()

    async def test_batch_enrich(self, mock_config, sample_findings):
        """Test batch enrichment of findings."""
        enricher = VulnerabilityEnricher(mock_config)
        reports = await enricher.batch_enrich(sample_findings)

        assert len(reports) == len(sample_findings)
        assert all(r.finding in sample_findings for r in reports)

    async def test_missing_gemini_uses_explicit_fallback(self, sample_finding):
        """Test Gemini unavailability is marked as fallback, not confirmed enrichment."""
        config = AuditConfig(mock_mode=False, gemini_api_key="")
        enricher = VulnerabilityEnricher(config)

        report = await enricher.enrich(sample_finding)

        assert report.enrichment_source == "fallback"
        assert "Gemini model is not configured" in report.enrichment_error
        assert "manual" in report.remediation.lower()

    def test_classify_vulnerability(self, mock_config):
        """Test vulnerability classification."""
        enricher = VulnerabilityEnricher(mock_config)

        assert enricher.classify_vulnerability("reentrancy-eth") == VulnerabilityType.REENTRANCY
        assert (
            enricher.classify_vulnerability("unchecked-transfer")
            == VulnerabilityType.UNCHECKED_CALL
        )
        assert (
            enricher.classify_vulnerability("arbitrary-send-eth")
            == VulnerabilityType.ARBITRARY_SEND
        )
        assert enricher.classify_vulnerability("unknown") == VulnerabilityType.OTHER


class TestDetectorMapping:
    """Tests for detector to vulnerability type mapping."""

    def test_reentrancy_detectors(self):
        """Test reentrancy detector mapping."""
        reentrancy_detectors = [
            "reentrancy-eth",
            "reentrancy-no-eth",
            "reentrancy-benign",
            "reentrancy-events",
        ]
        for detector in reentrancy_detectors:
            assert DETECTOR_TO_VULN_TYPE.get(detector) == VulnerabilityType.REENTRANCY

    def test_unchecked_call_detectors(self):
        """Test unchecked call detector mapping."""
        unchecked_detectors = [
            "unchecked-transfer",
            "unchecked-lowlevel",
            "unchecked-send",
        ]
        for detector in unchecked_detectors:
            assert DETECTOR_TO_VULN_TYPE.get(detector) == VulnerabilityType.UNCHECKED_CALL

    def test_delegatecall_detectors(self):
        """Test delegatecall detector mapping."""
        assert (
            DETECTOR_TO_VULN_TYPE.get("controlled-delegatecall") == VulnerabilityType.DELEGATECALL
        )
        assert DETECTOR_TO_VULN_TYPE.get("delegatecall-loop") == VulnerabilityType.DELEGATECALL

    def test_access_control_detectors(self):
        """Test access control detector mapping."""
        assert DETECTOR_TO_VULN_TYPE.get("unprotected-upgrade") == VulnerabilityType.ACCESS_CONTROL
        assert DETECTOR_TO_VULN_TYPE.get("missing-zero-check") == VulnerabilityType.ACCESS_CONTROL


class TestEnrichmentContent:
    """Tests for enrichment content quality."""

    async def test_remediation_includes_code(self, mock_config):
        """Test that reentrancy remediation includes code example."""
        enricher = VulnerabilityEnricher(mock_config)

        finding = SlitherFinding(
            detector="reentrancy-eth",
            check="reentrancy-eth",
            severity=Severity.HIGH,
            description="Reentrancy",
            function_name="withdraw",
            contract_name="Vault",
        )

        report = await enricher.enrich(finding)

        # Should include remediation code for reentrancy
        assert len(report.remediation_code) > 0 or "ReentrancyGuard" in report.remediation

    async def test_attack_vector_present(self, mock_config):
        """Test that attack vector is provided."""
        enricher = VulnerabilityEnricher(mock_config)

        finding = SlitherFinding(
            detector="reentrancy-eth",
            check="reentrancy-eth",
            severity=Severity.HIGH,
            description="Reentrancy",
            function_name="withdraw",
            contract_name="Vault",
        )

        report = await enricher.enrich(finding)

        assert len(report.attack_vector) > 0

    async def test_exploitability_rating(self, mock_config):
        """Test that exploitability is rated."""
        enricher = VulnerabilityEnricher(mock_config)

        finding = SlitherFinding(
            detector="reentrancy-eth",
            check="reentrancy-eth",
            severity=Severity.HIGH,
            description="Reentrancy",
            function_name="withdraw",
            contract_name="Vault",
        )

        report = await enricher.enrich(finding)

        assert report.exploitability in ["Easy", "Medium", "Hard", ""]

    async def test_affected_functions_populated(self, mock_config):
        """Test that affected functions are listed."""
        enricher = VulnerabilityEnricher(mock_config)

        finding = SlitherFinding(
            detector="reentrancy-eth",
            check="reentrancy-eth",
            severity=Severity.HIGH,
            description="Reentrancy",
            function_name="withdraw",
            contract_name="Vault",
        )

        report = await enricher.enrich(finding)

        assert len(report.affected_functions) > 0
        assert "withdraw" in report.affected_functions


class TestJsonExtraction:
    """Tests for JSON extraction from AI responses."""

    def test_extract_json_from_code_block(self, mock_config):
        """Test extracting JSON from markdown code block."""
        enricher = VulnerabilityEnricher(mock_config)

        text = """
        Here is the analysis:
        ```json
        {"title": "Test", "impact": "High"}
        ```
        """

        result = enricher._extract_json(text)
        assert result["title"] == "Test"

    def test_extract_raw_json(self, mock_config):
        """Test extracting raw JSON."""
        enricher = VulnerabilityEnricher(mock_config)

        text = '{"title": "Test", "impact": "High"}'

        result = enricher._extract_json(text)
        assert result["title"] == "Test"

    def test_extract_invalid_json(self, mock_config):
        """Test handling invalid JSON."""
        enricher = VulnerabilityEnricher(mock_config)

        result = enricher._extract_json("not valid json")
        assert result == {}
