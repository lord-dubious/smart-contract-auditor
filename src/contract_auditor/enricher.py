"""Gemini-backed vulnerability enrichment."""

from __future__ import annotations

import json
import re
from typing import Any

import google.generativeai as genai
import structlog

from contract_auditor.models import (
    AuditConfig,
    SlitherFinding,
    VulnerabilityReport,
    VulnerabilityType,
    create_vulnerability_report,
)

logger = structlog.get_logger()


# Mapping of Slither detectors to vulnerability types
DETECTOR_TO_VULN_TYPE: dict[str, VulnerabilityType] = {
    "reentrancy-eth": VulnerabilityType.REENTRANCY,
    "reentrancy-no-eth": VulnerabilityType.REENTRANCY,
    "reentrancy-benign": VulnerabilityType.REENTRANCY,
    "reentrancy-events": VulnerabilityType.REENTRANCY,
    "unchecked-transfer": VulnerabilityType.UNCHECKED_CALL,
    "unchecked-lowlevel": VulnerabilityType.UNCHECKED_CALL,
    "unchecked-send": VulnerabilityType.UNCHECKED_CALL,
    "arbitrary-send-eth": VulnerabilityType.ARBITRARY_SEND,
    "arbitrary-send-erc20": VulnerabilityType.ARBITRARY_SEND,
    "controlled-delegatecall": VulnerabilityType.DELEGATECALL,
    "delegatecall-loop": VulnerabilityType.DELEGATECALL,
    "suicidal": VulnerabilityType.SELFDESTRUCT,
    "tx-origin": VulnerabilityType.TX_ORIGIN,
    "locked-ether": VulnerabilityType.LOCKED_ETHER,
    "timestamp": VulnerabilityType.TIMESTAMP_DEPENDENCE,
    "weak-prng": VulnerabilityType.TIMESTAMP_DEPENDENCE,
    "uninitialized-state": VulnerabilityType.UNINITIALIZED_STORAGE,
    "uninitialized-storage": VulnerabilityType.UNINITIALIZED_STORAGE,
    "unprotected-upgrade": VulnerabilityType.ACCESS_CONTROL,
    "missing-zero-check": VulnerabilityType.ACCESS_CONTROL,
}


ENRICHMENT_PROMPT = """You are a senior smart contract security auditor. Analyze this vulnerability finding and provide a detailed security report.

## Slither Finding
- Detector: {detector}
- Severity: {severity}
- Confidence: {confidence}
- Contract: {contract_name}
- Function: {function_name}
- Description: {description}
- Affected Lines: {source_lines}

## Instructions
Provide a focused vulnerability analysis in the following JSON format:

```json
{{
    "title": "Clear, descriptive vulnerability title",
    "detailed_description": "Detailed technical explanation of the vulnerability",
    "impact": "Potential security impact and consequences",
    "root_cause": "Technical root cause of the vulnerability",
    "affected_functions": ["list", "of", "affected", "functions"],
    "remediation": "Detailed fix recommendation",
    "remediation_code": "// Example Solidity code fix",
    "exploitability": "How difficult is it to exploit (Easy/Medium/Hard)",
    "attack_vector": "Step-by-step attack scenario"
}}
```

Respond with only the JSON, no additional text.
"""


class VulnerabilityEnricher:
    """Vulnerability analysis and enrichment with explicit fallback metadata."""

    def __init__(self, config: AuditConfig) -> None:
        """Initialize the vulnerability enricher.

        Args:
            config: Audit configuration
        """
        self.config = config
        self._model: Any = None

        if not config.mock_mode and config.gemini_api_key:
            genai.configure(api_key=config.gemini_api_key)
            self._model = genai.GenerativeModel(config.gemini_model)

    async def enrich(self, finding: SlitherFinding) -> VulnerabilityReport:
        """Enrich a Slither finding with AI analysis.

        Args:
            finding: Raw Slither finding

        Returns:
            Enriched vulnerability report
        """
        if self.config.mock_mode:
            logger.info("enrichment_mock_mode_enabled", detector=finding.detector)
            return self._get_mock_report(finding)

        return await self._enrich_with_ai(finding)

    async def batch_enrich(self, findings: list[SlitherFinding]) -> list[VulnerabilityReport]:
        """Enrich multiple findings.

        Args:
            findings: List of Slither findings

        Returns:
            List of enriched reports
        """
        reports = []
        for finding in findings:
            report = await self.enrich(finding)
            reports.append(report)

        return reports

    async def _enrich_with_ai(self, finding: SlitherFinding) -> VulnerabilityReport:
        """Use Gemini to enrich a finding.

        Args:
            finding: Slither finding to enrich

        Returns:
            Enriched vulnerability report
        """
        logger.info(
            "enriching_vulnerability",
            detector=finding.detector,
            contract=finding.contract_name,
        )

        prompt = ENRICHMENT_PROMPT.format(
            detector=finding.detector,
            severity=finding.severity.value,
            confidence=finding.confidence,
            contract_name=finding.contract_name,
            function_name=finding.function_name,
            description=finding.description,
            source_lines=", ".join(finding.source_lines),
        )

        if self._model is None:
            reason = "Gemini model is not configured"
            logger.warning(
                "enrichment_model_unavailable",
                detector=finding.detector,
                contract=finding.contract_name,
                reason=reason,
            )
            return self._get_fallback_report(finding, reason)

        try:
            response = self._model.generate_content(prompt)
            analysis = self._extract_json(response.text)

            vuln_type = DETECTOR_TO_VULN_TYPE.get(finding.detector, VulnerabilityType.OTHER)

            return create_vulnerability_report(
                finding=finding,
                vulnerability_type=vuln_type,
                title=analysis.get("title", f"{finding.detector} vulnerability"),
                detailed_description=analysis.get("detailed_description", finding.description),
                impact=analysis.get("impact", "Unknown impact"),
                root_cause=analysis.get("root_cause", "Unknown root cause"),
                remediation=analysis.get("remediation", "Review and fix the code"),
                remediation_code=analysis.get("remediation_code", ""),
                affected_functions=analysis.get("affected_functions", [finding.function_name]),
                exploitability=analysis.get("exploitability", "Medium"),
                attack_vector=analysis.get("attack_vector", ""),
                enrichment_source="gemini",
            )

        except Exception as e:
            reason = f"Gemini enrichment failed: {e}"
            logger.error(
                "enrichment_error",
                detector=finding.detector,
                contract=finding.contract_name,
                error=str(e),
                exc_info=True,
            )
            return self._get_fallback_report(finding, reason)

    def _extract_json(self, text: str) -> dict[str, Any]:
        """Extract JSON from AI response.

        Args:
            text: Raw AI response text

        Returns:
            Parsed JSON dictionary
        """
        # Try to find JSON in markdown code blocks
        json_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Try to parse the whole text as JSON
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Return empty dict if no valid JSON found
        logger.warning("json_extraction_failed")
        return {}

    def _get_mock_report(self, finding: SlitherFinding) -> VulnerabilityReport:
        """Generate mock report for testing.

        Args:
            finding: Slither finding

        Returns:
            Mock vulnerability report
        """
        vuln_type = DETECTOR_TO_VULN_TYPE.get(finding.detector, VulnerabilityType.OTHER)

        mock_data = self._get_mock_analysis(finding)

        return create_vulnerability_report(
            finding=finding,
            vulnerability_type=vuln_type,
            enrichment_source="mock",
            **mock_data,
        )

    def _get_mock_analysis(self, finding: SlitherFinding) -> dict[str, Any]:
        """Get mock analysis data based on finding type.

        Args:
            finding: Slither finding

        Returns:
            Mock analysis dictionary
        """
        if "reentrancy" in finding.detector:
            return {
                "title": f"Reentrancy Vulnerability in {finding.function_name}",
                "detailed_description": (
                    f"The {finding.function_name} function in {finding.contract_name} "
                    "is vulnerable to reentrancy attacks. An external call is made before "
                    "updating the contract state, allowing an attacker to recursively call "
                    "the function and drain funds."
                ),
                "impact": (
                    "An attacker can drain all ETH from the contract by exploiting the "
                    "reentrancy vulnerability. This could result in complete loss of funds."
                ),
                "root_cause": (
                    "The contract violates the checks-effects-interactions pattern. "
                    "State variables are updated after an external call, allowing recursive calls."
                ),
                "remediation": (
                    "Apply the checks-effects-interactions pattern: update state variables "
                    "before making external calls. Additionally, use a reentrancy guard modifier."
                ),
                "remediation_code": (
                    "// Use ReentrancyGuard from OpenZeppelin\n"
                    "import '@openzeppelin/contracts/security/ReentrancyGuard.sol';\n\n"
                    "function withdraw() external nonReentrant {\n"
                    "    uint256 amount = balances[msg.sender];\n"
                    "    balances[msg.sender] = 0;  // Update state first\n"
                    "    (bool success, ) = msg.sender.call{value: amount}('');\n"
                    "    require(success, 'Transfer failed');\n"
                    "}"
                ),
                "affected_functions": [finding.function_name],
                "exploitability": "Easy",
                "attack_vector": (
                    "1. Deploy malicious contract with fallback function\n"
                    "2. Deposit funds into vulnerable contract\n"
                    "3. Call withdraw function\n"
                    "4. In fallback, recursively call withdraw\n"
                    "5. Drain all funds before balance update"
                ),
            }

        elif "unchecked" in finding.detector:
            return {
                "title": f"Unchecked Return Value in {finding.function_name}",
                "detailed_description": (
                    f"The {finding.function_name} function does not check the return value "
                    "of an external call. This could lead to silent failures where the "
                    "contract assumes success when the call actually failed."
                ),
                "impact": (
                    "Failed transfers may go unnoticed, leading to accounting discrepancies "
                    "and potential loss of funds."
                ),
                "root_cause": "Missing return value check on external call.",
                "remediation": (
                    "Always check the return value of external calls and handle failures appropriately."
                ),
                "remediation_code": (
                    "// Check return value\n"
                    "bool success = token.transfer(to, amount);\n"
                    "require(success, 'Transfer failed');\n\n"
                    "// Or use SafeERC20\n"
                    "import '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';\n"
                    "using SafeERC20 for IERC20;\n"
                    "token.safeTransfer(to, amount);"
                ),
                "affected_functions": [finding.function_name],
                "exploitability": "Medium",
                "attack_vector": (
                    "1. Identify contracts that don't check return values\n"
                    "2. Cause transfer to fail (e.g., token blacklist)\n"
                    "3. Contract state updates but funds don't move"
                ),
            }

        else:
            return {
                "title": f"{finding.detector} in {finding.function_name}",
                "detailed_description": finding.description,
                "impact": "Potential security vulnerability that should be reviewed.",
                "root_cause": "See Slither detector documentation for details.",
                "remediation": "Review and apply appropriate security measures.",
                "remediation_code": "",
                "affected_functions": [finding.function_name] if finding.function_name else [],
                "exploitability": "Medium",
                "attack_vector": "",
            }

    def _get_fallback_report(
        self, finding: SlitherFinding, reason: str = "Gemini enrichment failed"
    ) -> VulnerabilityReport:
        """Generate fallback report when AI fails.

        Args:
            finding: Slither finding

        Returns:
            Basic vulnerability report
        """
        vuln_type = DETECTOR_TO_VULN_TYPE.get(finding.detector, VulnerabilityType.OTHER)

        return create_vulnerability_report(
            finding=finding,
            vulnerability_type=vuln_type,
            title=f"{finding.detector} vulnerability in {finding.contract_name}",
            detailed_description=finding.description,
            impact="Potential security vulnerability. Manual review recommended.",
            root_cause="Gemini enrichment was unavailable; see Slither documentation.",
            remediation="Review the Slither finding manually before treating this as confirmed.",
            enrichment_source="fallback",
            enrichment_error=reason,
        )

    def classify_vulnerability(self, detector: str) -> VulnerabilityType:
        """Classify a vulnerability based on detector name.

        Args:
            detector: Slither detector name

        Returns:
            Classified vulnerability type
        """
        return DETECTOR_TO_VULN_TYPE.get(detector, VulnerabilityType.OTHER)


def create_enricher(config: AuditConfig | None = None) -> VulnerabilityEnricher:
    """Factory function to create VulnerabilityEnricher.

    Args:
        config: Optional audit configuration

    Returns:
        Configured VulnerabilityEnricher instance
    """
    if config is None:
        config = AuditConfig()

    return VulnerabilityEnricher(config)
