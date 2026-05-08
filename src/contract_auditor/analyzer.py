"""Slither static analyzer wrapper for smart contract analysis."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import structlog

from contract_auditor.models import (
    AuditConfig,
    ContractInfo,
    Severity,
    SlitherFinding,
)

logger = structlog.get_logger()


# Mapping of Slither severity to our severity enum
SEVERITY_MAP = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFORMATIONAL,
    "Optimization": Severity.INFORMATIONAL,
}


class SlitherAnalyzer:
    """Wrapper for Slither static analysis tool."""

    def __init__(self, config: AuditConfig) -> None:
        """Initialize the Slither analyzer.

        Args:
            config: Audit configuration
        """
        self.config = config
        self._mock_findings: list[dict[str, Any]] = []
        self.last_run_error = ""

    def set_mock_findings(self, findings: list[dict[str, Any]]) -> None:
        """Set mock findings for testing.

        Args:
            findings: List of mock finding dictionaries
        """
        self._mock_findings = findings

    async def analyze_file(self, file_path: str) -> list[SlitherFinding]:
        """Analyze a Solidity file with Slither.

        Args:
            file_path: Path to the Solidity file

        Returns:
            List of Slither findings
        """
        if self.config.mock_mode:
            logger.info("slither_mock_mode_enabled", target=file_path)
            return self._get_mock_findings(file_path)

        return await self._run_slither(file_path)

    async def analyze_contract(self, contract: ContractInfo) -> list[SlitherFinding]:
        """Analyze a contract with Slither.

        Args:
            contract: Contract information

        Returns:
            List of Slither findings
        """
        if self.config.mock_mode:
            logger.info("slither_mock_mode_enabled", target=contract.file_path)
            return self._get_mock_findings(contract.file_path)

        # If we have source code but no file, write to temp file
        if contract.source_code and not Path(contract.file_path).exists():
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
                f.write(contract.source_code)
                temp_path = f.name

            try:
                return await self._run_slither(temp_path)
            finally:
                Path(temp_path).unlink(missing_ok=True)

        return await self._run_slither(contract.file_path)

    async def analyze_directory(self, dir_path: str) -> list[SlitherFinding]:
        """Analyze all Solidity files in a directory.

        Args:
            dir_path: Path to directory containing Solidity files

        Returns:
            List of all Slither findings
        """
        if self.config.mock_mode:
            logger.info("slither_mock_mode_enabled", target=dir_path)
            return self._get_mock_findings(dir_path)

        return await self._run_slither(dir_path)

    async def _run_slither(self, target: str) -> list[SlitherFinding]:
        """Run Slither on a target.

        Args:
            target: File or directory path

        Returns:
            List of parsed Slither findings
        """
        logger.info("running_slither", target=target)
        self.last_run_error = ""

        try:
            result = subprocess.run(
                [
                    self.config.slither_path,
                    target,
                    "--json",
                    "-",
                ],
                capture_output=True,
                text=True,
                timeout=self.config.slither_timeout,
            )

            # Slither returns non-zero even on success if findings exist
            output = result.stdout or result.stderr

            if not output:
                self.last_run_error = "Slither produced no JSON output"
                logger.warning(
                    "slither_no_output",
                    target=target,
                    returncode=result.returncode,
                )
                return []

            findings = self._parse_slither_output(output)
            if self.last_run_error:
                logger.warning(
                    "slither_parse_failed",
                    target=target,
                    returncode=result.returncode,
                    error=self.last_run_error,
                )
            return findings

        except subprocess.TimeoutExpired as e:
            self.last_run_error = f"Slither timed out after {self.config.slither_timeout}s"
            logger.error(
                "slither_timeout",
                target=target,
                timeout=self.config.slither_timeout,
                error=str(e),
            )
            return []
        except FileNotFoundError:
            self.last_run_error = f"Slither binary not found: {self.config.slither_path}"
            logger.error("slither_not_found", target=target, path=self.config.slither_path)
            return []
        except Exception as e:
            self.last_run_error = f"Slither execution failed: {e}"
            logger.error("slither_error", target=target, error=str(e), exc_info=True)
            return []

    def _parse_slither_output(self, output: str) -> list[SlitherFinding]:
        """Parse Slither JSON output.

        Args:
            output: Raw Slither JSON output

        Returns:
            List of SlitherFinding objects
        """
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            self.last_run_error = "Slither output was not valid JSON"
            logger.error("slither_json_parse_error", output_preview=output[:500])
            return []

        findings: list[SlitherFinding] = []

        detectors = data.get("results", {}).get("detectors", [])

        for detector in detectors:
            finding = self._parse_detector(detector)
            if finding:
                findings.append(finding)

        logger.info("slither_findings_parsed", count=len(findings))
        return findings

    def _parse_detector(self, detector: dict[str, Any]) -> SlitherFinding | None:
        """Parse a single Slither detector result.

        Args:
            detector: Detector dictionary from Slither

        Returns:
            SlitherFinding or None
        """
        try:
            # Extract severity
            impact = detector.get("impact", "Medium")
            severity = SEVERITY_MAP.get(impact, Severity.MEDIUM)

            # Filter by severity threshold
            severity_order = [
                Severity.INFORMATIONAL,
                Severity.LOW,
                Severity.MEDIUM,
                Severity.HIGH,
                Severity.CRITICAL,
            ]
            if severity_order.index(severity) < severity_order.index(
                self.config.severity_threshold
            ):
                return None

            # Extract source lines and function info
            elements = detector.get("elements", [])
            source_lines = []
            function_name = ""
            contract_name = ""

            for elem in elements:
                if "source_mapping" in elem:
                    lines = elem["source_mapping"].get("lines", [])
                    source_lines.extend([str(line) for line in lines])

                if elem.get("type") == "function":
                    function_name = elem.get("name", "")

                if elem.get("type") == "contract":
                    contract_name = elem.get("name", "")

            return SlitherFinding(
                detector=detector.get("check", "unknown"),
                check=detector.get("check", "unknown"),
                severity=severity,
                confidence=detector.get("confidence", "Medium"),
                description=detector.get("description", ""),
                elements=elements,
                first_markdown_element=detector.get("first_markdown_element", ""),
                source_lines=source_lines[:10],  # Limit lines
                function_name=function_name,
                contract_name=contract_name,
            )
        except Exception as e:
            logger.error("parse_detector_error", error=str(e))
            return None

    def _get_mock_findings(self, target: str) -> list[SlitherFinding]:
        """Get mock findings for testing.

        Args:
            target: Target path (ignored in mock mode)

        Returns:
            List of mock findings
        """
        if self._mock_findings:
            return [
                SlitherFinding(
                    detector=f.get("detector", "reentrancy-eth"),
                    check=f.get("check", "reentrancy-eth"),
                    severity=Severity(f.get("severity", "high")),
                    confidence=f.get("confidence", "High"),
                    description=f.get("description", "Mock reentrancy vulnerability"),
                    elements=f.get("elements", []),
                    function_name=f.get("function_name", "withdraw"),
                    contract_name=f.get("contract_name", "Vault"),
                )
                for f in self._mock_findings
            ]

        # Default mock findings
        return [
            SlitherFinding(
                detector="reentrancy-eth",
                check="reentrancy-eth",
                severity=Severity.HIGH,
                confidence="High",
                description="Reentrancy vulnerability detected in withdraw function. "
                "External call is made before state update.",
                elements=[],
                function_name="withdraw",
                contract_name="Vault",
                source_lines=["45", "46", "47", "48"],
            ),
            SlitherFinding(
                detector="unchecked-transfer",
                check="unchecked-transfer",
                severity=Severity.MEDIUM,
                confidence="High",
                description="Return value of transfer not checked.",
                elements=[],
                function_name="transferTokens",
                contract_name="TokenVault",
                source_lines=["62"],
            ),
            SlitherFinding(
                detector="arbitrary-send-eth",
                check="arbitrary-send-eth",
                severity=Severity.HIGH,
                confidence="Medium",
                description="Contract sends ETH to arbitrary user.",
                elements=[],
                function_name="sendEther",
                contract_name="Payment",
                source_lines=["89", "90"],
            ),
        ]

    def get_detector_info(self, detector_name: str) -> dict[str, Any]:
        """Get information about a Slither detector.

        Args:
            detector_name: Name of the detector

        Returns:
            Detector information dictionary
        """
        # Common detector information
        detectors = {
            "reentrancy-eth": {
                "name": "Reentrancy ETH",
                "wiki": "https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities",
                "impact": "High",
                "confidence": "Medium",
            },
            "unchecked-transfer": {
                "name": "Unchecked Transfer",
                "wiki": "https://github.com/crytic/slither/wiki/Detector-Documentation#unchecked-transfer",
                "impact": "Medium",
                "confidence": "High",
            },
            "arbitrary-send-eth": {
                "name": "Arbitrary Send ETH",
                "wiki": "https://github.com/crytic/slither/wiki/Detector-Documentation#arbitrary-send-eth",
                "impact": "High",
                "confidence": "Medium",
            },
        }

        return detectors.get(
            detector_name, {"name": detector_name, "wiki": "", "impact": "Unknown"}
        )


def create_analyzer(config: AuditConfig | None = None) -> SlitherAnalyzer:
    """Factory function to create SlitherAnalyzer.

    Args:
        config: Optional audit configuration

    Returns:
        Configured SlitherAnalyzer instance
    """
    if config is None:
        config = AuditConfig()

    return SlitherAnalyzer(config)
