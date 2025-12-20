"""Test fixtures for Smart Contract Auditor."""

import os
import pytest

from contract_auditor.models import (
    AuditConfig,
    ContractInfo,
    SlitherFinding,
    Severity,
    VulnerabilityType,
)


@pytest.fixture(autouse=True)
def mock_env(monkeypatch):
    """Set up mock environment for all tests."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-api-key")
    monkeypatch.setenv("AUDIT_MOCK_MODE", "true")


@pytest.fixture
def mock_config():
    """Create a mock configuration."""
    return AuditConfig(
        gemini_api_key="test-api-key",
        mock_mode=True,
        generate_poc=True,
        severity_threshold=Severity.LOW,
    )


@pytest.fixture
def sample_contract():
    """Create a sample contract for testing."""
    return ContractInfo(
        name="VulnerableVault",
        file_path="/test/contracts/VulnerableVault.sol",
        source_code="""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        
        // Vulnerable: external call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] = 0;
    }
}
""",
        compiler_version="0.8.0",
    )


@pytest.fixture
def sample_finding():
    """Create a sample Slither finding."""
    return SlitherFinding(
        detector="reentrancy-eth",
        check="reentrancy-eth",
        severity=Severity.HIGH,
        confidence="High",
        description="Reentrancy vulnerability in withdraw function",
        elements=[],
        function_name="withdraw",
        contract_name="VulnerableVault",
        source_lines=["15", "16", "17", "18"],
    )


@pytest.fixture
def sample_findings():
    """Create multiple sample findings."""
    return [
        SlitherFinding(
            detector="reentrancy-eth",
            check="reentrancy-eth",
            severity=Severity.HIGH,
            confidence="High",
            description="Reentrancy vulnerability in withdraw",
            elements=[],
            function_name="withdraw",
            contract_name="Vault",
        ),
        SlitherFinding(
            detector="unchecked-transfer",
            check="unchecked-transfer",
            severity=Severity.MEDIUM,
            confidence="High",
            description="Unchecked transfer return value",
            elements=[],
            function_name="transfer",
            contract_name="Token",
        ),
        SlitherFinding(
            detector="arbitrary-send-eth",
            check="arbitrary-send-eth",
            severity=Severity.HIGH,
            confidence="Medium",
            description="ETH sent to arbitrary destination",
            elements=[],
            function_name="sendFunds",
            contract_name="Payment",
        ),
    ]


@pytest.fixture
def vulnerable_source_code():
    """Vulnerable Solidity source code for testing."""
    return """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract InsecureBank {
    mapping(address => uint256) private balances;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    // VULNERABILITY: Reentrancy
    function withdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Insufficient balance");
        
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] = 0;  // State update after external call
    }
    
    // VULNERABILITY: tx.origin
    function transferOwnership(address newOwner) external {
        require(tx.origin == msg.sender, "Not owner");  // Unsafe tx.origin
    }
    
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}
"""
