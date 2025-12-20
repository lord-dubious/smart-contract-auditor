# Smart Contract Auditor

An AI-powered smart contract security auditor that combines **Slither** static analysis with **Gemini AI** for intelligent vulnerability detection and **Foundry** for Proof of Concept exploit generation.

## Features

- **Slither Integration**: Leverages Slither's comprehensive static analysis for initial vulnerability detection
- **AI-Powered Enrichment**: Uses Gemini AI to provide detailed vulnerability descriptions, impact analysis, and remediation guidance
- **PoC Generation**: Automatically generates Foundry test cases that prove vulnerabilities are exploitable
- **Vulnerability Verification**: Executes generated PoCs to verify vulnerabilities with 100% certainty
- **MITRE-style Classification**: Categorizes vulnerabilities into standardized types (Reentrancy, Access Control, etc.)
- **Comprehensive Reporting**: Generates detailed audit reports in Markdown or JSON format

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        Smart Contract Auditor Pipeline                      │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌──────────────────┐    ┌───────────────────────────┐  │
│  │   Solidity  │───▶│ Slither Analyzer │───▶│   AI Vulnerability       │  │
│  │   Contracts │    │ (Static Analysis)│    │   Enricher (Gemini)      │  │
│  └─────────────┘    └──────────────────┘    └───────────────────────────┘  │
│                              │                           │                  │
│                              ▼                           ▼                  │
│                     ┌────────────────┐         ┌─────────────────────┐     │
│                     │ Raw Findings   │         │ Enriched Reports    │     │
│                     │ (JSON)         │         │ (Impact, Remediation)│    │
│                     └────────────────┘         └─────────────────────┘     │
│                                                          │                  │
│                                                          ▼                  │
│                                                ┌─────────────────────┐     │
│                                                │ PoC Generator       │     │
│                                                │ (Gemini + Foundry)  │     │
│                                                └─────────────────────┘     │
│                                                          │                  │
│                                                          ▼                  │
│                                                ┌─────────────────────┐     │
│                                                │ Foundry Executor    │     │
│                                                │ (Verify Exploits)   │     │
│                                                └─────────────────────┘     │
│                                                          │                  │
│                                                          ▼                  │
│                                                ┌─────────────────────┐     │
│                                                │ Audit Report        │     │
│                                                │ (MD / JSON)         │     │
│                                                └─────────────────────┘     │
└────────────────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Python 3.11+
- Slither (pip install slither-analyzer)
- Foundry (forge, cast, anvil)
- Gemini API key

### Quick Start

```bash
# Clone the repository
git clone https://github.com/lord-dubious/smart-contract-auditor.git
cd smart-contract-auditor

# Create virtual environment
uv venv
source .venv/bin/activate

# Install dependencies
uv pip install -e ".[dev]"

# Set up environment
cp .env.example .env
# Edit .env with your GEMINI_API_KEY

# Run tests
pytest tests/ -v
```

### Install Slither

```bash
pip install slither-analyzer
```

### Install Foundry

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

## Usage

### CLI Commands

```bash
# Audit a single Solidity file
contract-auditor audit contracts/Vault.sol

# Audit a directory
contract-auditor audit ./contracts/

# Audit with specific severity threshold
contract-auditor audit contracts/ --severity high

# Generate JSON report
contract-auditor audit contracts/ --format json --output report.json

# Skip PoC generation
contract-auditor audit contracts/ --no-poc

# Analyze source code directly
contract-auditor analyze "contract Foo { function bar() external { } }"
```

### Python API

```python
from contract_auditor import (
    ContractAuditor,
    create_auditor,
    AuditConfig,
    Severity,
)

# Create auditor with configuration
config = AuditConfig(
    gemini_api_key="your-api-key",
    severity_threshold=Severity.MEDIUM,
    generate_poc=True,
)

auditor = create_auditor(config)

# Audit a file
result = await auditor.audit_file("contracts/Vault.sol")

# Print summary
print(f"Total findings: {result.total_findings}")
print(f"Critical: {result.critical_count}")
print(f"High: {result.high_count}")
print(f"Verified exploits: {result.successful_exploits}")

# Generate report
report = auditor.generate_report(result, format="markdown")
print(report)
```

## Vulnerability Types Detected

| Type | Description |
|------|-------------|
| Reentrancy | External calls before state updates |
| Unchecked Call | Return values not checked |
| Access Control | Missing or weak authorization |
| Integer Overflow/Underflow | Arithmetic vulnerabilities |
| Front Running | Transaction ordering exploits |
| Flash Loan | Flash loan attack vectors |
| Oracle Manipulation | Price oracle vulnerabilities |
| Delegatecall | Unsafe delegatecall usage |
| Self-destruct | Unprotected selfdestruct |
| tx.origin | Authentication using tx.origin |

## Sample Output

```
┌──────────────────────────────────────────────────────────────┐
│                       Audit Summary                          │
├──────────────────────────────────────────────────────────────┤
│ Audit ID: abc123def456                                       │
│ Duration: 5.23s                                              │
│ Contracts: 3                                                 │
│ Total Findings: 5                                            │
└──────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────┐
│        Severity Breakdown             │
├───────────────┬───────────────────────┤
│ Severity      │ Count                 │
├───────────────┼───────────────────────┤
│ Critical      │ 1                     │
│ High          │ 2                     │
│ Medium        │ 1                     │
│ Low           │ 1                     │
└───────────────┴───────────────────────┘

┌────────────────────────────────────────────────────────────────────────────┐
│                          Vulnerabilities Found                              │
├────┬──────────┬─────────────────┬──────────────────────────┬───────────────┤
│ #  │ Severity │ Type            │ Title                    │ Contract      │
├────┼──────────┼─────────────────┼──────────────────────────┼───────────────┤
│ 1  │ HIGH     │ reentrancy      │ Reentrancy in withdraw   │ Vault         │
│ 2  │ HIGH     │ arbitrary-send  │ ETH sent to arbitrary... │ Payment       │
│ 3  │ MEDIUM   │ unchecked-call  │ Unchecked transfer       │ Token         │
└────┴──────────┴─────────────────┴──────────────────────────┴───────────────┘
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `GEMINI_API_KEY` | Google Gemini API key | Required |
| `AUDIT_SLITHER_PATH` | Path to Slither binary | `slither` |
| `AUDIT_FORGE_PATH` | Path to Forge binary | `forge` |
| `AUDIT_SEVERITY_THRESHOLD` | Minimum severity to report | `medium` |
| `AUDIT_GENERATE_POC` | Generate PoC exploits | `true` |
| `AUDIT_MAX_CONTRACTS` | Max contracts per audit | `10` |

## Project Structure

```
smart-contract-auditor/
├── src/contract_auditor/
│   ├── __init__.py        # Package exports
│   ├── models.py          # Pydantic data models
│   ├── analyzer.py        # Slither wrapper
│   ├── enricher.py        # AI vulnerability enrichment
│   ├── poc_generator.py   # Foundry PoC generation
│   ├── auditor.py         # Main orchestrator
│   └── cli.py             # Typer CLI
├── tests/
│   ├── conftest.py        # Test fixtures
│   ├── test_models.py     # Model tests
│   ├── test_analyzer.py   # Analyzer tests
│   ├── test_enricher.py   # Enricher tests
│   ├── test_poc_generator.py  # PoC generator tests
│   ├── test_auditor.py    # Auditor integration tests
│   └── test_cli.py        # CLI tests
├── docker-compose.yml
├── Dockerfile
└── pyproject.toml
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=contract_auditor --cov-report=html

# Run specific test file
pytest tests/test_analyzer.py -v

# Run in mock mode (no external dependencies)
pytest tests/ -v -k "mock"
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`pytest tests/ -v`)
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Slither](https://github.com/crytic/slither) - Smart contract static analyzer
- [Foundry](https://github.com/foundry-rs/foundry) - Ethereum development toolkit
- [Google Gemini](https://ai.google.dev/) - AI language model
