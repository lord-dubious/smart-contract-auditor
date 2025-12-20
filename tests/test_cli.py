"""Tests for CLI interface."""

import pytest
from typer.testing import CliRunner

from contract_auditor.cli import app


runner = CliRunner()


class TestCLI:
    """Tests for CLI commands."""

    def test_version_command(self):
        """Test version command."""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "Smart Contract Auditor" in result.stdout

    def test_audit_command_missing_target(self):
        """Test audit command with missing target."""
        result = runner.invoke(app, ["audit"])
        assert result.exit_code != 0

    def test_audit_command_nonexistent_file(self):
        """Test audit command with nonexistent file."""
        result = runner.invoke(app, ["audit", "/nonexistent/file.sol"])
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

    def test_audit_invalid_severity(self):
        """Test audit with invalid severity."""
        result = runner.invoke(app, ["audit", ".", "--severity", "invalid"])
        assert result.exit_code == 1
        assert (
            "invalid severity" in result.stdout.lower() or "valid options" in result.stdout.lower()
        )


class TestAuditOptions:
    """Tests for audit command options."""

    def test_severity_option(self):
        """Test severity option parsing."""
        # This would need a real file to test fully
        # Just verify the help includes severity option
        result = runner.invoke(app, ["audit", "--help"])
        assert "--severity" in result.stdout

    def test_format_option(self):
        """Test format option parsing."""
        result = runner.invoke(app, ["audit", "--help"])
        assert "--format" in result.stdout

    def test_poc_option(self):
        """Test PoC generation option."""
        result = runner.invoke(app, ["audit", "--help"])
        assert "--poc" in result.stdout or "poc" in result.stdout.lower()

    def test_mock_option(self):
        """Test mock mode option."""
        result = runner.invoke(app, ["audit", "--help"])
        assert "--mock" in result.stdout

    def test_output_option(self):
        """Test output file option."""
        result = runner.invoke(app, ["audit", "--help"])
        assert "--output" in result.stdout


class TestAnalyzeCommand:
    """Tests for analyze command."""

    def test_analyze_help(self):
        """Test analyze command help."""
        result = runner.invoke(app, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "source" in result.stdout.lower()

    def test_analyze_missing_source(self):
        """Test analyze without source."""
        result = runner.invoke(app, ["analyze"])
        assert result.exit_code != 0


class TestHelpOutput:
    """Tests for help output."""

    def test_main_help(self):
        """Test main help output."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "AI-powered" in result.stdout or "smart contract" in result.stdout.lower()

    def test_audit_help(self):
        """Test audit command help."""
        result = runner.invoke(app, ["audit", "--help"])
        assert result.exit_code == 0
        assert "Audit" in result.stdout

    def test_analyze_help(self):
        """Test analyze command help."""
        result = runner.invoke(app, ["analyze", "--help"])
        assert result.exit_code == 0
