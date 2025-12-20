"""CLI interface for Smart Contract Auditor."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from contract_auditor.models import AuditConfig, Severity
from contract_auditor.auditor import ContractAuditor, create_auditor

app = typer.Typer(
    name="contract-auditor",
    help="AI-powered smart contract security auditor",
    add_completion=False,
)
console = Console()


@app.command()
def audit(
    target: str = typer.Argument(..., help="File or directory to audit"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: str = typer.Option("markdown", "--format", "-f", help="Output format (markdown, json)"),
    severity: str = typer.Option("medium", "--severity", "-s", help="Minimum severity to report"),
    generate_poc: bool = typer.Option(True, "--poc/--no-poc", help="Generate PoC exploits"),
    mock: bool = typer.Option(False, "--mock", help="Use mock mode for testing"),
) -> None:
    """Audit a smart contract or directory of contracts."""

    # Validate target
    target_path = Path(target)
    if not target_path.exists():
        console.print(f"[red]Error: Target not found: {target}[/red]")
        raise typer.Exit(1)

    # Create config
    try:
        severity_enum = Severity(severity.lower())
    except ValueError:
        console.print(f"[red]Error: Invalid severity: {severity}[/red]")
        console.print("Valid options: critical, high, medium, low, informational")
        raise typer.Exit(1)

    config = AuditConfig(
        severity_threshold=severity_enum,
        generate_poc=generate_poc,
        mock_mode=mock,
    )

    auditor = create_auditor(config)

    # Run audit
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running security audit...", total=None)

        if target_path.is_file():
            result = asyncio.run(auditor.audit_file(str(target_path)))
        else:
            result = asyncio.run(auditor.audit_directory(str(target_path)))

        progress.update(task, completed=True)

    # Display results
    _display_results(result, auditor)

    # Write output
    if output:
        report = auditor.generate_report(result, format=format)
        Path(output).write_text(report)
        console.print(f"\n[green]Report saved to: {output}[/green]")


@app.command()
def analyze(
    source: str = typer.Argument(..., help="Solidity source code or file path"),
    name: str = typer.Option("Contract", "--name", "-n", help="Contract name"),
    mock: bool = typer.Option(False, "--mock", help="Use mock mode for testing"),
) -> None:
    """Analyze Solidity source code directly."""

    # Check if source is a file
    if Path(source).exists():
        source_code = Path(source).read_text()
        name = Path(source).stem
    else:
        source_code = source

    config = AuditConfig(mock_mode=mock)
    auditor = create_auditor(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing source code...", total=None)
        result = asyncio.run(auditor.audit_source(source_code, name))
        progress.update(task, completed=True)

    _display_results(result, auditor)


@app.command()
def version() -> None:
    """Show version information."""
    from contract_auditor import __version__

    console.print(f"Smart Contract Auditor v{__version__}")


def _display_results(result: "AuditResult", auditor: ContractAuditor) -> None:  # noqa: F821
    """Display audit results in a formatted table."""

    # Summary panel
    summary = f"""
[bold]Audit ID:[/bold] {result.audit_id}
[bold]Duration:[/bold] {result.duration_seconds:.2f}s
[bold]Contracts:[/bold] {len(result.contracts)}
[bold]Total Findings:[/bold] {result.total_findings}
    """

    console.print(Panel(summary.strip(), title="Audit Summary", border_style="blue"))

    # Severity breakdown
    severity_table = Table(title="Severity Breakdown")
    severity_table.add_column("Severity", style="bold")
    severity_table.add_column("Count", justify="right")

    severity_table.add_row("Critical", str(result.critical_count), style="red bold")
    severity_table.add_row("High", str(result.high_count), style="red")
    severity_table.add_row("Medium", str(result.medium_count), style="yellow")
    severity_table.add_row("Low", str(result.low_count), style="blue")
    severity_table.add_row("Informational", str(result.informational_count), style="dim")

    console.print(severity_table)

    # Vulnerabilities table
    if result.vulnerabilities:
        vuln_table = Table(title="Vulnerabilities Found")
        vuln_table.add_column("#", style="dim")
        vuln_table.add_column("Severity")
        vuln_table.add_column("Type")
        vuln_table.add_column("Title")
        vuln_table.add_column("Contract")

        for i, vuln in enumerate(result.vulnerabilities, 1):
            severity_style = {
                Severity.CRITICAL: "red bold",
                Severity.HIGH: "red",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue",
                Severity.INFORMATIONAL: "dim",
            }.get(vuln.finding.severity, "")

            vuln_table.add_row(
                str(i),
                vuln.finding.severity.value.upper(),
                vuln.vulnerability_type.value,
                vuln.title[:40] + "..." if len(vuln.title) > 40 else vuln.title,
                vuln.finding.contract_name,
                style=severity_style,
            )

        console.print(vuln_table)

    # PoC results
    if result.poc_exploits:
        poc_table = Table(title="Proof of Concept Results")
        poc_table.add_column("PoC Name")
        poc_table.add_column("Executed")
        poc_table.add_column("Success")
        poc_table.add_column("Gas Used", justify="right")

        for poc in result.poc_exploits:
            poc_table.add_row(
                poc.name,
                "Yes" if poc.executed else "No",
                "[green]Yes[/green]" if poc.success else "[red]No[/red]",
                str(poc.gas_used) if poc.gas_used else "-",
            )

        console.print(poc_table)
        console.print(f"\n[bold]Verified Vulnerabilities:[/bold] {result.verified_vulnerabilities}")
        console.print(f"[bold]Successful Exploits:[/bold] {result.successful_exploits}")


if __name__ == "__main__":
    app()
