from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scanner.report.models import ScanReport, Severity

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "orange3",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def print_report(report: ScanReport) -> None:
    console.print(
        Panel.fit(
            f"[bold]Scan Report[/bold] â {report.target_url}",
            border_style="blue",
        )
    )

    if not report.findings:
        console.print("[green]â No findings.[/green]")
        return

    console.print(
        f"[red]Critical: {report.critical_count}[/red]  "
        f"[orange3]High: {report.high_count}[/orange3]  "
        f"[yellow]Medium: {report.medium_count}[/yellow]  "
        f"[cyan]Low: {report.low_count}[/cyan]  "
        f"  Total: {len(report.findings)}"
    )

    table = Table(box=box.ROUNDED, show_lines=True, expand=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Module", width=18)
    table.add_column("Title", width=30)
    table.add_column("URL")
    table.add_column("Evidence")

    sorted_findings = sorted(report.findings, key=lambda f: f.severity, reverse=True)

    for f in sorted_findings:
        color = SEVERITY_COLORS[f.severity]
        evidence = f.evidence[:80] + "..." if len(f.evidence) > 80 else f.evidence
        table.add_row(
            f"[{color}]{f.severity.value}[/{color}]",
            f.module,
            f.title,
            f.url,
            evidence,
        )

    console.print(table)

    if report.duration_seconds is not None:
        console.print(f"Scan completed in [bold]{report.duration_seconds:.1f}s[/bold]")
