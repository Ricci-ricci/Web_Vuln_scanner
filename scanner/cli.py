from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from scanner.core.engine import MODULE_MAP, Engine
from scanner.core.target import Target
from scanner.report.console import print_report
from scanner.report.exporter import export_html, export_json

app = typer.Typer(
    help="Web Vulnerability Scanner â educational tool for authorised testing only."
)
console = Console()


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL to scan."),
    modules: Optional[str] = typer.Option(
        None,
        "--modules",
        "-m",
        help="Comma-separated list of modules to run. Default: all.",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output format: json or html.",
    ),
    report_path: Optional[str] = typer.Option(
        None,
        "--report",
        "-r",
        help="Output file path for the report.",
    ),
    max_depth: int = typer.Option(3, "--depth", help="Maximum crawl depth."),
    max_pages: int = typer.Option(200, "--max-pages", help="Maximum pages to crawl."),
    timeout: int = typer.Option(
        10, "--timeout", help="HTTP request timeout in seconds."
    ),
) -> None:
    """Scan a target URL for common web vulnerabilities."""
    try:
        target = Target(url)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    module_list: list[str] | None = None
    if modules:
        module_list = [m.strip() for m in modules.split(",")]
        unknown = [m for m in module_list if m not in MODULE_MAP]
        if unknown:
            console.print(f"[red]Unknown module(s):[/red] {', '.join(unknown)}")
            console.print(f"Available: {', '.join(MODULE_MAP.keys())}")
            raise typer.Exit(1)

    engine = Engine(
        target,
        modules=module_list,
        max_depth=max_depth,
        max_pages=max_pages,
        timeout=timeout,
    )

    console.print(f"[bold blue]Scanning[/bold blue] {target.url} ...")
    scan_report = engine.run()

    print_report(scan_report)

    if output and report_path:
        if output == "json":
            export_json(scan_report, report_path)
            console.print(f"[green]JSON report saved to {report_path}[/green]")
        elif output == "html":
            export_html(scan_report, report_path)
            console.print(f"[green]HTML report saved to {report_path}[/green]")
        else:
            console.print(
                f"[yellow]Unknown output format '{output}'. Use 'json' or 'html'.[/yellow]"
            )


@app.command(name="list-modules")
def list_modules() -> None:
    """List all available scan modules."""
    console.print("[bold]Available modules:[/bold]")
    for name, cls in MODULE_MAP.items():
        console.print(f"  [cyan]{name:<20}[/cyan] {cls.description}")
    console.print()


if __name__ == "__main__":
    app()
