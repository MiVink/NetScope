""" CLI entry point with Typer and Rich. """

import asyncio
import sys
import typer
from rich.console import Console
from rich.panel import Panel

from .scanner import NetScopeScanner
from .utils import normalize_target

app = typer.Typer(
    name="netscope",
    help="NetScope CLI — Educational Web Inspector",
    add_completion=False,
)
console = Console()


BANNER = """
[bold cyan]███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗[/bold cyan]
[bold cyan]████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝[/bold cyan]
[bold cyan]██╔██╗ ██║█████╗     ██║   ███████╗██║     ██║   ██║██████╔╝█████╗  [/bold cyan]
[bold cyan]██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  [/bold cyan]
[bold cyan]██║ ╚████║███████╗   ██║   ███████║╚██████╗╚██████╔╝██║     ███████╗[/bold cyan]
[bold cyan]╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝[/bold cyan]
[dim]                    Version 1.0 Release — Web Inspector[/dim]
"""


def show_banner():
    """Display banner."""
    console.print(BANNER)
    console.print()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain or URL to scan"),
    raw: bool = typer.Option(False, "--raw", help="Display raw HTTP request and response"),
    export: str = typer.Option(None, "--export", help="Export report to directory (Markdown)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Display detailed output"),
    log: bool = typer.Option(False, "--log", help="Save scan log to scan.log"),
):
    """Scan a website and analyze its technologies, security, and infrastructure."""
    show_banner()

    # Normalize and validate
    try:
        domain, full_url, is_https = normalize_target(target)
    except Exception as e:
        console.print(f"[red]Invalid target: {e}[/red]")
        raise typer.Exit(1)

    console.print(f"[dim]Target: {target} → {domain}[/dim]")
    if verbose:
        console.print("[dim]Verbose mode enabled[/dim]")
    console.print()

    log_file = "scan.log" if log else None
    scanner = NetScopeScanner(verbose=verbose, log_file=log_file)

    try:
        asyncio.run(scanner.scan(target, raw_mode=raw, export_dir=export))
    except KeyboardInterrupt:
        console.print()
        console.print("[yellow]Scan cancelled.[/yellow]")
        console.print("[dim]Cleaning up...[/dim]")
        console.print("[dim]Done.[/dim]")
        raise typer.Exit(0)


@app.command()
def version():
    """Show version information."""
    show_banner()


if __name__ == "__main__":
    app()
