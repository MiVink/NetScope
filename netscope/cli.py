"""CLI entry point with Typer and Rich."""

import asyncio
import sys
from typing import Optional

import typer
from rich.console import Console

from .scanner import NetScopeScanner
from .utils import normalize_target


def _configure_streams() -> None:
    """Make stdout/stderr encoding-safe.

    On Windows, piped/redirected output uses the ANSI code page (cp1251,
    cp866, ...) which cannot represent the box-drawing characters and glyphs
    the tool prints, crashing with UnicodeEncodeError. Force UTF-8 with
    replacement so output degrades gracefully instead of raising.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


_configure_streams()

try:
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("netscope")
except Exception:
    __version__ = "1.0.0"

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
[dim]                    Version {version} — Web Inspector[/dim]
""".format(version=__version__)


def show_banner():
    """Display banner."""
    console.print(BANNER)
    console.print()


def _safe_print(message: str):
    """Print without ever crashing on consoles with limited encodings."""
    try:
        console.print(message)
    except UnicodeEncodeError:
        # Rich may leave buffered segments behind; bypass it entirely.
        plain = message.encode("utf-8", errors="replace").decode("utf-8")
        try:
            sys.stdout.write(plain + "\n")
            sys.stdout.flush()
        except UnicodeEncodeError:
            sys.stdout.write(plain.encode("ascii", "replace").decode("ascii") + "\n")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain or URL to scan"),
    raw: bool = typer.Option(False, "--raw", help="Display raw HTTP request and response"),
    export: Optional[str] = typer.Option(None, "--export", help="Export report to directory (Markdown)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Display detailed output"),
    log: bool = typer.Option(False, "--log", help="Save scan log to scan.log"),
):
    """Scan a website and analyze its technologies, security, and infrastructure."""
    show_banner()

    # Normalize and validate
    try:
        domain, _full_url, _is_https = normalize_target(target)
    except ValueError as e:
        _safe_print(f"[red]Invalid target: {e}[/red]")
        raise typer.Exit(2)

    _safe_print(f"[dim]Target: {target} → {domain}[/dim]")
    if verbose:
        _safe_print("[dim]Verbose mode enabled[/dim]")
    console.print()

    log_file = "scan.log" if log else None
    scanner = NetScopeScanner(verbose=verbose, log_file=log_file)

    try:
        ok = asyncio.run(scanner.scan(target, raw_mode=raw, export_dir=export))
    except KeyboardInterrupt:
        console.print()
        console.print("[yellow]Scan cancelled.[/yellow]")
        raise typer.Exit(130)

    if not ok:
        _safe_print("[red]Scan failed — see errors above.[/red]")
        raise typer.Exit(1)


@app.command()
def version():
    """Show version information."""
    _safe_print(BANNER)
    _safe_print(f"[dim]netscope {__version__}[/dim]")


if __name__ == "__main__":
    app()
