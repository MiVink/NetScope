"""Main scanner orchestrator with step-by-step output."""

import asyncio
import socket
import time
from datetime import datetime
from typing import Optional, Dict, List

from rich.console import Console

from .models import (
    ScanResult,
    DNSRecord,
    ResponseTimeline,
    AdditionalInfo,
    ErrorLog,
)
from .utils import normalize_target, format_timestamp, PreciseTimer

# Import modules
from .modules import dns_lookup, ssl_check, http_info, security_headers
from .modules import cookies, robots, sitemap, favicon, compression
from .modules import redirects, technologies, whois_lookup
from .config import MAX_RETRIES, MODULE_TIMEOUT, HTTP_TIMEOUT, TCP_TIMEOUT, RETRY_BACKOFF


class NetScopeScanner:
    """Orchestrates all scanning modules with real-time step output."""

    def __init__(self, verbose: bool = False, log_file: Optional[str] = None):
        self.console = Console()
        self.verbose = verbose
        self.log_file = log_file
        self._log_lines: List[str] = []
        self.result = ScanResult(target="")
        self.is_https = True
        self._tls_checked = False
        self._timeline = ResponseTimeline()

    # ─── Logging helpers ────────────────────────────────────────────

    def _log(self, message: str):
        """Internal log collector for --log mode."""
        self._log_lines.append(f"{format_timestamp()} {message}")

    def _save_log(self):
        """Save collected log to file."""
        if self.log_file and self._log_lines:
            try:
                with open(self.log_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(self._log_lines))
                self.console.print(f"[dim]Log saved to {self.log_file}[/dim]")
            except Exception as e:
                self.console.print(f"[red]Failed to save log: {e}[/red]")

    def _log_step(self, message: str, style: str = "cyan"):
        """Print a timestamped step message."""
        line = f"{format_timestamp()} {message}"
        self.console.print(line, style=style)
        self._log(line)

    def _log_success(self, message: str):
        """Print a success checkmark."""
        line = f"  ✔ {message}"
        self.console.print(f"  [bold green]✔[/bold green] {message}")
        self._log(line)

    def _log_info(self, message: str):
        """Print an info bullet."""
        line = f"  • {message}"
        self.console.print(f"  [dim]• {message}[/dim]")
        self._log(line)

    def _log_warning(self, message: str):
        """Print a warning."""
        line = f"  ⚠ {message}"
        self.console.print(f"  [bold yellow]⚠[/bold yellow] {message}")
        self._log(line)

    def _log_error(self, message: str):
        """Print an error but continue."""
        line = f"  ✗ {message}"
        self.console.print(f"  [bold red]✗[/bold red] {message}")
        self._log(line)

    def _log_retry(self, attempt: int, max_retries: int):
        """Print retry message."""
        line = f"  Retry {attempt}/{max_retries}..."
        self.console.print(f"  [yellow]↻ Retry {attempt}/{max_retries}...[/yellow]")
        self._log(line)

    def _print_section_header(self, title: str):
        """Print a clean section header."""
        self.console.print()
        self.console.print(f"[bold white]{title}[/bold white]")
        self.console.print("[dim]" + "─" * 40 + "[/dim]")

    def _group_dns_records(self, records: List[DNSRecord]) -> Dict[str, List[DNSRecord]]:
        """Group DNS records by type."""
        grouped = {}
        for rec in records:
            grouped.setdefault(rec.type, []).append(rec)
        return grouped

    def _record_error(self, module: str, error: str, is_warning: bool = False):
        """Record an error for the error summary (long messages are trimmed)."""
        error = " ".join(str(error).split())  # collapse newlines/whitespace
        if len(error) > 300:
            error = error[:297] + "..."
        self.result.errors.append(ErrorLog(module=module, error=error, is_warning=is_warning))
        self._log(f"ERROR [{module}]: {error}")

    # ─── Module runner ──────────────────────────────────────────────

    async def _run_module(
        self, name: str, coro, *args, max_retries: int = MAX_RETRIES, timeout: float = MODULE_TIMEOUT, **kwargs
    ):
        """Run a module with retry logic and timeout handling."""
        for attempt in range(1, max_retries + 1):
            try:
                return await asyncio.wait_for(coro(*args, **kwargs), timeout=timeout)
            except asyncio.TimeoutError:
                if attempt < max_retries:
                    self._log_retry(attempt, max_retries)
                    await asyncio.sleep(RETRY_BACKOFF * attempt)
                    continue
                self._record_error(name, f"Timeout after {timeout:.0f}s")
                raise
            except Exception as e:
                error_str = str(e).lower()
                # Don't retry permanent errors
                permanent = [
                    "nxdomain",
                    "noanswer",
                    "nonameservers",
                    "nodename",
                    "not known",
                    "invalid",
                    "refused",
                    "no such file",
                    "no match",
                    "not found",
                    "no entries",
                    "does not exist",
                    "getaddrinfo failed",
                    "name or service not known",
                    "temporary failure in name resolution",
                ]
                if any(p in error_str for p in permanent):
                    self._record_error(name, str(e))
                    raise
                if attempt < max_retries:
                    self._log_retry(attempt, max_retries)
                    await asyncio.sleep(RETRY_BACKOFF * attempt)
                    continue
                self._record_error(name, str(e))
                raise

    # ─── Scan ───────────────────────────────────────────────────────

    async def scan(self, target: str, raw_mode: bool = False, export_dir: Optional[str] = None) -> bool:
        """Run full scan with step-by-step output.

        Returns True when the core scan (DNS + HTTP) succeeded.
        """
        try:
            return await self._do_scan(target, raw_mode, export_dir)
        except KeyboardInterrupt:
            self.console.print()
            self.console.print("[yellow]Scan cancelled.[/yellow]")
            self.console.print("[dim]Cleaning up...[/dim]")
            self._save_log()
            self.console.print("[dim]Done.[/dim]")
            raise
        except Exception as e:
            # Never leak a traceback: report and still save the log
            self._log_error(f"Scan aborted: {e}")
            self._record_error("Scanner", str(e))
            self._save_log()
            return False

    async def _do_scan(self, target: str, raw_mode: bool = False, export_dir: Optional[str] = None) -> bool:
        """Internal scan implementation. Returns True on success."""
        domain, full_url, is_https = normalize_target(target)

        # Fresh state for every run
        self.result = ScanResult(target=domain)
        self.is_https = is_https
        self._tls_checked = False
        self._timeline = ResponseTimeline()

        total_start = time.perf_counter()
        self._log_step(f"Target: {domain}", "dim")

        # ─── DNS ───
        self._log_step("Resolving DNS...")
        with PreciseTimer() as t:
            try:
                dns_records = await self._run_module("DNS", dns_lookup.scan, domain)
                self.result.dns_records = dns_records
                if dns_records:
                    self._log_success(f"DNS resolved ({len(dns_records)} records)")
                else:
                    self._log_warning("No DNS records found")
                    self._record_error("DNS", "No DNS records found", is_warning=True)
            except Exception as e:
                self._log_error(f"DNS lookup failed: {e}")
        self._timeline.dns_lookup_ms = t.elapsed_ms

        # ─── IP Info ───
        self._log_step("Analyzing IP information...")
        try:
            ip_info = await self._run_module("IP Info", dns_lookup.get_ip_info, domain)
            self.result.ip_info = ip_info
            if ip_info.ipv4 or ip_info.ipv6:
                self._log_success("IP information retrieved")
            else:
                self._log_warning("No IP addresses resolved")
        except Exception as e:
            self._log_error(f"IP analysis failed: {e}")

        # ─── WHOIS ───
        self._log_step("Querying WHOIS database...")
        try:
            whois_info = await self._run_module("WHOIS", whois_lookup.scan, domain)
            self.result.whois = whois_info
            if whois_info.registrar:
                self._log_success("WHOIS data retrieved")
            else:
                self._log_warning("WHOIS returned no registrar data")
        except Exception as e:
            self._log_error(f"WHOIS lookup failed: {e}")

        # ─── TCP Connection ───
        # A failed pre-check must not abort the scan: HTTP/TLS modules report
        # their own, more precise errors.
        tcp_ok = False
        self._log_step("Opening TCP connection...")
        with PreciseTimer() as t:
            port = 443 if is_https else 80
            try:
                sock = await asyncio.to_thread(socket.create_connection, (domain, port), TCP_TIMEOUT)
                sock.close()
                tcp_ok = True
                self._log_success(f"Connected to {domain}:{port}")
            except Exception as e:
                self._log_error(f"TCP connection failed: {e}")
                self._record_error("TCP", str(e))
        self._timeline.tcp_connect_ms = t.elapsed_ms

        # ─── TLS Handshake ───
        if is_https:
            self._tls_checked = True
            self._log_step("Performing TLS handshake...")
            with PreciseTimer() as t:
                try:
                    tls_info = await self._run_module("TLS", ssl_check.scan, domain)
                    self.result.tls = tls_info
                    if tls_info.version:
                        suffix = ""
                        if tls_info.chain_valid is False:
                            suffix = " [red](certificate INVALID)[/red]"
                        self._log_success(f"{tls_info.version} established{suffix}")
                except Exception as e:
                    self._log_error(f"TLS handshake failed: {e}")
            self._timeline.tls_handshake_ms = t.elapsed_ms
        elif tcp_ok:
            self._log_info("Plaintext HTTP target — TLS skipped")

        # ─── HTTP Request ───
        self._log_step("Sending HTTP request...")
        try:
            http_data = await self._run_module("HTTP", http_info.scan, full_url, timeout=HTTP_TIMEOUT)
            self.result.http_version = http_data.get("http_version")
            self.result.status_code = http_data.get("status_code")
            self.result.response_time_ms = http_data.get("response_time_ms")
            self.result.final_url = http_data.get("final_url")
            self.result.server_header = http_data.get("server")
            self.result.content_length = http_data.get("content_length")
            self.result.content_type = http_data.get("content_type")
            self.result.all_headers = http_data.get("headers", {})
            self.result.headers_list = http_data.get("headers_list", [])
            self.result.request_method = http_data.get("request_method", "GET")
            self.result.request_url = http_data.get("request_url")
            self.result.request_headers = http_data.get("request_headers", {})

            self._timeline.ttfb_ms = http_data.get("ttfb_ms")
            self._timeline.download_ms = http_data.get("download_ms")

            # Judge HTTPS by where we actually ended up, not by the input scheme:
            # http://target may redirect to https://target.
            self.is_https = (self.result.final_url or full_url).lower().startswith("https")

            # Build AdditionalInfo from HTTP headers
            add_info = AdditionalInfo()
            add_info.content_encoding = http_data.get("content_encoding")
            add_info.transfer_encoding = http_data.get("transfer_encoding")
            add_info.keep_alive = http_data.get("keep_alive")
            add_info.alt_svc = http_data.get("alt_svc")
            if http_data.get("alt_svc") and "h3" in (http_data.get("alt_svc") or "").lower():
                add_info.http3_support = True
            self.result.additional_info = add_info

            status = self.result.status_code or "???"
            version = self.result.http_version or "HTTP/?"
            self._log_success(f"{version} {status}")
        except Exception as e:
            self._log_error(f"HTTP request failed: {e}")
            # Produce a partial report instead of exiting silently
            self._finish_scan(total_start, raw_mode, export_dir)
            return False

        # ─── Redirects ───
        self._log_step("Analyzing redirect chain...")
        try:
            redirects_data = await self._run_module("Redirects", redirects.scan, full_url)
            self.result.redirect_chain = redirects_data
            if len(redirects_data) > 1:
                self._log_success(f"{len(redirects_data) - 1} redirect(s) traced")
            else:
                self._log_success("No redirects")
        except Exception as e:
            self._log_error(f"Redirect analysis failed: {e}")

        # ─── Compression ───
        self._log_step("Checking compression support...")
        try:
            comp = await self._run_module("Compression", compression.scan, full_url)
            self.result.compression = comp
            if comp:
                self._log_success(f"{', '.join(comp)} supported")
            else:
                self._log_success("No compression")
        except Exception as e:
            self._log_error(f"Compression check failed: {e}")

        # ─── Security Headers ───
        self._log_step("Analyzing security headers...")
        try:
            sec_headers = await self._run_module("Security Headers", security_headers.scan, self.result.all_headers)
            self.result.security_headers = sec_headers
            present = [h for h in sec_headers if h.present]
            self._log_success(f"{len(present)} security headers present")
        except Exception as e:
            self._log_error(f"Security header analysis failed: {e}")

        # ─── Cookies (from the already-fetched response headers) ───
        self._log_step("Inspecting cookies...")
        try:
            cookies_data = cookies.parse_headers(self.result.headers_list)
            self.result.cookies = cookies_data
            if cookies_data:
                self._log_success(f"{len(cookies_data)} cookie(s) found")
            else:
                self._log_success("No cookies")
        except Exception as e:
            self._log_error(f"Cookie inspection failed: {e}")

        # ─── robots.txt ───
        self._log_step("Fetching robots.txt...")
        try:
            robots_data = await self._run_module("robots.txt", robots.scan, domain, full_url)
            self.result.robots_txt = robots_data
            if robots_data.get("exists"):
                self._log_success("robots.txt found")
            else:
                self._log_success("robots.txt not found")
        except Exception as e:
            self._log_error(f"robots.txt check failed: {e}")

        # ─── sitemap.xml ───
        self._log_step("Fetching sitemap.xml...")
        try:
            sitemap_data = await self._run_module("sitemap.xml", sitemap.scan, domain, full_url)
            self.result.sitemap = sitemap_data
            if sitemap_data.get("exists"):
                self._log_success(f"sitemap.xml found ({sitemap_data.get('url_count', 0)} URLs)")
            else:
                self._log_success("sitemap.xml not found")
        except Exception as e:
            self._log_error(f"sitemap check failed: {e}")

        # ─── Favicon ───
        self._log_step("Checking favicon...")
        try:
            favicon_data = await self._run_module("Favicon", favicon.scan, domain, full_url)
            self.result.favicon = favicon_data
            if favicon_data.get("exists"):
                self._log_success("Favicon found")
            else:
                self._log_success("No favicon")
        except Exception as e:
            self._log_error(f"Favicon check failed: {e}")

        # ─── Technology Detection ───
        self._log_step("Detecting technologies...")
        try:
            techs = await self._run_module(
                "Technologies",
                technologies.scan,
                full_url,
                self.result.all_headers,
                self.result.server_header or "",
            )
            self.result.technologies = techs
            if techs:
                self._log_success(f"{len(techs)} technology(s) detected")
            else:
                self._log_success("No technologies detected")
        except Exception as e:
            self._log_error(f"Technology detection failed: {e}")

        self._finish_scan(total_start, raw_mode, export_dir)
        return True

    def _finish_scan(self, total_start: float, raw_mode: bool, export_dir: Optional[str]):
        """Common tail: finalize timeline, render report, save log."""
        self._timeline.total_ms = (time.perf_counter() - total_start) * 1000
        self.result.timeline = self._timeline

        self._log_step("Generating report...")
        self._display_report(raw_mode=raw_mode, export_dir=export_dir)
        self._save_log()

    # ─── Report ─────────────────────────────────────────────────────

    def _display_report(self, raw_mode: bool = False, export_dir: Optional[str] = None):
        """Display final report with sections."""
        self.console.print()

        # ═══════════════════════════════════════
        # NETWORK
        # ═══════════════════════════════════════
        self._print_section_header("Network")

        if self.result.dns_records:
            grouped = self._group_dns_records(self.result.dns_records)
            for rtype in ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]:
                if rtype in grouped:
                    recs = grouped[rtype]
                    self.console.print(f"[bold cyan]{rtype} Records[/bold cyan] ({len(recs)})")
                    shown = recs if self.verbose else recs[:3]
                    for rec in shown:
                        ttl_str = f" (TTL: {rec.ttl})" if rec.ttl else ""
                        self.console.print(f"  {rec.value}{ttl_str}")
                    if not self.verbose and len(recs) > 3:
                        self.console.print(f"  ... and {len(recs) - 3} more")

        if self.result.ip_info:
            ip = self.result.ip_info
            if ip.ipv4:
                self.console.print(f"[bold cyan]IPv4[/bold cyan] ({len(ip.ipv4)})")
                shown = ip.ipv4 if self.verbose else ip.ipv4[:3]
                for addr in shown:
                    self.console.print(f"  {addr}")
                if not self.verbose and len(ip.ipv4) > 3:
                    self.console.print(f"  ... and {len(ip.ipv4) - 3} more")
            if ip.ipv6:
                self.console.print(f"[bold cyan]IPv6[/bold cyan] ({len(ip.ipv6)})")
                shown = ip.ipv6 if self.verbose else ip.ipv6[:2]
                for addr in shown:
                    self.console.print(f"  {addr}")
                if not self.verbose and len(ip.ipv6) > 2:
                    self.console.print(f"  ... and {len(ip.ipv6) - 2} more")
            if ip.asn:
                self.console.print(f"[bold cyan]ASN[/bold cyan] {ip.asn}")
            if ip.provider:
                self.console.print(f"[bold cyan]Provider[/bold cyan] {ip.provider}")
            if ip.cdn:
                self.console.print(f"[bold cyan]CDN[/bold cyan] {ip.cdn}")
            if ip.country:
                self.console.print(f"[bold cyan]Country[/bold cyan] {ip.country}")

        if self.result.whois:
            w = self.result.whois
            self.console.print(f"[bold cyan]Registrar[/bold cyan] {w.registrar or 'N/A'}")
            if w.creation_date:
                self.console.print(f"[bold cyan]Created[/bold cyan] {w.creation_date.strftime('%Y-%m-%d')}")
            if w.expiration_date:
                self.console.print(f"[bold cyan]Expires[/bold cyan] {w.expiration_date.strftime('%Y-%m-%d')}")
            if w.name_servers:
                ns = ", ".join(w.name_servers[:4])
                self.console.print(f"[bold cyan]Name Servers[/bold cyan] {ns}")

        # ═══════════════════════════════════════
        # HTTP
        # ═══════════════════════════════════════
        self._print_section_header("HTTP")

        if self.result.http_version:
            self.console.print(f"[bold cyan]Version[/bold cyan] {self.result.http_version}")
        if self.result.status_code is not None:
            code = self.result.status_code
            status_color = "green" if code < 400 else "yellow" if code < 500 else "red"
            self.console.print(f"[bold cyan]Status[/bold cyan] [{status_color}]{code}[/{status_color}]")
        if self.result.response_time_ms is not None:
            self.console.print(f"[bold cyan]Response Time[/bold cyan] {self.result.response_time_ms:.2f} ms")
        if self.result.final_url:
            self.console.print(f"[bold cyan]Final URL[/bold cyan] {self.result.final_url}")
        if self.result.server_header:
            self.console.print(f"[bold cyan]Server[/bold cyan] {self.result.server_header}")
        if self.result.content_length is not None:
            self.console.print(f"[bold cyan]Content Length[/bold cyan] {self.result.content_length} bytes")
        if self.result.content_type:
            self.console.print(f"[bold cyan]Content Type[/bold cyan] {self.result.content_type}")

        if self.result.redirect_chain and len(self.result.redirect_chain) > 1:
            self.console.print(f"[bold cyan]Redirects[/bold cyan] {len(self.result.redirect_chain) - 1}")
            chain = self.result.redirect_chain if self.verbose else self.result.redirect_chain[:5]
            for r in chain:
                self.console.print(f"  [{r.status_code}] {r.url}")
            if not self.verbose and len(self.result.redirect_chain) > 5:
                self.console.print(f"  ... and {len(self.result.redirect_chain) - 5} more")

        if self.result.compression:
            self.console.print(f"[bold cyan]Compression[/bold cyan] {', '.join(self.result.compression)}")

        # ═══════════════════════════════════════
        # TLS
        # ═══════════════════════════════════════
        if self.result.tls:
            self._print_section_header("TLS")
            tls = self.result.tls
            if tls.version:
                self.console.print(f"[bold cyan]Version[/bold cyan] {tls.version}")
            if tls.cipher:
                self.console.print(f"[bold cyan]Cipher[/bold cyan] {tls.cipher}")
            if tls.alpn:
                self.console.print(f"[bold cyan]ALPN[/bold cyan] {tls.alpn}")
            if tls.issuer:
                self.console.print(f"[bold cyan]Issuer[/bold cyan] {tls.issuer}")
            if tls.subject:
                self.console.print(f"[bold cyan]Subject[/bold cyan] {tls.subject}")
            if tls.valid_from:
                self.console.print(f"[bold cyan]Valid From[/bold cyan] {tls.valid_from.strftime('%Y-%m-%d')}")
            if tls.valid_until:
                self.console.print(f"[bold cyan]Valid Until[/bold cyan] {tls.valid_until.strftime('%Y-%m-%d')}")
            if tls.days_remaining is not None:
                color = "green" if tls.days_remaining > 30 else "yellow" if tls.days_remaining > 7 else "red"
                self.console.print(f"[bold cyan]Days Remaining[/bold cyan] [{color}]{tls.days_remaining}[/{color}]")
            if tls.chain_valid is not None:
                if tls.chain_valid:
                    self.console.print("[bold cyan]Certificate[/bold cyan] [green]Valid[/green]")
                else:
                    err = f" — {tls.verify_error}" if tls.verify_error else ""
                    self.console.print(f"[bold cyan]Certificate[/bold cyan] [red]INVALID[/red]{err}")
            if tls.fingerprint:
                self.console.print("[bold cyan]SHA256 Fingerprint[/bold cyan]")
                self.console.print(f"  {tls.fingerprint}")

        # ═══════════════════════════════════════
        # SECURITY AUDIT
        # ═══════════════════════════════════════
        self._print_section_header("Security Audit")
        self._display_security_audit()

        # ═══════════════════════════════════════
        # COOKIES
        # ═══════════════════════════════════════
        if self.result.cookies:
            self._print_section_header("Cookies")
            cookie_list = self.result.cookies if self.verbose else self.result.cookies[:5]
            for c in cookie_list:
                flags = []
                if c.secure:
                    flags.append("Secure")
                if c.httponly:
                    flags.append("HttpOnly")
                if c.samesite:
                    flags.append(f"SameSite={c.samesite}")
                flags_str = f" ({', '.join(flags)})" if flags else " (no flags)"
                self.console.print(f"  {c.name}{flags_str}")
            if not self.verbose and len(self.result.cookies) > 5:
                self.console.print(f"  ... and {len(self.result.cookies) - 5} more")

        # ═══════════════════════════════════════
        # ROBOTS.TXT
        # ═══════════════════════════════════════
        if self.result.robots_txt:
            self._print_section_header("robots.txt")
            r = self.result.robots_txt
            if r.get("exists"):
                self.console.print("[green]Exists[/green]")
                rules = r.get("rules", [])
                if rules:
                    for rule in rules[:10]:
                        self.console.print(f"  {rule['type'].upper()}: {rule['path']}")
                    if not self.verbose and len(rules) > 10:
                        self.console.print(f"  ... and {len(rules) - 10} more")
                else:
                    self.console.print("  [dim]No Allow/Disallow rules[/dim]")
                if r.get("sitemap"):
                    self.console.print(f"  Sitemap: {r['sitemap']}")
            else:
                self.console.print("[dim]Not found[/dim]")

        # ═══════════════════════════════════════
        # SITEMAP
        # ═══════════════════════════════════════
        if self.result.sitemap:
            self._print_section_header("sitemap.xml")
            s = self.result.sitemap
            if s.get("exists"):
                kind = "index" if s.get("is_index") else "sitemap"
                self.console.print(f"[green]Exists[/green] ({kind}, {s.get('url_count', 0)} URLs)")
            else:
                self.console.print("[dim]Not found[/dim]")

        # ═══════════════════════════════════════
        # FAVICON
        # ═══════════════════════════════════════
        if self.result.favicon:
            self._print_section_header("Favicon")
            f = self.result.favicon
            if f.get("exists"):
                self.console.print(f"[green]Found[/green] ({f.get('file_type', 'unknown')})")
                if f.get("hash"):
                    self.console.print(f"  Hash: {f['hash']}")
            else:
                self.console.print("[dim]Not found[/dim]")

        # ═══════════════════════════════════════
        # TECHNOLOGIES
        # ═══════════════════════════════════════
        if self.result.technologies:
            self._print_section_header("Technologies")
            for t in self.result.technologies:
                self.console.print(f"[bold green]{t.name}[/bold green] ({t.category})")
                if t.evidence:
                    self.console.print(f"  Evidence: {t.evidence}")

        # ═══════════════════════════════════════
        # RESPONSE HEADERS
        # ═══════════════════════════════════════
        if self.result.all_headers:
            self._print_section_header("Response Headers")
            if self.verbose:
                for key, value in sorted(self.result.all_headers.items()):
                    self.console.print(f"[cyan]{key}:[/cyan] {value}")
            else:
                self.console.print(f"{len(self.result.all_headers)} headers (use -v to show)")

        # ═══════════════════════════════════════
        # ADDITIONAL INFORMATION
        # ═══════════════════════════════════════
        if self.result.additional_info:
            add = self.result.additional_info
            items = [
                ("Keep-Alive", add.keep_alive),
                ("Alt-Svc", add.alt_svc),
                ("Content-Encoding", add.content_encoding),
                ("Transfer-Encoding", add.transfer_encoding),
            ]
            bools = [
                ("HTTP/3 Support", add.http3_support),
            ]
            if any(v for _, v in items) or any(v is not None for _, v in bools):
                self._print_section_header("Additional Information")
                for label, value in items:
                    if value:
                        self.console.print(f"[bold cyan]{label}[/bold cyan] {value}")
                for label, value in bools:
                    if value is not None:
                        self.console.print(f"[bold cyan]{label}[/bold cyan] {'Yes' if value else 'No'}")

        # ═══════════════════════════════════════
        # RESPONSE TIMELINE
        # ═══════════════════════════════════════
        if self.result.timeline:
            self._print_section_header("Response Timeline")
            tl = self.result.timeline

            def fmt_ms(val):
                if val is None:
                    return "N/A"
                return f"{val:.0f} ms"

            labels = [
                ("DNS Lookup", tl.dns_lookup_ms),
                ("TCP Connect", tl.tcp_connect_ms),
                ("TLS Handshake", tl.tls_handshake_ms),
                ("TTFB", tl.ttfb_ms),
                ("Download", tl.download_ms),
                ("Total", tl.total_ms),
            ]
            max_label_len = max(len(lb[0]) for lb in labels)

            for label, val in labels:
                dots = "." * max(20, 30 - len(label))
                self.console.print(f"{label:<{max_label_len}} {dots} {fmt_ms(val)}")
            self.console.print("[dim]TTFB includes connection setup; Total covers the whole scan.[/dim]")

        # ═══════════════════════════════════════
        # RAW MODE
        # ═══════════════════════════════════════
        if raw_mode:
            self._print_section_header("Raw HTTP")
            self._display_raw_mode()

        # ═══════════════════════════════════════
        # ERROR SUMMARY
        # ═══════════════════════════════════════
        if self.result.errors:
            self._print_section_header("Error Summary")
            for err in self.result.errors:
                color = "yellow" if err.is_warning else "red"
                self.console.print(f"[bold {color}]{err.module}[/bold {color}]")
                self.console.print(f"  {err.error}")

        # ═══════════════════════════════════════
        # EXPORT
        # ═══════════════════════════════════════
        if export_dir:
            self._export_markdown(export_dir)

        self.console.print()
        self.console.print(f"[dim]Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")

    def _display_security_audit(self):
        """Display security audit grouped by severity."""
        findings = {
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": [],
        }

        # Header-based findings require an actual analyzed response
        analyzed = bool(self.result.security_headers) and bool(self.result.all_headers)
        headers = {h.name: h for h in self.result.security_headers}

        # A 4xx/5xx response is usually a block page or error page: the header
        # verdict below describes that page, not what a real visitor gets.
        status = self.result.status_code
        if status is not None and status >= 400:
            findings["INFO"].append(
                f"Target answered HTTP {status} — findings describe that response, "
                "not a normal page (the site may be blocking this scanner)"
            )

        if not analyzed:
            findings["INFO"].append("Response headers unavailable — header checks skipped")
        else:
            if not self.is_https:
                findings["INFO"].append("Site served over plain HTTP (no HSTS possible)")
            elif not headers.get("HSTS") or not headers["HSTS"].present:
                findings["HIGH"].append("Missing HSTS (HTTP Strict Transport Security)")

            if not headers.get("CSP") or not headers["CSP"].present:
                findings["MEDIUM"].append("Missing CSP (Content Security Policy)")

            if not headers.get("X-Frame-Options") or not headers["X-Frame-Options"].present:
                csp = headers.get("CSP")
                if not csp or "frame-ancestors" not in (csp.value or "").lower():
                    findings["MEDIUM"].append("Missing X-Frame-Options or CSP frame-ancestors (clickjacking risk)")

            if not headers.get("X-Content-Type-Options") or not headers["X-Content-Type-Options"].present:
                findings["MEDIUM"].append("Missing X-Content-Type-Options (MIME sniffing risk)")

            for name in ("Referrer-Policy", "Permissions-Policy", "Cross-Origin-Opener-Policy"):
                h = headers.get(name)
                if not h or not h.present:
                    findings["LOW"].append(f"Missing {name}")

        if self.result.tls:
            tls = self.result.tls
            if tls.version in ("TLSv1.0", "TLSv1.1"):
                findings["HIGH"].append(f"Weak TLS version: {tls.version}")
            elif tls.version == "TLSv1.2":
                findings["MEDIUM"].append("TLS 1.2 supported (TLS 1.3 recommended)")

            if tls.chain_valid is False and tls.verify_error:
                findings["HIGH"].append(f"Certificate does not validate: {tls.verify_error}")

            if tls.days_remaining is not None:
                if tls.days_remaining < 0:
                    findings["HIGH"].append("TLS certificate expired")
                elif tls.days_remaining < 7:
                    findings["HIGH"].append(f"TLS certificate expires in {tls.days_remaining} days")
                elif tls.days_remaining < 30:
                    findings["MEDIUM"].append(f"TLS certificate expires in {tls.days_remaining} days")
        else:
            # No TLS data: was the target HTTPS at all?
            final = (self.result.final_url or "").lower()
            target_https = final.startswith("https") or (not final and self.is_https)
            if target_https:
                # Only claim a failure if we actually attempted the handshake
                if self._tls_checked:
                    findings["HIGH"].append("HTTPS URL but TLS handshake failed")
                else:
                    findings["INFO"].append("TLS not inspected (target was entered as http://)")

        if self.result.cookies:
            for c in self.result.cookies:
                if not c.secure:
                    findings["MEDIUM"].append(f"Cookie '{c.name}' missing Secure flag")
                if not c.httponly:
                    findings["LOW"].append(f"Cookie '{c.name}' missing HttpOnly flag")
                if not c.samesite:
                    findings["LOW"].append(f"Cookie '{c.name}' missing SameSite attribute")

        server = (self.result.server_header or "").lower()
        if any(x in server for x in ("nginx/", "apache/", "iis/", "microsoft-iis", "php/")):
            findings["LOW"].append(f"Server header reveals version: {self.result.server_header}")

        if self.result.ip_info and self.result.ip_info.ipv6:
            findings["INFO"].append("IPv6 enabled")

        if self.result.http_version and "HTTP/2" in self.result.http_version:
            findings["INFO"].append("HTTP/2 supported")

        if self.result.compression:
            findings["INFO"].append(f"Compression: {', '.join(self.result.compression)}")

        if self.result.additional_info and self.result.additional_info.http3_support:
            findings["INFO"].append("HTTP/3 supported (Alt-Svc header)")

        for severity in ["HIGH", "MEDIUM", "LOW", "INFO"]:
            items = findings[severity]
            if items:
                color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}[severity]
                self.console.print(f"[bold {color}]{severity}[/bold {color}]")
                for item in items:
                    self.console.print(f"  • {item}")

        if not any(findings.values()):
            self.console.print("[dim]No security findings[/dim]")

    def _display_raw_mode(self):
        """Display the actual raw HTTP request and response."""
        self.console.print("[bold]HTTP Request:[/bold]")
        method = self.result.request_method or "GET"
        url = self.result.request_url or self.result.final_url or "/"
        self.console.print(f"{method} {url} (as sent by httpx, HTTP/2+ style)")

        req_headers = self.result.request_headers or {}
        if req_headers:
            for key, value in sorted(req_headers.items()):
                self.console.print(f"{key}: {value}")
        else:
            self.console.print(f"Host: {self.result.target}")
        self.console.print()

        self.console.print("[bold]HTTP Response:[/bold]")
        if self.result.http_version and self.result.status_code is not None:
            self.console.print(f"{self.result.http_version} {self.result.status_code}")
        for key, value in sorted(self.result.all_headers.items()):
            self.console.print(f"{key}: {value}")

    def _export_markdown(self, export_dir: str):
        """Export scan results to Markdown file."""
        import os

        os.makedirs(export_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        safe_target = "".join(c if c.isalnum() or c in ".-_" else "_" for c in self.result.target)
        filename = f"{safe_target}_{timestamp}.md"
        filepath = os.path.join(export_dir, filename)

        lines = []
        lines.append(f"# NetScope Report: {self.result.target}")
        lines.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        lines.append("## Network")
        lines.append("---")
        if self.result.dns_records:
            grouped = self._group_dns_records(self.result.dns_records)
            for rtype in ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]:
                if rtype in grouped:
                    recs = grouped[rtype]
                    lines.append(f"### {rtype} Records ({len(recs)})")
                    for rec in recs:
                        lines.append(f"- {rec.value}")
                    lines.append("")

        lines.append("## HTTP")
        lines.append("---")
        if self.result.http_version:
            lines.append(f"- **Version:** {self.result.http_version}")
        if self.result.status_code is not None:
            lines.append(f"- **Status:** {self.result.status_code}")
        if self.result.response_time_ms is not None:
            lines.append(f"- **Response Time:** {self.result.response_time_ms:.2f} ms")
        if self.result.final_url:
            lines.append(f"- **Final URL:** {self.result.final_url}")
        if self.result.server_header:
            lines.append(f"- **Server:** {self.result.server_header}")
        lines.append("")

        lines.append("## TLS")
        lines.append("---")
        if self.result.tls:
            tls = self.result.tls
            if tls.version:
                lines.append(f"- **Version:** {tls.version}")
            if tls.cipher:
                lines.append(f"- **Cipher:** {tls.cipher}")
            if tls.issuer:
                lines.append(f"- **Issuer:** {tls.issuer}")
            if tls.chain_valid is not None:
                verdict = "Valid" if tls.chain_valid else f"INVALID ({tls.verify_error})"
                lines.append(f"- **Certificate:** {verdict}")
            if tls.days_remaining is not None:
                lines.append(f"- **Days Remaining:** {tls.days_remaining}")
            if tls.fingerprint:
                lines.append(f"- **Fingerprint:** `{tls.fingerprint}`")
        lines.append("")

        if self.result.security_headers:
            lines.append("## Security Headers")
            lines.append("---")
            for h in self.result.security_headers:
                status = "✅" if h.present else "❌"
                lines.append(f"- {status} **{h.name}** — {h.status}")
            lines.append("")

        if self.result.technologies:
            lines.append("## Technologies")
            lines.append("---")
            for t in self.result.technologies:
                lines.append(f"- **{t.name}** ({t.category})")
            lines.append("")

        if self.result.all_headers:
            lines.append("## Response Headers")
            lines.append("---")
            for key, value in sorted(self.result.all_headers.items()):
                lines.append(f"- `{key}`: {value}")
            lines.append("")

        if self.result.errors:
            lines.append("## Errors")
            lines.append("---")
            for err in self.result.errors:
                lines.append(f"- **{err.module}**: {err.error}")
            lines.append("")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        self.console.print(f"[green]Report exported to:[/green] {filepath}")
