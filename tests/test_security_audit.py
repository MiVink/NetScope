"""Tests for the security audit aggregation (scanner._display_security_audit)."""

from io import StringIO

from rich.console import Console

from netscope.models import SecurityHeader, ScanResult, TLSInfo
from netscope.scanner import NetScopeScanner

HSTS = "strict-transport-security"


def _header(name, present, value=None, status="present"):
    return SecurityHeader(name=name, present=present, value=value, status=status)


def audit(result: ScanResult, is_https=True, tls_checked=True) -> str:
    scanner = NetScopeScanner()
    scanner.result = result
    scanner.is_https = is_https
    scanner._tls_checked = tls_checked
    scanner.console = Console(file=StringIO(), width=100, force_terminal=False)
    scanner._display_security_audit()
    return scanner.console.file.getvalue()


def _base(status=200, headers=None, security_headers=None):
    return ScanResult(
        target="example.com",
        status_code=status,
        all_headers=headers or {},
        security_headers=security_headers or [],
    )


def test_missing_headers_no_response_is_skipped_not_alarming():
    out = audit(_base(headers={}))
    assert "header checks skipped" in out
    assert "Missing HSTS" not in out


def test_4xx_response_is_flagged_as_block_page():
    result = _base(status=403, headers={"content-type": "text/html"})
    result.security_headers = [_header("HSTS", False), _header("CSP", False)]
    out = audit(result)
    assert "HTTP 403" in out
    assert "Missing HSTS" in out  # findings still shown, but caveated


def test_missing_hsts_is_high_only_on_https():
    sec = [
        _header("HSTS", False),
        _header("CSP", True, "default-src 'self'"),
        _header("X-Frame-Options", True),
        _header("X-Content-Type-Options", True),
    ]
    out = audit(_base(headers={"server": "x"}, security_headers=sec), is_https=True)
    assert "Missing HSTS" in out


def test_plain_http_target_reports_no_hsts_verdict():
    sec = [
        _header("HSTS", False),
        _header("CSP", True, "default-src 'self'"),
        _header("X-Frame-Options", True),
        _header("X-Content-Type-Options", True),
    ]
    out = audit(_base(headers={"server": "x"}, security_headers=sec), is_https=False)
    assert "plain HTTP" in out
    assert "Missing HSTS" not in out


def test_tls_not_checked_is_not_reported_as_failure():
    out = audit(_base(), is_https=True, tls_checked=False)
    assert "TLS not inspected" in out
    assert "TLS handshake failed" not in out


def test_tls_checked_without_result_is_high():
    out = audit(_base(), is_https=True, tls_checked=True)
    assert "TLS handshake failed" in out


def test_expired_certificate_is_high():
    result = _base()
    result.tls = TLSInfo(
        version="TLSv1.3", days_remaining=-3, chain_valid=False, verify_error="certificate has expired"
    )
    out = audit(result)
    assert "certificate expired" in out
    assert "does not validate" in out


def test_healthy_site_reports_no_high_findings():
    sec = [
        _header(n, True, "max-age=31536000" if n == "HSTS" else "default-src 'self'")
        for n in (
            "HSTS",
            "CSP",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "Cross-Origin-Opener-Policy",
        )
    ]
    result = _base(headers={"server": "nginx"}, security_headers=sec)
    result.tls = TLSInfo(version="TLSv1.3", days_remaining=365, chain_valid=True)
    out = audit(result)
    assert "HIGH" not in out
    assert "Missing HSTS" not in out
