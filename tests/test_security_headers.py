"""Tests for security headers and favicon type detection."""

import asyncio

from netscope.modules.security_headers import scan
from netscope.modules.favicon import detect_file_type


def _run(coro):
    return asyncio.run(coro)


def test_all_missing():
    results = _run(scan({}))
    assert all(h.present is False for h in results)
    assert {h.name for h in results} >= {"HSTS", "CSP", "X-Frame-Options"}


def test_present_and_weak_hsts():
    results = _run(scan({"Strict-Transport-Security": "max-age=31536000"}))
    hsts = next(h for h in results if h.name == "HSTS")
    assert hsts.present is True
    assert hsts.status == "present"

    weak = next(h for h in _run(scan({"Strict-Transport-Security": "includeSubDomains"})) if h.name == "HSTS")
    assert weak.status == "weak"


def test_hsts_max_age_zero_is_weak():
    # max-age=0 disables HSTS — must not be reported as healthy
    results = _run(scan({"Strict-Transport-Security": "max-age=0; includeSubDomains"}))
    hsts = next(h for h in results if h.name == "HSTS")
    assert hsts.present is True
    assert hsts.status == "weak"


def test_case_insensitive_header_lookup():
    results = _run(scan({"X-FRAME-OPTIONS": "DENY"}))
    xfo = next(h for h in results if h.name == "X-Frame-Options")
    assert xfo.present is True


def test_csp_partial_when_no_default_src():
    results = _run(scan({"content-security-policy": "img-src 'self'"}))
    csp = next(h for h in results if h.name == "CSP")
    assert csp.status == "partial"


def test_favicon_type_from_magic_bytes():
    assert detect_file_type(b"\x89PNG\r\n\x1a\nrest") == "PNG"
    assert detect_file_type(b"\xff\xd8\xff\xe0rest") == "JPEG"
    assert detect_file_type(b"\x00\x00\x01\x00rest") == "ICO"


def test_favicon_type_from_content_type_header():
    assert detect_file_type(b"<svg></svg>", "image/svg+xml") == "SVG"
    assert detect_file_type(b"anything", "text/html; charset=utf-8") == "Unknown"
