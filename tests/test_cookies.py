"""Tests for cookie parsing (netscope.modules.cookies)."""

from netscope.modules.cookies import parse_set_cookie, parse_headers


def test_basic_cookie():
    c = parse_set_cookie("session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax")
    assert c is not None
    assert c.name == "session"
    assert c.value == "abc123"
    assert c.path == "/"
    assert c.httponly is True
    assert c.secure is True
    assert c.samesite == "Lax"


def test_samesite_none_stays_none():
    c = parse_set_cookie("id=1; SameSite=None")
    assert c.samesite == "None"


def test_flags_case_insensitive():
    c = parse_set_cookie("id=1; secure; HTTPONLY")
    assert c.secure is True
    assert c.httponly is True


def test_domain_and_expires():
    c = parse_set_cookie("id=1; Domain=.Example.COM; Expires=Wed, 21 Oct 2026 07:28:00 GMT")
    assert c.domain == "example.com"
    assert c.expires is not None


def test_invalid_cookie_returns_none():
    assert parse_set_cookie("") is None
    assert parse_set_cookie("novalue") is None


def test_parse_headers_picks_only_set_cookie():
    headers = [
        ("content-type", "text/html"),
        ("set-cookie", "a=1"),
        ("Set-Cookie", "b=2"),
    ]
    cookies = parse_headers(headers)
    assert [c.name for c in cookies] == ["a", "b"]
