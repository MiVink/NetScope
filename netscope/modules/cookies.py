"""Cookie inspection module."""

from typing import List, Iterable, Tuple
from ..models import CookieInfo


def parse_set_cookie(cookie_str: str) -> CookieInfo | None:
    """Parse a single Set-Cookie header value into CookieInfo."""
    if not cookie_str or "=" not in cookie_str.split(";")[0]:
        return None

    parts = cookie_str.split(";")
    name, sep, value = parts[0].strip().partition("=")
    if not name or not sep:
        return None

    cookie = CookieInfo(name=name, value=value)

    for part in parts[1:]:
        attr = part.strip()
        key, eq, val = attr.partition("=")
        key_l = key.strip().lower()
        val = val.strip() if eq else ""

        if key_l == "secure":
            cookie.secure = True
        elif key_l == "httponly":
            cookie.httponly = True
        elif key_l == "samesite":
            cookie.samesite = val.capitalize() if val else None
        elif key_l == "expires":
            cookie.expires = val
        elif key_l == "domain":
            cookie.domain = val.lstrip(".").lower() or None
        elif key_l == "path":
            cookie.path = val or "/"

    return cookie


def parse_headers(headers: Iterable[Tuple[str, str]]) -> List[CookieInfo]:
    """Extract cookies from a raw (name, value) header list."""
    cookies: List[CookieInfo] = []
    for name, value in headers:
        if name.lower() == "set-cookie":
            cookie = parse_set_cookie(value)
            if cookie:
                cookies.append(cookie)
    return cookies
