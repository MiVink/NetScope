""" Cookie inspection module. """

import httpx
from typing import List
from ..models import CookieInfo


async def scan(url: str) -> List[CookieInfo]:
    """Inspect cookies from HTTP response."""
    cookies = []

    async with httpx.AsyncClient(follow_redirects=True, timeout=30.0, http2=True) as client:
        response = await client.get(url)

    # Parse Set-Cookie headers
    set_cookie_headers = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
    if not set_cookie_headers:
        # Fallback for httpx
        raw_cookies = response.headers.get("set-cookie", "")
        if raw_cookies:
            set_cookie_headers = [raw_cookies]

    for cookie_str in set_cookie_headers:
        if not cookie_str:
            continue

        parts = cookie_str.split(";")
        name_value = parts[0].strip()
        name = name_value.split("=")[0] if "=" in name_value else name_value

        cookie = CookieInfo(name=name)

        for part in parts[1:]:
            part = part.strip().lower()
            if part.startswith("secure"):
                cookie.secure = True
            elif part.startswith("httponly"):
                cookie.httponly = True
            elif part.startswith("samesite="):
                cookie.samesite = part.split("=")[1].capitalize()
            elif part.startswith("expires="):
                cookie.expires = part.split("=", 1)[1]
            elif part.startswith("domain="):
                cookie.domain = part.split("=", 1)[1]

        cookies.append(cookie)

    return cookies
