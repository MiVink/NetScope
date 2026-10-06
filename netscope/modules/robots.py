"""robots.txt analysis module."""

import httpx
from typing import Dict, Any
from urllib.parse import urlsplit

from ..config import MODULE_TIMEOUT


def origin_of(url: str) -> str:
    """Return scheme://host[:port] — robots.txt lives at the origin root."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"Cannot determine origin from URL: {url!r}")
    return f"{parts.scheme}://{parts.netloc}"


def parse_robots(content: str) -> Dict[str, Any]:
    """Parse robots.txt content into rules + sitemap reference."""
    rules = []
    sitemap = None

    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()  # strip comments
        if not line:
            continue
        lower = line.lower()
        if lower.startswith("disallow:"):
            rules.append({"type": "disallow", "path": line.split(":", 1)[1].strip()})
        elif lower.startswith("allow:"):
            rules.append({"type": "allow", "path": line.split(":", 1)[1].strip()})
        elif lower.startswith("sitemap:"):
            sitemap = line.split(":", 1)[1].strip()

    return {"rules": rules, "sitemap": sitemap}


async def scan(domain: str, base_url: str) -> Dict[str, Any]:
    """Fetch and parse robots.txt from the origin root."""
    result = {"exists": False, "rules": [], "sitemap": None}

    robots_url = f"{origin_of(base_url)}/robots.txt"

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=MODULE_TIMEOUT) as client:
            response = await client.get(robots_url)

        if response.status_code == 200:
            content = response.text
            # Soft-404 guard: many servers return an HTML page with 200
            stripped = content.lstrip()[:200].lower()
            if stripped.startswith("<!doctype html") or stripped.startswith("<html"):
                return result

            result["exists"] = True
            parsed = parse_robots(content)
            result["rules"] = parsed["rules"]
            result["sitemap"] = parsed["sitemap"]
    except Exception:
        pass

    return result
