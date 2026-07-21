""" robots.txt analysis module. """

import httpx
from typing import Dict, Any


async def scan(domain: str, base_url: str) -> Dict[str, Any]:
    """Fetch and parse robots.txt."""
    result = {"exists": False, "rules": [], "sitemap": None}

    robots_url = f"{base_url.rstrip('/')}/robots.txt"

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            response = await client.get(robots_url)

        if response.status_code == 200:
            result["exists"] = True
            content = response.text

            for line in content.split("\n"):
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    result["rules"].append({"type": "disallow", "path": path})
                elif line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    result["rules"].append({"type": "allow", "path": path})
                elif line.lower().startswith("sitemap:"):
                    result["sitemap"] = line.split(":", 1)[1].strip()
    except Exception:
        pass

    return result
