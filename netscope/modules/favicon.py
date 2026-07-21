""" Favicon analysis module. """

import httpx
import hashlib
from typing import Dict, Any
from urllib.parse import urljoin


async def scan(domain: str, base_url: str) -> Dict[str, Any]:
    """Fetch and analyze favicon."""
    result = {"exists": False, "hash": None, "file_type": None, "url": None}

    favicon_paths = ["/favicon.ico", "/favicon.png", "/favicon.svg"]

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        for path in favicon_paths:
            url = urljoin(base_url, path)
            try:
                response = await client.get(url)
                if response.status_code == 200 and len(response.content) > 0:
                    result["exists"] = True
                    result["url"] = url
                    result["hash"] = hashlib.md5(response.content).hexdigest()[:16]

                    # Simple file type detection
                    content = response.content[:8]
                    if content[:4] == b"\x89PNG":
                        result["file_type"] = "PNG"
                    elif content[:2] == b"\xff\xd8":
                        result["file_type"] = "JPEG"
                    elif content[:4] == b"\x00\x00\x01\x00":
                        result["file_type"] = "ICO"
                    elif b"<svg" in response.content[:100]:
                        result["file_type"] = "SVG"
                    else:
                        result["file_type"] = "Unknown"
                    break
            except Exception:
                continue

    return result
