""" sitemap.xml analysis module. """

import httpx
from typing import Dict, Any
import xml.etree.ElementTree as ET


async def scan(domain: str, base_url: str) -> Dict[str, Any]:
    """Fetch and parse sitemap.xml."""
    result = {"exists": False, "url_count": 0, "urls": []}

    sitemap_url = f"{base_url.rstrip('/')}/sitemap.xml"

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            response = await client.get(sitemap_url)

        if response.status_code == 200:
            result["exists"] = True
            content = response.text

            try:
                root = ET.fromstring(content)
                # Handle namespace
                ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                urls = root.findall(".//sm:url", ns) or root.findall(".//url")
                result["url_count"] = len(urls)
                result["urls"] = [u.find("sm:loc", ns).text if u.find("sm:loc", ns) is not None else "" for u in urls[:10]]
            except ET.ParseError:
                result["url_count"] = content.count("<url>")
    except Exception:
        pass

    return result
