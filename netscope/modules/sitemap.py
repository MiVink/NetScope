"""sitemap.xml analysis module."""

import httpx
from typing import Dict, Any
import xml.etree.ElementTree as ET

from ..config import MODULE_TIMEOUT, MAX_SITEMAP_SIZE
from .robots import origin_of


def _local_name(tag: str) -> str:
    """Return the local part of an XML tag (strip any namespace)."""
    return tag.rsplit("}", 1)[-1].lower()


def parse_sitemap(content: str) -> Dict[str, Any]:
    """Parse sitemap.xml (or sitemap index) content.

    Namespaces are matched by local tag name, so non-standard namespace
    versions (google.com uses .../0.84) are handled too.
    """
    result = {"exists": True, "url_count": 0, "urls": [], "is_index": False}

    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        # Fallback: rough count of <url> entries (namespaced or not)
        result["url_count"] = content.count("<url>") + content.count(":url>")
        return result

    root_name = _local_name(root.tag)
    if root_name == "sitemapindex":
        result["is_index"] = True

    entry_name = "sitemap" if result["is_index"] else "url"
    entries = [el for el in root.iter() if _local_name(el.tag) == entry_name]

    result["url_count"] = len(entries)

    urls = []
    for entry in entries[:10]:
        loc = next((el for el in entry.iter() if _local_name(el.tag) == "loc"), None)
        urls.append(loc.text.strip() if loc is not None and loc.text else "")
    result["urls"] = urls

    return result


async def scan(domain: str, base_url: str) -> Dict[str, Any]:
    """Fetch and parse sitemap.xml from the origin root."""
    result = {"exists": False, "url_count": 0, "urls": [], "is_index": False}

    sitemap_url = f"{origin_of(base_url)}/sitemap.xml"

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=MODULE_TIMEOUT) as client:
            async with client.stream("GET", sitemap_url) as response:
                if response.status_code != 200:
                    return result

                # Read at most MAX_SITEMAP_SIZE bytes to bound memory use
                chunks = []
                size = 0
                truncated = False
                async for chunk in response.aiter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= MAX_SITEMAP_SIZE:
                        truncated = True
                        break

                content = b"".join(chunks).decode("utf-8", errors="replace")

        result["exists"] = True
        if truncated:
            # Too large to parse reliably — report presence only
            result["url_count"] = content.count("<url>") + content.count(":url>")
            result["truncated"] = True
        else:
            result.update(parse_sitemap(content))
    except Exception:
        pass

    return result
