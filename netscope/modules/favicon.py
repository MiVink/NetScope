"""Favicon analysis module."""

import httpx
import hashlib
from typing import Dict, Any
from urllib.parse import urljoin

from ..config import MODULE_TIMEOUT

MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"\x00\x00\x01\x00", "ICO"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"RIFF", "WEBP"),
]

CONTENT_TYPE_MAP = {
    "image/png": "PNG",
    "image/jpeg": "JPEG",
    "image/x-icon": "ICO",
    "image/vnd.microsoft.icon": "ICO",
    "image/svg+xml": "SVG",
    "image/gif": "GIF",
    "image/webp": "WEBP",
}


def detect_file_type(content: bytes, content_type: str = "") -> str:
    """Detect file type from Content-Type header, falling back to magic bytes."""
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct in CONTENT_TYPE_MAP:
        return CONTENT_TYPE_MAP[ct]

    for magic, name in MAGIC:
        if content.startswith(magic):
            return name
    if b"<svg" in content[:512].lower():
        return "SVG"
    return "Unknown"


async def scan(domain: str, base_url: str) -> Dict[str, Any]:
    """Fetch and analyze favicon from conventional root paths."""
    result = {"exists": False, "hash": None, "file_type": None, "url": None}

    favicon_paths = ["/favicon.ico", "/favicon.png", "/favicon.svg"]

    async with httpx.AsyncClient(follow_redirects=True, timeout=MODULE_TIMEOUT) as client:
        for path in favicon_paths:
            url = urljoin(base_url, path)
            try:
                response = await client.get(url)
                if response.status_code != 200 or not response.content:
                    continue

                # Soft-404 guard: some servers return an HTML page with 200
                head = response.content[:200].lstrip().lower()
                if head.startswith(b"<!doctype html") or head.startswith(b"<html"):
                    continue

                result["exists"] = True
                result["url"] = str(response.url)
                result["hash"] = hashlib.md5(response.content).hexdigest()[:16]
                result["file_type"] = detect_file_type(response.content, response.headers.get("content-type", ""))
                break
            except Exception:
                continue

    return result
