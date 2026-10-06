"""HTTP compression detection module."""

import httpx
from typing import List

from ..config import MODULE_TIMEOUT


async def scan(url: str) -> List[str]:
    """Detect supported compression methods via Accept-Encoding negotiation."""
    supported = []
    encodings = ["gzip", "deflate", "br", "zstd"]
    display = {"br": "brotli"}

    async with httpx.AsyncClient(follow_redirects=True, timeout=MODULE_TIMEOUT) as client:
        for enc in encodings:
            try:
                response = await client.get(url, headers={"Accept-Encoding": enc})
                # Server answers with exactly the encoding it used (or none)
                applied = [
                    e.strip().lower() for e in response.headers.get("content-encoding", "").split(",") if e.strip()
                ]
                if enc in applied:
                    supported.append(display.get(enc, enc))
            except Exception:
                continue

    # Preserve order, drop duplicates
    return list(dict.fromkeys(supported))
