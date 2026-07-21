""" HTTP compression detection module. """

import httpx
from typing import List


async def scan(url: str) -> List[str]:
    """Detect supported compression methods."""
    supported = []

    # Check via Accept-Encoding negotiation
    encodings = ["gzip", "br", "deflate"]

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        for enc in encodings:
            try:
                headers = {"Accept-Encoding": enc}
                response = await client.get(url, headers=headers)
                ce = response.headers.get("content-encoding", "").lower()
                if enc in ce or (enc == "br" and "br" in ce):
                    supported.append(enc)
            except Exception:
                continue

    # Deduplicate and rename br -> brotli
    result = []
    for s in supported:
        if s == "br":
            result.append("brotli")
        elif s not in result:
            result.append(s)

    return result
