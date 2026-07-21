""" HTTP information gathering module with precise timing. """

import asyncio
import time
import httpx

from ..models import RedirectInfo


async def scan(url: str) -> dict:
    """Fetch HTTP information with precise timing breakdown."""
    headers = {
        "User-Agent": "NetScope/1.0 (Web Inspector)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }

    # Use httpx with http2 for accurate protocol detection
    # For precise TTFB, we measure time to first byte of response headers

    total_start = time.perf_counter()
    ttfb_ms = None
    download_ms = None

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=30.0,
        headers=headers,
        http2=True,
    ) as client:
        # Stream the response to measure TTFB accurately
        async with client.stream("GET", url) as response:
            # TTFB = time until first byte of response headers received
            ttfb_end = time.perf_counter()
            ttfb_ms = (ttfb_end - total_start) * 1000

            # Read the body
            content = b""
            async for chunk in response.aiter_bytes():
                content += chunk

            total_end = time.perf_counter()
            total_ms = (total_end - total_start) * 1000
            download_ms = max(0, total_ms - ttfb_ms)

    # Detect HTTP version
    http_version = "HTTP/1.1"
    if hasattr(response, "http_version"):
        version_raw = response.http_version
        if version_raw == "HTTP/2":
            http_version = "HTTP/2"
        elif version_raw == "HTTP/1.1":
            http_version = "HTTP/1.1"

    # Extract additional info from headers
    all_headers = dict(response.headers)

    return {
        "http_version": http_version,
        "status_code": response.status_code,
        "response_time_ms": total_ms,
        "ttfb_ms": ttfb_ms,
        "download_ms": download_ms,
        "final_url": str(response.url),
        "server": all_headers.get("server"),
        "content_length": len(content),
        "content_type": all_headers.get("content-type"),
        "headers": all_headers,
        "content_encoding": all_headers.get("content-encoding"),
        "transfer_encoding": all_headers.get("transfer-encoding"),
        "keep_alive": all_headers.get("keep-alive"),
        "alt_svc": all_headers.get("alt-svc"),
    }
