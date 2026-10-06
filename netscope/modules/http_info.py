"""HTTP information gathering module with precise timing."""

import time
import httpx

from ..config import HTTP_TIMEOUT


async def scan(url: str) -> dict:
    """Fetch HTTP information with precise timing breakdown.

    Note: ttfb_ms is measured from the moment the request is issued and
    therefore includes connection establishment (and TLS for https).
    """
    headers = {
        "User-Agent": "NetScope/1.0 (Web Inspector)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }

    total_start = time.perf_counter()
    ttfb_ms = None
    download_ms = None
    total_ms = None
    content = b""
    response = None

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=HTTP_TIMEOUT,
        headers=headers,
        http2=True,
    ) as client:
        # Stream the response so timing reflects headers vs. body separately
        async with client.stream("GET", url) as response:
            # First byte of response headers received
            ttfb_end = time.perf_counter()
            ttfb_ms = (ttfb_end - total_start) * 1000

            # Read the body
            async for chunk in response.aiter_bytes():
                content += chunk

            total_end = time.perf_counter()
            total_ms = (total_end - total_start) * 1000
            download_ms = max(0, total_ms - ttfb_ms)

    if response is None:  # pragma: no cover - stream always binds it
        raise RuntimeError("No HTTP response received")

    # Detect HTTP version (httpx reports "HTTP/1.1", "HTTP/2", "HTTP/3")
    version_raw = getattr(response, "http_version", "") or ""
    http_version = version_raw if version_raw.startswith("HTTP/") else "HTTP/1.1"

    all_headers = dict(response.headers)

    # Actual request as sent (used by --raw display)
    request = response.request
    request_headers = dict(request.headers)

    # Prefer the declared Content-Length; fall back to the decoded body size
    declared_length = all_headers.get("content-length")
    try:
        content_length = int(declared_length) if declared_length is not None else len(content)
    except (TypeError, ValueError):
        content_length = len(content)

    return {
        "http_version": http_version,
        "status_code": response.status_code,
        "response_time_ms": total_ms,
        "ttfb_ms": ttfb_ms,
        "download_ms": download_ms,
        "final_url": str(response.url),
        "server": all_headers.get("server"),
        "content_length": content_length,
        "body_bytes": len(content),
        "content_type": all_headers.get("content-type"),
        "headers": all_headers,
        "headers_list": response.headers.multi_items(),
        "content_encoding": all_headers.get("content-encoding"),
        "transfer_encoding": all_headers.get("transfer-encoding"),
        "keep_alive": all_headers.get("keep-alive"),
        "alt_svc": all_headers.get("alt-svc"),
        "request_method": request.method,
        "request_url": str(request.url),
        "request_headers": request_headers,
    }
