"""Redirect chain analysis module."""

import httpx
from typing import List
from urllib.parse import urljoin

from ..models import RedirectInfo
from ..config import MODULE_TIMEOUT, MAX_REDIRECTS


async def scan(url: str) -> List[RedirectInfo]:
    """Trace redirect chain (loop-safe, bounded by MAX_REDIRECTS)."""
    chain: List[RedirectInfo] = []
    seen: set = set()

    async with httpx.AsyncClient(follow_redirects=False, timeout=MODULE_TIMEOUT) as client:
        current_url = url

        for step in range(MAX_REDIRECTS + 1):
            if current_url in seen:
                break  # redirect loop
            seen.add(current_url)

            try:
                response = await client.get(current_url)
            except Exception:
                if not chain:
                    raise  # the first request failing is a real error
                break

            chain.append(
                RedirectInfo(
                    step=step,
                    url=str(current_url),
                    status_code=response.status_code,
                )
            )

            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location")
                if not location:
                    break
                current_url = urljoin(current_url, location)
            else:
                break

    return chain
