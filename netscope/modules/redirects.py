""" Redirect chain analysis module. """

import httpx
from typing import List
from ..models import RedirectInfo


async def scan(url: str) -> List[RedirectInfo]:
    """Trace redirect chain."""
    chain = []

    async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as client:
        current_url = url
        step = 0

        for _ in range(10):  # Max 10 redirects
            try:
                response = await client.get(current_url)
                chain.append(RedirectInfo(
                    step=step,
                    url=str(current_url),
                    status_code=response.status_code
                ))

                if response.status_code in (301, 302, 307, 308, 303):
                    location = response.headers.get("location")
                    if location:
                        from urllib.parse import urljoin
                        current_url = urljoin(current_url, location)
                        step += 1
                    else:
                        break
                else:
                    break
            except Exception:
                break

    return chain
