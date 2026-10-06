"""WHOIS lookup module."""

import asyncio
from datetime import datetime
from typing import Optional

from ..models import WhoisInfo
from ..config import RETRY_BACKOFF


def _parse_date(d) -> Optional[datetime]:
    """Normalize python-whois date values (datetime, str or list)."""
    if isinstance(d, list):
        d = d[0] if d else None
    if isinstance(d, datetime):
        return d
    if isinstance(d, str):
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d-%b-%Y", "%Y.%m.%d"):
            try:
                return datetime.strptime(d.strip(), fmt)
            except ValueError:
                continue
    return None


def _query(domain: str) -> dict:
    """Blocking WHOIS query, executed in a worker thread."""
    import whois

    w = whois.whois(domain)

    data = {
        "registrar": getattr(w, "registrar", None),
        "creation_date": getattr(w, "creation_date", None),
        "expiration_date": getattr(w, "expiration_date", None),
        "name_servers": getattr(w, "name_servers", None),
    }

    if isinstance(data["registrar"], list):
        data["registrar"] = data["registrar"][0] if data["registrar"] else None

    ns = data["name_servers"]
    if isinstance(ns, str):
        data["name_servers"] = [ns]
    elif isinstance(ns, list):
        data["name_servers"] = [str(n).lower().rstrip(".") for n in ns]
    else:
        data["name_servers"] = []

    return data


async def scan(domain: str) -> WhoisInfo:
    """Perform WHOIS lookup (blocking library call run off the event loop)."""
    info = WhoisInfo()

    last_error: Optional[Exception] = None
    for attempt in range(1, 4):
        try:
            data = await asyncio.to_thread(_query, domain)
            info.registrar = data["registrar"] if isinstance(data["registrar"], str) else None
            info.creation_date = _parse_date(data["creation_date"])
            info.expiration_date = _parse_date(data["expiration_date"])
            info.name_servers = data["name_servers"]
            return info
        except Exception as e:
            last_error = e
            # "No match" and similar are permanent — no point retrying
            msg = str(e).lower()
            if any(p in msg for p in ("no match", "not found", "no entries", "no data found")):
                break
            if attempt < 3:
                await asyncio.sleep(RETRY_BACKOFF * attempt)

    msg = " ".join(str(last_error).split())
    if len(msg) > 200:
        msg = msg[:197] + "..."
    raise RuntimeError(msg) from last_error
