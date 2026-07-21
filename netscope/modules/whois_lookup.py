""" WHOIS lookup module. """

import asyncio
from datetime import datetime
from ..models import WhoisInfo


async def scan(domain: str) -> WhoisInfo:
    """Perform WHOIS lookup."""
    info = WhoisInfo()

    try:
        import whois
        w = whois.whois(domain)

        info.registrar = w.registrar if hasattr(w, "registrar") else None
        if isinstance(info.registrar, list):
            info.registrar = info.registrar[0] if info.registrar else None

        # Handle dates
        def parse_date(d):
            if isinstance(d, list):
                d = d[0]
            if isinstance(d, datetime):
                return d
            if isinstance(d, str):
                for fmt in ["%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d-%b-%Y"]:
                    try:
                        return datetime.strptime(d, fmt)
                    except ValueError:
                        continue
            return None

        if hasattr(w, "creation_date"):
            info.creation_date = parse_date(w.creation_date)
        if hasattr(w, "expiration_date"):
            info.expiration_date = parse_date(w.expiration_date)
        if hasattr(w, "name_servers"):
            ns = w.name_servers
            if isinstance(ns, list):
                info.name_servers = [str(n).lower().rstrip(".") for n in ns]
            else:
                info.name_servers = [str(ns).lower().rstrip(".")]
    except Exception as e:
        raise Exception(f"WHOIS lookup failed: {e}")

    return info
