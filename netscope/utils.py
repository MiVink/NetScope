"""Utility functions"""

import re
import time
from urllib.parse import urlparse
from typing import Optional, Tuple

# A valid DNS hostname: letters, digits, hyphens and dots (no spaces, no scheme).
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$")


def normalize_target(target: str) -> Tuple[str, str, bool]:
    """
    Normalize user input to extract domain and scheme.
    Accepts: domain.com, http://domain.com, https://domain.com/path?query
    Returns: (domain, full_url_for_requests, is_https)

    Raises ValueError for empty or obviously invalid targets.
    """
    if target is None:
        raise ValueError("Target is empty")

    target = target.strip()
    if not target:
        raise ValueError("Target is empty")
    if any(c.isspace() for c in target):
        raise ValueError("Target must not contain spaces")

    # If no scheme, assume https
    if not target.startswith(("http://", "https://")):
        domain = target.split("/")[0].split(":")[0]
        full_url = f"https://{target}"
        is_https = True
    else:
        parsed = urlparse(target)
        domain = parsed.hostname or ""
        full_url = target
        is_https = parsed.scheme != "http"

    # Normalize: lowercase, drop trailing dot, drop leading "www." for DNS/TCP/TLS
    domain = (domain or "").lower().rstrip(".")
    if not domain:
        raise ValueError("Could not determine hostname from target")
    domain = re.sub(r"^www\.", "", domain)

    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid hostname: {domain!r}")

    return domain, full_url, is_https


def format_timestamp() -> str:
    """Return current time in [HH:MM:SS] format."""
    from datetime import datetime

    return datetime.now().strftime("[%H:%M:%S]")


class PreciseTimer:
    """Context manager for precise timing measurements."""

    def __init__(self):
        self.start_time: Optional[float] = None
        self.elapsed_ms: Optional[float] = None

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, *args):
        self.elapsed_ms = (time.perf_counter() - self.start_time) * 1000
