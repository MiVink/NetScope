""" Utility functions """

import re
import time
import functools
from urllib.parse import urlparse
from typing import Optional, Tuple, Callable, Any


def normalize_target(target: str) -> Tuple[str, str, bool]:
    """
    Normalize user input to extract domain and scheme.
    Accepts: domain.com, http://domain.com, https://domain.com/path?query
    Returns: (domain, full_url_for_requests, is_https)
    """
    target = target.strip()

    # If no scheme, assume https
    if not target.startswith(("http://", "https://")):
        domain = target.split("/")[0].split(":")[0]
        full_url = f"https://{target}"
        is_https = True
    else:
        parsed = urlparse(target)
        domain = parsed.hostname or parsed.netloc
        full_url = target if target.startswith("http") else f"https://{target}"
        is_https = parsed.scheme == "https" or not parsed.scheme

    # Clean domain (remove www. prefix for DNS lookups but keep for HTTP)
    clean_domain = domain.lower().lstrip("www.")

    return clean_domain, full_url, is_https


def format_timestamp() -> str:
    """Return current time in [HH:MM:SS] format."""
    from datetime import datetime
    return datetime.now().strftime("[%H:%M:%S]")


def risk_color(level: str) -> str:
    """Return color name for risk level."""
    mapping = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "red",
        "info": "blue",
    }
    return mapping.get(level.lower(), "white")


def truncate_string(s: str, max_len: int = 80) -> str:
    """Truncate string with ellipsis."""
    if len(s) <= max_len:
        return s
    return s[:max_len - 3] + "..."


def with_retry(max_retries: int = 3, retryable_exceptions: Tuple[type, ...] = (Exception,)):
    """Decorator for automatic retry logic with transient error handling."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(1, max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except retryable_exceptions as e:
                    last_exception = e
                    error_str = str(e).lower()

                    # Don't retry permanent errors
                    permanent_errors = [
                        "nxdomain", "noanswer", "nonameservers",
                        "nodename", "name or service not known",
                        "invalid", "not found", "refused",
                    ]
                    if any(pe in error_str for pe in permanent_errors):
                        raise

                    if attempt < max_retries:
                        # Log retry will be handled by caller
                        pass
                    else:
                        raise
            raise last_exception
        return wrapper
    return decorator


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
