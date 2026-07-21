""" Security headers analysis module. """

from typing import List, Dict
from ..models import SecurityHeader


# Header definitions with explanations and risk levels
HEADER_DEFS = {
    "strict-transport-security": {
        "name": "HSTS",
        "explanation": "Forces HTTPS connections and prevents downgrade attacks",
        "risk": "high",
    },
    "content-security-policy": {
        "name": "CSP",
        "explanation": "Controls resources the browser is allowed to load",
        "risk": "high",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "explanation": "Prevents clickjacking by controlling iframe embedding",
        "risk": "medium",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "explanation": "Controls browser features and APIs",
        "risk": "medium",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "explanation": "Controls how much referrer information is sent",
        "risk": "low",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "explanation": "Prevents MIME type sniffing attacks",
        "risk": "medium",
    },
    "cross-origin-opener-policy": {
        "name": "Cross-Origin-Opener-Policy",
        "explanation": "Isolates browsing context to prevent cross-origin attacks",
        "risk": "medium",
    },
    "cross-origin-embedder-policy": {
        "name": "Cross-Origin-Embedder-Policy",
        "explanation": "Requires explicit permission for cross-origin resources",
        "risk": "medium",
    },
    "cross-origin-resource-policy": {
        "name": "Cross-Origin-Resource-Policy",
        "explanation": "Controls which sites can embed resources",
        "risk": "low",
    },
}


async def scan(headers: Dict[str, str]) -> List[SecurityHeader]:
    """Analyze security headers from response."""
    results = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for key, meta in HEADER_DEFS.items():
        present = key in headers_lower
        value = headers_lower.get(key)

        status = "present"
        if not present:
            status = "missing"
        elif key == "strict-transport-security" and "max-age" not in (value or "").lower():
            status = "weak"
        elif key == "content-security-policy" and "default-src" not in (value or "").lower():
            status = "partial"

        results.append(SecurityHeader(
            name=meta["name"],
            present=present,
            value=value,
            status=status,
            explanation=meta["explanation"],
            risk_level=meta["risk"],
        ))

    return results
