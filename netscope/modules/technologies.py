"""Technology detection module with evidence-based matching."""

import re
from typing import List, Dict, Optional
from ..models import TechnologyInfo
from ..config import MAX_BODY_SIZE, MODULE_TIMEOUT

# Technology definitions: (name, category, evidence rules)
# Rule sources:
#   ("header",        header_name, regex)  → regex search in header value
#   ("header_exists", header_name, None)   → header present at all
#   ("body_regex",    pattern,       None) → regex search in page body
TECHNOLOGIES = [
    # ─── Servers / CDNs ───
    {
        "name": "Nginx",
        "category": "Server",
        "rules": [("header", "server", r"^nginx")],
    },
    {
        "name": "Apache",
        "category": "Server",
        "rules": [("header", "server", r"^apache")],
    },
    {
        "name": "IIS",
        "category": "Server",
        "rules": [("header", "server", r"microsoft-iis")],
    },
    {
        "name": "LiteSpeed",
        "category": "Server",
        "rules": [("header", "server", r"litespeed")],
    },
    {
        "name": "Google Web Server",
        "category": "Server",
        "rules": [
            ("header", "server", r"^(gws|gse|google)"),
        ],
    },
    {
        "name": "Cloudflare",
        "category": "CDN/WAF",
        "rules": [
            ("header_exists", "cf-ray", None),
            ("header_exists", "cf-cache-status", None),
            ("header", "server", r"cloudflare"),
        ],
    },
    {
        "name": "Akamai",
        "category": "CDN",
        "rules": [
            ("header_exists", "x-akamai-transformed", None),
            ("header", "server", r"akamai"),
        ],
    },
    {
        "name": "Fastly",
        "category": "CDN",
        "rules": [
            ("header_exists", "x-fastly", None),
            ("header_exists", "fastly-debug-digest", None),
        ],
    },
    {
        "name": "AWS CloudFront",
        "category": "CDN",
        "rules": [
            ("header_exists", "x-amz-cf-id", None),
            ("header", "via", r"cloudfront"),
        ],
    },
    {
        "name": "Vercel",
        "category": "Hosting",
        "rules": [
            ("header", "server", r"vercel"),
            ("header_exists", "x-vercel-id", None),
            ("header_exists", "x-vercel-cache", None),
        ],
    },
    {
        "name": "Netlify",
        "category": "Hosting",
        "rules": [
            ("header", "server", r"netlify"),
            ("header_exists", "x-nf-request-id", None),
        ],
    },
    {
        "name": "GitHub Pages",
        "category": "Hosting",
        "rules": [("header", "server", r"github\.com")],
    },
    # ─── Frameworks / Languages ───
    {
        "name": "PHP",
        "category": "Language",
        "rules": [("header", "x-powered-by", r"php")],
    },
    {
        "name": "ASP.NET",
        "category": "Framework",
        "rules": [
            ("header_exists", "x-aspnet-version", None),
            ("header", "x-powered-by", r"asp\.net"),
        ],
    },
    {
        "name": "Express",
        "category": "Framework",
        "rules": [("header", "x-powered-by", r"express")],
    },
    {
        "name": "WordPress",
        "category": "CMS",
        "rules": [
            ("body_regex", r"/wp-content/|/wp-includes/", None),
            ("header", "x-powered-by", r"wordpress"),
        ],
    },
    {
        "name": "Laravel",
        "category": "Framework",
        "rules": [("header", "set-cookie", r"laravel_session")],
    },
    {
        "name": "Next.js",
        "category": "Framework",
        "rules": [
            ("header", "x-powered-by", r"next\.js"),
            ("body_regex", r"__NEXT_DATA__|/_next/static/", None),
        ],
    },
    {
        "name": "Nuxt",
        "category": "Framework",
        "rules": [
            ("header", "x-powered-by", r"nuxt"),
            ("body_regex", r"__NUXT__|/_nuxt/", None),
        ],
    },
    # ─── Frontend ───
    {
        "name": "React",
        "category": "Frontend",
        "rules": [
            ("body_regex", r"data-react(root|id)=|__REACT_DEVTOOLS", None),
        ],
    },
    {
        "name": "Vue.js",
        "category": "Frontend",
        "rules": [
            ("body_regex", r"data-v-[0-9a-f]{6,}|__vue__|Vue\.config|__VUE__", None),
        ],
    },
    {
        "name": "Angular",
        "category": "Frontend",
        "rules": [
            ("body_regex", r"ng-version=|ng-app[ =]|_nghost", None),
        ],
    },
    {
        "name": "jQuery",
        "category": "Library",
        "rules": [
            ("body_regex", r"jquery[.-]\d+\.\d+|jquery\.min\.js", None),
        ],
    },
    {
        "name": "Bootstrap",
        "category": "CSS Framework",
        "rules": [
            ("body_regex", r"bootstrap[.-]\d+\.\d+|bootstrap\.min\.(css|js)", None),
        ],
    },
    {
        "name": "Tailwind CSS",
        "category": "CSS Framework",
        "rules": [
            ("body_regex", r"cdn\.tailwindcss\.com|tailwind\.min\.css|/tailwindcss@", None),
        ],
    },
    # ─── Analytics ───
    {
        "name": "Google Analytics",
        "category": "Analytics",
        "rules": [
            ("body_regex", r"google-analytics\.com/(analytics|ga)\.js|googletagmanager\.com/gtm\.js|gtag\(", None),
        ],
    },
]


def detect(
    headers: Dict[str, str],
    body: str = "",
    extra_headers: Optional[Dict[str, str]] = None,
) -> List[TechnologyInfo]:
    """Pure, side-effect-free technology detection from headers + body."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for k, v in (extra_headers or {}).items():
        if k.lower() not in headers_lower:
            headers_lower[k.lower()] = v
    body_l = (body or "").lower()

    detected: List[TechnologyInfo] = []
    for tech in TECHNOLOGIES:
        evidence: List[str] = []

        for source, key, pattern in tech["rules"]:
            if source == "header":
                header_value = headers_lower.get(key, "")
                if header_value and re.search(pattern, header_value, re.IGNORECASE):
                    evidence.append(f"{key}: {header_value}")
            elif source == "header_exists":
                if key in headers_lower:
                    evidence.append(f"{key}: {headers_lower[key]}")
            elif source == "body_regex" and body_l:
                match = re.search(key, body_l, re.IGNORECASE)
                if match:
                    evidence.append(f"Body matches: {match.group(0)[:60]}")

        if evidence:
            detected.append(
                TechnologyInfo(
                    name=tech["name"],
                    category=tech["category"],
                    evidence="; ".join(evidence[:2]),
                )
            )

    return detected


async def scan(
    url: str,
    headers: Dict[str, str],
    server_header: str = "",
) -> List[TechnologyInfo]:
    """Fetch page content (bounded) and detect technologies."""
    page_content = ""
    try:
        import httpx

        async with httpx.AsyncClient(follow_redirects=True, timeout=MODULE_TIMEOUT) as client:
            async with client.stream("GET", url) as response:
                chunks = []
                size = 0
                async for chunk in response.aiter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= MAX_BODY_SIZE:
                        break
                page_content = b"".join(chunks).decode("utf-8", errors="replace")
    except Exception:
        pass

    extra = {"server": server_header} if server_header else None
    return detect(headers, page_content, extra_headers=extra)
