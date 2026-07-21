""" Technology detection module with evidence-based matching. """

import re
from typing import List, Dict, Tuple
from ..models import TechnologyInfo


# Technology definitions: (name, category, evidence_rules)
# Each rule is a tuple: (source, key_or_pattern, expected_value_or_pattern)
# source can be: "header", "header_contains", "body", "body_contains"
TECHNOLOGIES = [
    # ─── Servers / CDNs ───
    {
        "name": "Nginx",
        "category": "Server",
        "rules": [
            ("header", "server", r"^nginx"),
        ],
    },
    {
        "name": "Apache",
        "category": "Server",
        "rules": [
            ("header", "server", r"^apache"),
        ],
    },
    {
        "name": "IIS",
        "category": "Server",
        "rules": [
            ("header", "server", r"microsoft-iis"),
        ],
    },
    {
        "name": "LiteSpeed",
        "category": "Server",
        "rules": [
            ("header", "server", r"litespeed"),
        ],
    },
    {
        "name": "Google Web Server",
        "category": "Server",
        "rules": [
            ("header", "server", r"^gws"),
            ("header", "server", r"^gse"),
            ("header", "server", r"^google"),
        ],
    },
    {
        "name": "Cloudflare",
        "category": "CDN/WAF",
        "rules": [
            ("header", "cf-ray", r"."),
            ("header", "cf-cache-status", r"."),
            ("header", "server", r"cloudflare"),
        ],
    },
    {
        "name": "Akamai",
        "category": "CDN",
        "rules": [
            ("header", "x-akamai-transformed", r"."),
            ("header", "server", r"akamai"),
        ],
    },
    {
        "name": "Fastly",
        "category": "CDN",
        "rules": [
            ("header", "x-fastly", r"."),
            ("header", "fastly-debug-digest", r"."),
        ],
    },
    {
        "name": "AWS CloudFront",
        "category": "CDN",
        "rules": [
            ("header", "x-amz-cf-id", r"."),
            ("header", "via", r"cloudfront"),
        ],
    },
    {
        "name": "Vercel",
        "category": "Hosting",
        "rules": [
            ("header", "server", r"vercel"),
            ("header", "x-vercel-id", r"."),
            ("header", "x-vercel-cache", r"."),
        ],
    },
    {
        "name": "Netlify",
        "category": "Hosting",
        "rules": [
            ("header", "server", r"netlify"),
            ("header", "x-nf-request-id", r"."),
        ],
    },
    {
        "name": "GitHub Pages",
        "category": "Hosting",
        "rules": [
            ("header", "server", r"github\.com"),
        ],
    },

    # ─── Frameworks / Languages ───
    {
        "name": "PHP",
        "category": "Language",
        "rules": [
            ("header", "x-powered-by", r"php"),
        ],
    },
    {
        "name": "ASP.NET",
        "category": "Framework",
        "rules": [
            ("header", "x-aspnet-version", r"."),
            ("header", "x-powered-by", r"asp\.net"),
        ],
    },
    {
        "name": "Express",
        "category": "Framework",
        "rules": [
            ("header", "x-powered-by", r"express"),
        ],
    },
    {
        "name": "WordPress",
        "category": "CMS",
        "rules": [
            ("body_contains", "wp-content", None),
            ("body_contains", "wp-includes", None),
            ("header", "x-powered-by", r"wordpress"),
        ],
    },
    {
        "name": "Laravel",
        "category": "Framework",
        "rules": [
            ("header", "set-cookie", r"laravel_session"),
        ],
    },
    {
        "name": "Next.js",
        "category": "Framework",
        "rules": [
            ("header", "x-powered-by", r"next\.js"),
            ("body_contains", "__next", None),
        ],
    },
    {
        "name": "Nuxt",
        "category": "Framework",
        "rules": [
            ("header", "x-powered-by", r"nuxt"),
        ],
    },

    # ─── Frontend ───
    {
        "name": "React",
        "category": "Frontend",
        "rules": [
            ("body_contains", "data-reactroot", None),
            ("body_contains", "data-reactid", None),
            ("body_contains", "reactroot", None),
        ],
    },
    {
        "name": "Vue.js",
        "category": "Frontend",
        "rules": [
            ("body_contains", "__vue", None),
            ("body_contains", "data-v-", None),
        ],
    },
    {
        "name": "Angular",
        "category": "Frontend",
        "rules": [
            ("body_contains", "ng-version", None),
            ("body_contains", "ng-app", None),
        ],
    },
    {
        "name": "jQuery",
        "category": "Library",
        "rules": [
            ("body_contains", "jquery", None),
        ],
    },
    {
        "name": "Bootstrap",
        "category": "CSS Framework",
        "rules": [
            ("body_contains", "bootstrap", None),
        ],
    },
    {
        "name": "Tailwind CSS",
        "category": "CSS Framework",
        "rules": [
            ("body_contains", "tailwind", None),
        ],
    },

    # ─── Analytics ───
    {
        "name": "Google Analytics",
        "category": "Analytics",
        "rules": [
            ("body_contains", "google-analytics", None),
            ("body_contains", "gtag", None),
            ("body_contains", "googletagmanager", None),
        ],
    },
]


async def scan(url: str, headers: Dict[str, str], server_header: str) -> List[TechnologyInfo]:
    """Detect technologies with evidence-based matching."""
    detected = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Fetch page content for body-based detection
    page_content = ""
    try:
        import httpx
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            response = await client.get(url)
            page_content = response.text.lower()[:100000]
    except Exception:
        pass

    for tech in TECHNOLOGIES:
        evidence_list = []
        matched = False

        for rule in tech["rules"]:
            source, key, pattern = rule

            if source == "header":
                # Exact header match with regex
                header_value = headers_lower.get(key, "")
                if header_value and re.search(pattern, header_value, re.IGNORECASE):
                    evidence_list.append(f"{key}: {header_value}")
                    matched = True

            elif source == "header_contains":
                # Header contains substring
                header_value = headers_lower.get(key, "")
                if header_value and pattern.lower() in header_value.lower():
                    evidence_list.append(f"{key}: {header_value}")
                    matched = True

            elif source == "body_contains":
                # Body contains substring
                if page_content and key.lower() in page_content:
                    evidence_list.append(f"Body contains: '{key}'")
                    matched = True

        if matched:
            # Build evidence string
            evidence = "; ".join(evidence_list[:2])  # Show first 2 pieces of evidence
            detected.append(TechnologyInfo(
                name=tech["name"],
                category=tech["category"],
            ))
            # Store evidence on the object dynamically
            detected[-1].evidence = evidence

    # Remove duplicates (keep first match)
    seen = set()
    unique = []
    for t in detected:
        if t.name not in seen:
            seen.add(t.name)
            unique.append(t)

    return unique
