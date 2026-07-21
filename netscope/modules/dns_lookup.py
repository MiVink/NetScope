""" DNS lookup module using dnspython. """

import asyncio
import socket
from typing import List
import dns.resolver
import dns.exception

from ..models import DNSRecord, IPInfo


async def scan(domain: str, max_retries: int = 3) -> List[DNSRecord]:
    """Perform comprehensive DNS lookup with retry support."""
    records = []
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]

    for rtype in record_types:
        for attempt in range(1, max_retries + 1):
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5

                answer = resolver.resolve(domain, rtype, raise_on_no_answer=False)

                for rdata in answer:
                    value = str(rdata)
                    if rtype == "MX":
                        value = f"{rdata.preference} {rdata.exchange}"
                    elif rtype == "SOA":
                        value = f"{rdata.mname} (serial: {rdata.serial})"

                    records.append(DNSRecord(
                        type=rtype,
                        value=value,
                        ttl=answer.ttl if hasattr(answer, 'ttl') else None
                    ))
                break  # Success, no retry needed

            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer):
                # Permanent DNS errors — don't retry
                break
            except dns.exception.Timeout:
                if attempt < max_retries:
                    await asyncio.sleep(0.5 * attempt)  # Exponential backoff
                    continue
                break
            except Exception:
                break

    return records


async def get_ip_info(domain: str, max_retries: int = 3) -> IPInfo:
    """Get IP information including CDN detection."""
    info = IPInfo()

    # IPv4
    for attempt in range(1, max_retries + 1):
        try:
            answers = socket.getaddrinfo(domain, None, socket.AF_INET)
            info.ipv4 = list(set(a[4][0] for a in answers))
            break
        except socket.gaierror:
            if attempt < max_retries:
                await asyncio.sleep(0.5 * attempt)
                continue
            break
        except Exception:
            break

    # IPv6
    for attempt in range(1, max_retries + 1):
        try:
            answers = socket.getaddrinfo(domain, None, socket.AF_INET6)
            info.ipv6 = list(set(a[4][0] for a in answers))
            break
        except socket.gaierror:
            if attempt < max_retries:
                await asyncio.sleep(0.5 * attempt)
                continue
            break
        except Exception:
            break

    # CDN detection via reverse DNS of first IP
    if info.ipv4:
        try:
            hostname = socket.gethostbyaddr(info.ipv4[0])[0].lower()
            cdn_signatures = {
                "cloudflare": "Cloudflare",
                "akamai": "Akamai",
                "fastly": "Fastly",
                "amazonaws": "AWS CloudFront",
                "google": "Google Cloud CDN",
                "azure": "Azure CDN",
                "vercel": "Vercel",
                "netlify": "Netlify",
                "github": "GitHub Pages",
            }
            for sig, name in cdn_signatures.items():
                if sig in hostname:
                    info.cdn = name
                    break
        except Exception:
            pass

    # Country detection (simplified via IP geolocation API)
    if info.ipv4:
        for attempt in range(1, max_retries + 1):
            try:
                import urllib.request
                import json
                req = urllib.request.Request(
                    f"https://ipapi.co/{info.ipv4[0]}/json/",
                    headers={"User-Agent": "NetScope/1.0"},
                    method="GET"
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read())
                    info.country = data.get("country_name") or data.get("country")
                    info.provider = data.get("org")
                    info.asn = data.get("asn")
                break
            except Exception:
                if attempt < max_retries:
                    await asyncio.sleep(0.5 * attempt)
                    continue
                break

    return info
