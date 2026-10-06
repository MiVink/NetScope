"""DNS lookup module using dnspython."""

import asyncio
import socket
from typing import List
import dns.resolver
import dns.exception

from ..models import DNSRecord, IPInfo
from ..config import DNS_TIMEOUT, DNS_LIFETIME, MAX_RETRIES, GEOIP_TIMEOUT, RETRY_BACKOFF


async def scan(domain: str, max_retries: int = MAX_RETRIES) -> List[DNSRecord]:
    """Perform comprehensive DNS lookup with retry support.

    NXDOMAIN is raised to the caller (it is a real finding), while
    "record type not present" is a normal, non-error condition.
    """
    records: List[DNSRecord] = []
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]
    last_error: Exception | None = None

    def _resolve(rtype: str) -> List[DNSRecord]:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_LIFETIME
        answer = resolver.resolve(domain, rtype, raise_on_no_answer=False)

        found: List[DNSRecord] = []
        ttl = answer.ttl if hasattr(answer, "ttl") else None
        for rdata in answer:
            value = str(rdata)
            if rtype == "MX":
                value = f"{rdata.preference} {rdata.exchange}"
            elif rtype == "SOA":
                value = f"{rdata.mname} (serial: {rdata.serial})"
            found.append(DNSRecord(type=rtype, value=value, ttl=ttl))
        return found

    for rtype in record_types:
        for attempt in range(1, max_retries + 1):
            try:
                # dnspython is blocking → run it off the event loop
                records.extend(await asyncio.to_thread(_resolve, rtype))
                break  # Success, no retry needed for this record type

            except dns.resolver.NXDOMAIN:
                # The domain itself does not exist — real finding, surface it
                raise
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                # Record type not present / no usable nameservers for it — normal
                break
            except (dns.exception.Timeout, OSError) as e:
                last_error = e
                if attempt < max_retries:
                    await asyncio.sleep(RETRY_BACKOFF * attempt)
                    continue
                break
            except Exception as e:  # unexpected — do not hide it
                last_error = e
                break

    if not records and last_error is not None:
        # Nothing resolved at all: surface the underlying error instead of
        # silently reporting "0 records ✔"
        raise last_error

    return records


async def get_ip_info(domain: str, max_retries: int = MAX_RETRIES) -> IPInfo:
    """Get IP information including CDN detection."""
    info = IPInfo()

    # IPv4
    for attempt in range(1, max_retries + 1):
        try:
            answers = await asyncio.to_thread(socket.getaddrinfo, domain, None, socket.AF_INET)
            info.ipv4 = list(dict.fromkeys(a[4][0] for a in answers))
            break
        except socket.gaierror:
            if attempt < max_retries:
                await asyncio.sleep(RETRY_BACKOFF * attempt)
                continue
            break
        except Exception:
            break

    # IPv6
    for attempt in range(1, max_retries + 1):
        try:
            answers = await asyncio.to_thread(socket.getaddrinfo, domain, None, socket.AF_INET6)
            info.ipv6 = list(dict.fromkeys(a[4][0] for a in answers))
            break
        except socket.gaierror:
            if attempt < max_retries:
                await asyncio.sleep(RETRY_BACKOFF * attempt)
                continue
            break
        except Exception:
            break

    # CDN detection via reverse DNS of first IP
    if info.ipv4:
        try:
            hostname = await asyncio.to_thread(socket.gethostbyaddr, info.ipv4[0])
            hostname = hostname[0].lower()
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

    # Country/ASN detection via a public IP geolocation API (best effort).
    # Failure here is never fatal and never retried aggressively: it is a
    # third-party service the user may be rate-limited by.
    if info.ipv4:

        def _geoip() -> dict:
            import urllib.request
            import json

            req = urllib.request.Request(
                f"https://ipapi.co/{info.ipv4[0]}/json/",
                headers={"User-Agent": "NetScope/1.0"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=GEOIP_TIMEOUT) as resp:
                return json.loads(resp.read())

        try:
            data = await asyncio.to_thread(_geoip)
            if isinstance(data, dict) and not data.get("error"):
                info.country = data.get("country_name") or data.get("country")
                info.provider = data.get("org")
                info.asn = data.get("asn")
        except Exception:
            pass

    return info
