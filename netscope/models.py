"""Data models"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class DNSRecord:
    type: str
    value: str
    ttl: Optional[int] = None


@dataclass
class IPInfo:
    ipv4: List[str] = field(default_factory=list)
    ipv6: List[str] = field(default_factory=list)
    asn: Optional[str] = None
    provider: Optional[str] = None
    cdn: Optional[str] = None
    country: Optional[str] = None


@dataclass
class WhoisInfo:
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    name_servers: List[str] = field(default_factory=list)


@dataclass
class TLSInfo:
    version: Optional[str] = None
    cipher: Optional[str] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    days_remaining: Optional[int] = None
    fingerprint: Optional[str] = None
    alpn: Optional[str] = None
    # Certificate chain validation (None = not checked / could not check)
    chain_valid: Optional[bool] = None
    verify_error: Optional[str] = None


@dataclass
class SecurityHeader:
    name: str
    present: bool
    value: Optional[str] = None
    status: str = "missing"
    explanation: str = ""
    risk_level: str = "low"


@dataclass
class CookieInfo:
    name: str
    secure: bool = False
    httponly: bool = False
    samesite: Optional[str] = None
    expires: Optional[str] = None
    domain: Optional[str] = None
    path: Optional[str] = None
    value: Optional[str] = None


@dataclass
class RedirectInfo:
    step: int
    url: str
    status_code: int


@dataclass
class TechnologyInfo:
    name: str
    category: str
    confidence: int = 100
    evidence: Optional[str] = None


@dataclass
class ResponseTimeline:
    dns_lookup_ms: Optional[float] = None
    tcp_connect_ms: Optional[float] = None
    tls_handshake_ms: Optional[float] = None
    ttfb_ms: Optional[float] = None
    download_ms: Optional[float] = None
    total_ms: Optional[float] = None


@dataclass
class AdditionalInfo:
    keep_alive: Optional[str] = None
    http3_support: Optional[bool] = None
    alt_svc: Optional[str] = None
    content_encoding: Optional[str] = None
    transfer_encoding: Optional[str] = None


@dataclass
class ErrorLog:
    module: str
    error: str
    is_warning: bool = False


@dataclass
class ScanResult:
    target: str
    timestamp: datetime = field(default_factory=datetime.now)
    dns_records: List[DNSRecord] = field(default_factory=list)
    ip_info: Optional[IPInfo] = None
    whois: Optional[WhoisInfo] = None
    http_version: Optional[str] = None
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    final_url: Optional[str] = None
    redirect_chain: List[RedirectInfo] = field(default_factory=list)
    server_header: Optional[str] = None
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    compression: List[str] = field(default_factory=list)
    tls: Optional[TLSInfo] = None
    security_headers: List[SecurityHeader] = field(default_factory=list)
    cookies: List[CookieInfo] = field(default_factory=list)
    robots_txt: Optional[Dict[str, Any]] = None
    sitemap: Optional[Dict[str, Any]] = None
    favicon: Optional[Dict[str, Any]] = None
    technologies: List[TechnologyInfo] = field(default_factory=list)
    all_headers: Dict[str, str] = field(default_factory=dict)
    timeline: Optional[ResponseTimeline] = None
    additional_info: Optional[AdditionalInfo] = None
    errors: List[ErrorLog] = field(default_factory=list)
    # Actual request that was sent (used by --raw display)
    request_method: str = "GET"
    request_url: Optional[str] = None
    request_headers: Dict[str, str] = field(default_factory=dict)
    # Raw header list, preserving duplicates (e.g. multiple Set-Cookie)
    headers_list: List[tuple] = field(default_factory=list)
    # Page body for technology detection (bounded by MAX_BODY_SIZE)
    page_body: str = ""
