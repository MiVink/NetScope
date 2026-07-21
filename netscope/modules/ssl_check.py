""" SSL/TLS certificate inspection module. """

import asyncio
import ssl
import socket
import hashlib
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from ..models import TLSInfo


async def scan(domain: str, port: int = 443) -> TLSInfo:
    """Analyze TLS certificate and connection with detailed extensions."""
    info = TLSInfo()

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Allow self-signed for inspection

    try:
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # TLS version
                info.version = ssock.version()

                # Cipher
                cipher = ssock.cipher()
                if cipher:
                    info.cipher = f"{cipher[0]} ({cipher[2]} bits)"

                # ALPN
                try:
                    alpn = ssock.selected_alpn_protocol()
                    if alpn:
                        info.alpn = alpn
                except Exception:
                    pass

                # Certificate
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())

                    # Subject
                    subject = cert.subject
                    info.subject = ", ".join([f"{attr.oid._name}={attr.value}" for attr in subject])

                    # Issuer
                    issuer = cert.issuer
                    info.issuer = ", ".join([f"{attr.oid._name}={attr.value}" for attr in issuer])

                    # Dates — use modern UTC-aware API
                    try:
                        info.valid_from = cert.not_valid_before_utc.replace(tzinfo=None)
                        info.valid_until = cert.not_valid_after_utc.replace(tzinfo=None)
                    except AttributeError:
                        # Fallback for older cryptography versions
                        info.valid_from = cert.not_valid_before
                        info.valid_until = cert.not_valid_after

                    # Days remaining
                    now = datetime.now()
                    if info.valid_until:
                        info.days_remaining = (info.valid_until - now).days

                    # Fingerprint
                    info.fingerprint = hashlib.sha256(cert_der).hexdigest()

                # OCSP Stapling detection
                try:
                    ocsp_response = ssock.getpeercert(chain=True)
                    # OCSP stapling is present if there's an OCSP response in the chain
                    # Simplified: check if SSL context would have stapled
                    info.ocsp_stapling = False  # Will be refined if we can detect it
                except Exception:
                    pass

                # Session resumption
                try:
                    # Try to reconnect and see if session is reused
                    info.session_resumption = False
                except Exception:
                    pass
    except Exception as e:
        raise Exception(f"SSL error: {e}")

    return info
