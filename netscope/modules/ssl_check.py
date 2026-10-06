"""SSL/TLS certificate inspection module."""

import socket
import ssl
import hashlib
from datetime import datetime, timezone
from cryptography import x509

from ..models import TLSInfo
from ..config import TCP_TIMEOUT, TLS_TIMEOUT


def _validate_certificate(domain: str, port: int = 443) -> tuple:
    """Second handshake with full certificate validation enabled.

    Returns (chain_valid, verify_error). chain_valid is True only when the
    default trust store accepts the chain and the hostname matches.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=TLS_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                return True, None
    except ssl.SSLCertVerificationError as e:
        return False, str(e)
    except (OSError, ssl.SSLError) as e:
        # Could not check (network/TLS problem) — not a certificate verdict
        return None, str(e)


async def scan(domain: str, port: int = 443) -> TLSInfo:
    """Analyze TLS certificate and connection with detailed extensions."""
    info = TLSInfo()

    # Inspection context: no verification, so broken/self-signed certs can be
    # examined instead of aborting. Validation happens separately below.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Allow self-signed for inspection

    try:
        with socket.create_connection((domain, port), timeout=TCP_TIMEOUT) as sock:
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
                    cert = x509.load_der_x509_certificate(cert_der)

                    # Subject / issuer (rfc4514 gives "CN=..., O=..." form)
                    info.subject = ", ".join(f"{attr.rfc4514_attribute_name}={attr.value}" for attr in cert.subject)
                    info.issuer = ", ".join(f"{attr.rfc4514_attribute_name}={attr.value}" for attr in cert.issuer)

                    # Dates — use modern UTC-aware API when available
                    try:
                        valid_from = cert.not_valid_before_utc
                        valid_until = cert.not_valid_after_utc
                    except AttributeError:
                        # Fallback for older cryptography versions
                        valid_from = cert.not_valid_before.replace(tzinfo=timezone.utc)
                        valid_until = cert.not_valid_after.replace(tzinfo=timezone.utc)

                    # Days remaining, computed against UTC (not local time)
                    info.days_remaining = (valid_until - datetime.now(timezone.utc)).days

                    info.valid_from = valid_from.replace(tzinfo=None)
                    info.valid_until = valid_until.replace(tzinfo=None)

                    # Fingerprint
                    info.fingerprint = hashlib.sha256(cert_der).hexdigest()

                # OCSP stapling / session resumption cannot be determined with
                # the Python standard library alone — not reported at all
                # rather than being shown as a false "No".
    except (OSError, ssl.SSLError) as e:
        raise RuntimeError(f"SSL error: {e}") from e

    # Separate handshake with verification enabled → real verdict on the cert
    info.chain_valid, info.verify_error = _validate_certificate(domain, port)

    return info
