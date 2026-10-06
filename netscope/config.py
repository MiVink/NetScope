"""Configuration for NetScope CLI."""

# Timeouts (seconds)
DNS_TIMEOUT = 5.0
DNS_LIFETIME = 5.0
HTTP_TIMEOUT = 30.0
MODULE_TIMEOUT = 15.0  # generic per-module watchdog
TCP_TIMEOUT = 10.0
TLS_TIMEOUT = 10.0
GEOIP_TIMEOUT = 5.0

# Retry settings
MAX_RETRIES = 3
RETRY_BACKOFF = 0.5  # seconds, multiplied by attempt number

# Content limits
MAX_BODY_SIZE = 100_000  # bytes for technology detection
MAX_SITEMAP_SIZE = 5_000_000  # bytes for sitemap parsing
MAX_REDIRECTS = 10
