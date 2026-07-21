# NetScope CLI

Web inspector for analyzing websites, technologies, security posture, and infrastructure.

## Features

- **Step-by-step scanning** — professional progress log with timestamps
- **DNS Analysis** — A, AAAA, MX, TXT, NS, SOA, CNAME with grouped output
- **IP Intelligence** — IPv4/IPv6, ASN, provider, CDN detection, country
- **WHOIS** — registrar, creation/expiration dates, name servers
- **HTTP Inspection** — version, status, response time, redirects, server header
- **TLS Analysis** — version, cipher, certificate details, ALPN, fingerprint, days remaining
- **Security Audit** — passive findings grouped by severity (HIGH / MEDIUM / LOW / INFO)
- **Cookie Analysis** — Secure, HttpOnly, SameSite flags
- **robots.txt & sitemap.xml** — parsing and analysis
- **Favicon Detection** — hash and file type
- **Technology Detection** — evidence-based matching with no false positives
- **Compression** — gzip, brotli, deflate support
- **Response Timeline** — precise DNS / TCP / TLS / TTFB / Download / Total timing
- **Additional Information** — ALPN, Keep-Alive, HTTP/3, OCSP, Alt-Svc
- **Raw Mode** — display complete HTTP request and response
- **Export** — Markdown reports with timestamp-based filenames
- **Retry Logic** — automatic retry on transient errors
- **Verbose Mode** — detailed output for deep inspection
- **Logging** — save complete scan log to file

## Requirements

- Python 3.13+
- httpx[http2]
- rich
- typer
- dnspython
- cryptography
- beautifulsoup4
- tldextract
- python-whois

Install dependencies manually:

```bash
pip install -r requirements.txt
```

## Installation

### Option 1: pip install (recommended)

```bash
git clone https://github.com/yourusername/netscope.git
cd netscope
pip install -e .
```

After installation, `netscope` is available globally:

```bash
netscope scan google.com
```

### Option 2: run without installing

```bash
git clone https://github.com/yourusername/netscope.git
cd netscope
```

Then use one of these methods:

**Via Python module:**

```bash
python -m netscope.cli scan google.com
```

**Via main.py:**

```bash
python netscope/main.py scan google.com
```

**Via direct execution:**

```bash
cd netscope
python cli.py scan google.com
```

## Usage

```bash
# Basic scan
netscope scan google.com

# Scan a full URL
netscope scan https://example.com/path

# Verbose mode (all details)
netscope scan google.com --verbose

# Raw HTTP display
netscope scan google.com --raw

# Export Markdown report
netscope scan google.com --export "./reports"

# Save scan log
netscope scan google.com --log

# Combined
netscope scan google.com --verbose --raw --export "./reports" --log
```

## Project Structure

```Structure
NetScope/                          # Repository root
├── pyproject.toml                 # Package configuration
├── README.md                      # This file
├── CHANGELOG.md                   # Version history
├── requirements.txt               # Dependencies
└── netscope/                      # Python package
    ├── __init__.py
    ├── main.py                    # Entry point
    ├── cli.py                     # CLI interface (Typer)
    ├── scanner.py                 # Main orchestrator
    ├── models.py                  # Data models
    ├── utils.py                   # Utilities (retry, timer, normalization)
    └── modules/                   # Analysis modules
        ├── __init__.py
        ├── dns_lookup.py
        ├── ssl_check.py
        ├── http_info.py
        ├── security_headers.py
        ├── cookies.py
        ├── robots.py
        ├── sitemap.py
        ├── favicon.py
        ├── compression.py
        ├── redirects.py
        ├── technologies.py
        └── whois_lookup.py
```

## License

MIT License.
