# Changelog

## [1.0.1] - 2026-10-06

### Fixed

- `lstrip("www.")` corrupted domains: `windows.com` → `indows.com`,
  `webworm.com` → `ebworm.com`. Now only a literal `www.` prefix is removed.
- Failed TCP/HTTP steps aborted the scan with **no report, no `--log` file and
  exit code 0**. The scan now always renders a (possibly partial) report,
  saves the log, and exits non-zero on failure.
- `UnicodeEncodeError` crash of `netscope version` / banners on Windows
  consoles with ANSI code pages (cp866/cp1251) — stdout/stderr are
  reconfigured to UTF-8 with replacement.
- `python netscope/main.py` raised `ImportError: attempted relative import`;
  README also documented a non-working `python cli.py` invocation.
- robots.txt / sitemap.xml were fetched from `{url}/robots.txt`, producing
  false negatives (`/search/robots.txt`) and false positives
  (`/?q=1/robots.txt`). They are now fetched from the origin root.
- Sitemap parsing failed for non-standard namespaces (Google's `.../0.84`);
  sitemap indexes and large files are now handled (size-capped).
- `--raw` displayed a fabricated request; it now shows the actual request
  (method, URL, headers) that httpx sent.
- OCSP stapling / session resumption were hardcoded to `No` — they are no
  longer reported, since they cannot be determined with the stdlib.
- Technology detection matched bare substrings (`jquery`, `bootstrap`,
  `tailwind`…) triggering false positives on plain prose; body rules are now
  regex patterns that require asset-like context.
- Soft-404 HTML pages served with HTTP 200 were reported as robots.txt /
  sitemap.xml / favicon.
- `response_time_ms == 0` / `content_length == 0` were skipped by truthiness
  checks in the report.
- DNS module swallowed all errors, reporting "0 records ✔" for NXDOMAIN.
- Blocking calls (`dnspython`, `socket.getaddrinfo`, `python-whois`,
  `urllib` GeoIP) were executed on the event loop; they now run in worker
  threads.
- Windows-only failure path in `_validate_certificate` now uses
  `TLS_TIMEOUT`; `MAX_BODY_SIZE`/`MAX_REDIRECTS`/`RETRY_BACKOFF` constants
  are actually used instead of magic numbers.
- Timeline `Total` was captured before half the scan ran; it is now measured
  over the entire scan and labelled accordingly.
- Long WHOIS registry disclaimers were dumped into the Error Summary; error
  messages are now trimmed.

### Added

- Real certificate validation (second handshake with the default trust
  store): reports `Certificate: Valid / INVALID (reason)` and raises it as a
  HIGH finding.
- Exit codes: `0` success, `1` failed scan, `2` invalid target, `130` Ctrl+C.
- Actual test suite (`tests/`, 37 tests) wired into CI; CI now installs the
  package and no longer masks test failures with `|| true`.
- `LICENSE` file (MIT), as already declared in pyproject/README.
- `netscope version` prints the real version number.
- GeoIP lookup is bounded by `GEOIP_TIMEOUT` and ignores API error payloads.

### Changed

- Removed unused dependencies `beautifulsoup4` and `tldextract`.
- `requires-python` lowered to `>=3.10`; dev extras added (`[dev]`).
- Security audit no longer claims "missing headers" when no response was
  analyzed, and only rates HSTS as HIGH for HTTPS targets (CSP is MEDIUM).
- Code formatted with `black` (line length 120) and clean under `flake8`.

## [1.0.0] - 2026-07-21

### Added

- Response Timeline with precise DNS/TCP/TLS/TTFB/Download/Total measurements
- Security Audit section with severity-grouped findings (HIGH/MEDIUM/LOW/INFO)
- Additional Information section (ALPN, Keep-Alive, HTTP/3, OCSP, Alt-Svc, etc.)
- Raw mode (`--raw`) for displaying complete HTTP request/response
- Export to Markdown (`--export`) with timestamp-based filenames
- Verbose mode (`--verbose`) for detailed output
- Logging (`--log`) to save complete scan log to `scan.log`
- Retry logic (up to 3 attempts) with exponential backoff for transient errors
- Timeout handling per module with graceful degradation
- Error Summary section listing only modules with warnings/errors
- Ctrl+C handling for clean exit without traceback
- Evidence-based technology detection to eliminate false positives
- `PreciseTimer` context manager for accurate timing measurements

### Changed

- Refactored console output: DNS records grouped by type, compact sections
- Removed all scoring systems (Security Score, Performance Rating, TLS Rating)
- Report layout redesigned with clean section headers
- Default output is now compact; verbose mode shows full details
- Technology detection now requires strong evidence per technology

### Fixed

- `CryptographyDeprecationWarning` — migrated to modern `cryptography` API
- `_log_success() got unexpected keyword argument 'style'` runtime error
- Graceful error handling: one module failure no longer terminates the scan
