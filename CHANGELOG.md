# Changelog

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
