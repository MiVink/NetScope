"""Tests for netscope.utils.normalize_target."""

import pytest

from netscope.utils import normalize_target, PreciseTimer, format_timestamp


class TestNormalizeTarget:
    def test_plain_domain(self):
        domain, url, is_https = normalize_target("example.com")
        assert domain == "example.com"
        assert url == "https://example.com"
        assert is_https is True

    def test_www_is_stripped_only_as_prefix(self):
        # Regression: the old lstrip("www.") turned "webworm.com" into "ebworm.com"
        assert normalize_target("www.example.com")[0] == "example.com"
        assert normalize_target("webworm.com")[0] == "webworm.com"
        assert normalize_target("windows.com")[0] == "windows.com"
        assert normalize_target("windowsupdate.com")[0] == "windowsupdate.com"
        # internal "www" must survive
        assert normalize_target("awwwwards.com")[0] == "awwwwards.com"

    def test_url_with_path_and_query(self):
        domain, url, is_https = normalize_target("https://example.com/some/path?a=1")
        assert domain == "example.com"
        assert url == "https://example.com/some/path?a=1"
        assert is_https is True

    def test_http_scheme(self):
        domain, url, is_https = normalize_target("http://example.com")
        assert domain == "example.com"
        assert url == "http://example.com"
        assert is_https is False

    def test_port_is_removed_from_domain_kept_in_url(self):
        domain, url, _ = normalize_target("example.com:8080/path")
        assert domain == "example.com"
        assert url == "https://example.com:8080/path"

    def test_uppercase_and_trailing_dot(self):
        assert normalize_target("EXAMPLE.COM.")[0] == "example.com"

    def test_invalid_targets_raise(self):
        for bad in ["", "   ", "not a domain", "https://", None]:
            with pytest.raises(ValueError):
                normalize_target(bad)

    def test_ip_address_allowed(self):
        assert normalize_target("192.168.0.1")[0] == "192.168.0.1"


def test_precise_timer():
    with PreciseTimer() as t:
        pass
    assert t.elapsed_ms is not None and t.elapsed_ms >= 0


def test_format_timestamp_shape():
    assert format_timestamp().startswith("[")
    assert format_timestamp().endswith("]")
