"""Tests for technology detection (pure function, no network)."""

from netscope.modules.technologies import detect


def test_server_header_detected():
    techs = detect({"Server": "nginx/1.24.0"})
    assert [t.name for t in techs] == ["Nginx"]


def test_cloudflare_via_ray_header():
    techs = detect({"cf-ray": "8f3a-AMS"})
    assert "Cloudflare" in [t.name for t in techs]


def test_wordpress_body_evidence():
    techs = detect({}, body='<script src="https://site.com/wp-content/themes/x.js"></script>')
    names = [t.name for t in techs]
    assert "WordPress" in names


def test_no_false_positive_on_plain_text_mention():
    # Regression: plain prose mentioning a library must not trigger detection
    techs = detect({}, body="<p>We compared jquery, bootstrap and tailwind for this article.</p>")
    assert techs == []


def test_jquery_detected_from_asset_url():
    techs = detect({}, body='<script src="/js/jquery-3.7.1.min.js"></script>')
    assert "jQuery" in [t.name for t in techs]


def test_evidence_is_populated():
    techs = detect({"server": "apache/2.4.57"})
    assert techs and techs[0].evidence


def test_headers_case_insensitive():
    techs = detect({"X-Powered-By": "PHP/8.2"})
    assert "PHP" in [t.name for t in techs]
