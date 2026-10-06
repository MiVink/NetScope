"""Tests for robots.txt and sitemap.xml parsing."""

from netscope.modules.robots import origin_of, parse_robots
from netscope.modules.sitemap import parse_sitemap


class TestOrigin:
    def test_origin_strips_path_and_query(self):
        # Regression: robots.txt must be fetched from the origin root
        assert origin_of("https://google.com/search") == "https://google.com"
        assert origin_of("https://google.com/?q=1") == "https://google.com"
        assert origin_of("http://example.com:8080/a/b?x=1") == "http://example.com:8080"

    def test_invalid_url_raises(self):
        import pytest

        with pytest.raises(ValueError):
            origin_of("not-a-url")


class TestParseRobots:
    def test_rules_and_sitemap(self):
        content = """
        # comment line
        User-agent: *
        Disallow: /private/
        Allow: /private/public.html

        Sitemap: https://example.com/sitemap.xml
        """
        result = parse_robots(content)
        assert result["sitemap"] == "https://example.com/sitemap.xml"
        assert {"type": "disallow", "path": "/private/"} in result["rules"]
        assert {"type": "allow", "path": "/private/public.html"} in result["rules"]

    def test_inline_comment_stripped(self):
        result = parse_robots("Disallow: /tmp  # no temp files")
        assert result["rules"] == [{"type": "disallow", "path": "/tmp"}]


SITEMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
  <url><loc>https://example.com/about</loc></url>
</urlset>
"""

SITEMAP_INDEX = """<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://example.com/sitemap-1.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sitemap-2.xml</loc></sitemap>
</sitemapindex>
"""


def test_parse_sitemap_urls():
    result = parse_sitemap(SITEMAP_XML)
    assert result["url_count"] == 2
    assert result["urls"][0] == "https://example.com/"
    assert result["is_index"] is False


def test_parse_sitemap_index():
    result = parse_sitemap(SITEMAP_INDEX)
    assert result["is_index"] is True
    assert result["url_count"] == 2


def test_parse_sitemap_nonstandard_namespace():
    # Google serves a sitemapindex with a custom namespace version
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <sitemapindex xmlns="http://www.google.com/schemas/sitemap/0.84">
      <sitemap><loc>https://example.com/a.xml</loc></sitemap>
      <sitemap><loc>https://example.com/b.xml</loc></sitemap>
    </sitemapindex>"""
    result = parse_sitemap(xml)
    assert result["is_index"] is True
    assert result["url_count"] == 2
    assert result["urls"][0] == "https://example.com/a.xml"


def test_parse_sitemap_invalid_xml_falls_back():
    result = parse_sitemap("<urlset><url></url")
    assert result["exists"] is True
    assert result["url_count"] >= 0
