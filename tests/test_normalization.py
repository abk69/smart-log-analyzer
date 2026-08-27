"""Tests for request normalization used by web detectors."""

from analyzer.normalization import normalize_request


def test_preserves_original():
    original = "/search?q=%3Cscript%3E"
    result = normalize_request(original)
    assert result.original == original
    assert result.normalized != original


def test_url_decode_and_lowercase():
    result = normalize_request("/x?id=1%20OR%201=1")
    assert "or 1=1" in result.normalized


def test_html_unescape():
    result = normalize_request("/x?q=&lt;script&gt;")
    assert "<script>" in result.normalized


def test_whitespace_collapse():
    result = normalize_request("/x?q=UNION\t\tSELECT")
    assert "union select" in result.normalized


def test_bounded_double_encoding():
    # %253C -> %3C on first pass -> < on second
    result = normalize_request("/x?q=%253Cscript%253E", max_decode_passes=2)
    assert "<script>" in result.normalized
