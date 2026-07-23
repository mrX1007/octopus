#!/usr/bin/env python3
"""Regression tests for the optional DuckDuckGo search dependency."""

import pytest

pytestmark = pytest.mark.contract


def test_web_search_reports_missing_dependency(monkeypatch):
    import search

    monkeypatch.setattr(search, "DDGS", None)
    result = search.web_search("example")

    assert "dependency unavailable" in result.lower()
    assert "ddgs" in result


def test_web_search_formats_ddgs_results(monkeypatch):
    import search

    class FakeDDGS:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def text(self, query, max_results):
            assert query == "example"
            assert max_results == 1
            return [{
                "title": "Example title",
                "href": "https://example.test",
                "body": "Example body",
            }]

    monkeypatch.setattr(search, "DDGS", FakeDDGS)
    result = search.web_search("example", max_results=1)

    assert "Example title" in result
    assert "https://example.test" in result
    assert "Example body" in result
