"""Unit tests for scrapling fetch and crawl in recon_tools."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import core.tools.recon_tools as rt


class FakeTag:
    def __init__(self, text="", attrs=None):
        self._text = text
        self._attrs = attrs or {}

    def get_text(self, separator="\n", strip=True):
        return self._text

    def get(self, key, default=""):
        return self._attrs.get(key, default)

    def __getitem__(self, key):
        return self._attrs[key]

    def find_all(self, *a, **kw):
        return []

    def __call__(self, *a, **kw):
        return []


class FakeSoup(FakeTag):
    def find(self, name):
        if name == "title":
            return FakeTag("Test Page")
        return None

    def find_all(self, name, href=None):
        if name == "a":
            return [FakeTag("Link 1", {"href": "/link1"})]
        return []


@pytest.mark.unit
def test_scrapling_fetch_and_crawl():
    mock_resp = SimpleNamespace(
        status_code=200,
        text="<html><head><title>Test Page</title></head><body><h1>Hello</h1><a href='/link1'>Link 1</a></body></html>",
    )

    with patch.dict("sys.modules", {"bs4": SimpleNamespace(BeautifulSoup=FakeSoup)}):
        with patch("requests.Session") as mock_sess_cls:
            mock_sess = MagicMock()
            mock_sess.get.return_value = mock_resp
            mock_sess_cls.return_value = mock_sess

            res = rt.run_scrapling_fetch("http://example.com")
            assert "Test Page" in res or "200" in res

            with patch(
                "core.tools.recon_tools._config_section",
                return_value={"enabled": True, "timeout": 5, "max_crawl_pages": 2},
            ):
                res_crawl = rt.run_scrapling_crawl("http://example.com", max_pages=2)
                assert "SCRAPLING CRAWL" in res_crawl
