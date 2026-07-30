"""Complete offline coverage for search, lookup, and page parsing helpers."""

from __future__ import annotations

import builtins
import importlib.util
import runpy
import sys
from datetime import datetime
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import ClassVar

import pytest
import requests

import search

pytestmark = pytest.mark.unit


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_optional_imports_support_modern_legacy_and_missing_search_dependencies(monkeypatch) -> None:
    path = Path(search.__file__)
    modern = ModuleType("ddgs")
    modern.DDGS = type("ModernDDGS", (), {})
    bs4 = ModuleType("bs4")
    bs4.BeautifulSoup = object
    monkeypatch.setitem(sys.modules, "ddgs", modern)
    monkeypatch.setitem(sys.modules, "bs4", bs4)
    loaded = _load(path, "search_with_modern_dependencies")
    assert loaded.DDGS is modern.DDGS
    assert loaded.BeautifulSoup is object

    legacy = ModuleType("duckduckgo_search")
    legacy.DDGS = type("LegacyDDGS", (), {})
    monkeypatch.setitem(sys.modules, "duckduckgo_search", legacy)
    real_import = builtins.__import__

    def missing_modern(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "ddgs":
            raise ImportError("modern search unavailable")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", missing_modern)
    loaded = _load(path, "search_with_legacy_dependency")
    assert loaded.DDGS is legacy.DDGS

    def missing_all_optional(name, globals=None, locals=None, fromlist=(), level=0):
        if name in {"bs4", "ddgs", "duckduckgo_search"}:
            raise ImportError(f"{name} unavailable")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", missing_all_optional)
    loaded = _load(path, "search_without_optional_dependencies")
    assert loaded.DDGS is None
    assert loaded.BeautifulSoup is None


def test_resilient_session_configures_retries_adapters_and_user_agent(monkeypatch) -> None:
    session = SimpleNamespace(mounts=[], headers={})
    session.mount = lambda prefix, adapter: session.mounts.append((prefix, adapter))
    retry_calls = []
    adapter_calls = []
    monkeypatch.setattr(search.requests, "Session", lambda: session)
    monkeypatch.setattr(
        search,
        "Retry",
        lambda **kwargs: retry_calls.append(kwargs) or "retry-policy",
    )
    monkeypatch.setattr(
        search,
        "HTTPAdapter",
        lambda **kwargs: adapter_calls.append(kwargs) or "adapter",
    )

    assert search.get_resilient_session() is session
    assert retry_calls == [
        {
            "total": 2,
            "backoff_factor": 0.5,
            "status_forcelist": [429, 500, 502, 503, 504],
            "allowed_methods": ["HEAD", "GET", "OPTIONS"],
        }
    ]
    assert adapter_calls == [{"max_retries": "retry-policy"}]
    assert session.mounts == [("http://", "adapter"), ("https://", "adapter")]
    assert "Firefox/120.0" in session.headers["User-Agent"]


class DDGS:
    results: ClassVar[list[dict[str, str]]] = []
    error = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def text(self, query, *, max_results):
        if self.error:
            raise self.error
        return self.results


def test_web_search_dependency_empty_results_success_error_and_timeout(monkeypatch) -> None:
    monkeypatch.setattr(search, "DDGS", None)
    assert "dependency unavailable" in search.web_search("query")

    monkeypatch.setattr(search, "DDGS", DDGS)
    DDGS.results = []
    DDGS.error = None
    assert search.web_search("empty") == "[!] No search results found."

    DDGS.results = [
        {"title": "One", "href": "https://one.test", "body": "First"},
        {"title": "Two", "href": "https://two.test", "body": "Second"},
    ]
    rendered = search.web_search("fixtures", max_results=2)
    assert "[1] One" in rendered and "[2] Two" in rendered

    DDGS.error = RuntimeError("search failed")
    assert search.web_search("broken") == "[!] Search failed: search failed"
    DDGS.error = None

    class NeverRunsThread:
        def __init__(self, *, target, daemon) -> None:
            self.target = target
            self.daemon = daemon

        def start(self) -> None:
            return None

        def join(self, *, timeout) -> None:
            assert timeout == 15

    import threading

    monkeypatch.setattr(threading, "Thread", NeverRunsThread)
    assert search.web_search("slow") == "[!] Search timed out after 15s for: slow"


def test_search_cve_combines_optional_nvd_data(monkeypatch) -> None:
    monkeypatch.setattr(search, "web_search", lambda query, max_results: "web")
    monkeypatch.setattr(search, "_fetch_nvd_cvss", lambda cve: "cvss")
    assert search.search_cve("CVE-2026-0001") == ("web\n\n[NVD CVSS DATA: CVE-2026-0001]\ncvss")
    monkeypatch.setattr(search, "_fetch_nvd_cvss", lambda cve: "")
    assert search.search_cve("CVE-2026-0001") == "web"


class NVDResponse:
    def __init__(self, status_code: int, payload=None, error=None) -> None:
        self.status_code = status_code
        self.payload = payload
        self.error = error

    def json(self):
        if self.error:
            raise self.error
        return self.payload


def test_nvd_lookup_handles_http_empty_metrics_versions_dates_and_errors(monkeypatch) -> None:
    responses = []
    monkeypatch.setattr(
        search,
        "session",
        SimpleNamespace(get=lambda url, timeout: responses.pop(0)),
    )

    responses.append(NVDResponse(503, {}))
    assert search._fetch_nvd_cvss("CVE-1") == ""
    responses.append(NVDResponse(200, {"vulnerabilities": []}))
    assert search._fetch_nvd_cvss("CVE-1") == ""

    for metric_name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric = {
            "cvssData": {
                "baseScore": 9.8,
                "vectorString": "VECTOR",
            },
            "baseSeverity": "CRITICAL",
            "exploitabilityScore": 3.9,
            "impactScore": 5.9,
        }
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [
                            {"lang": "de", "value": "Deutsch"},
                            {"lang": "en", "value": "English description"},
                        ],
                        "metrics": {metric_name: [metric]},
                        "published": "2026-07-29T00:00:00Z",
                    }
                }
            ]
        }
        responses.append(NVDResponse(200, payload))
        rendered = search._fetch_nvd_cvss("CVE-1")
        assert "9.8 (CRITICAL)" in rendered
        assert "English description" in rendered
        assert "Published: 2026-07-29" in rendered

    responses.append(
        NVDResponse(
            200,
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "descriptions": [{"lang": "fr", "value": "French"}],
                            "metrics": {},
                            "published": "",
                        }
                    }
                ]
            },
        )
    )
    assert search._fetch_nvd_cvss("CVE-1") == ""

    responses.append(NVDResponse(200, error=RuntimeError("invalid json")))
    assert search._fetch_nvd_cvss("CVE-1") == "  [!] NVD lookup failed: invalid json"


def test_exploit_and_fix_searches_build_expected_queries(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(
        search,
        "web_search",
        lambda query, max_results: calls.append((query, max_results)) or "result",
    )
    assert search.search_exploit("apache", "2.4.49") == "result"
    assert search.search_fix("log4shell") == "result"
    assert calls == [
        ("apache 2.4.49 exploit CVE vulnerability 2023 2024", 5),
        ("how to fix log4shell security mitigation patch", 3),
    ]


class PageResponse:
    def __init__(self, *, text="", error=None) -> None:
        self.text = text
        self.error = error

    def raise_for_status(self) -> None:
        if self.error:
            raise self.error


class Tag:
    def __init__(self) -> None:
        self.decomposed = False

    def decompose(self) -> None:
        self.decomposed = True


class Soup:
    def __init__(self, text: str) -> None:
        self.text = text
        self.tags = [Tag(), Tag()]

    def __call__(self, names):
        assert "script" in names and "footer" in names
        return self.tags

    def get_text(self, *, separator, strip):
        assert separator == "\n" and strip is True
        return self.text


def test_fetch_page_scrapling_parser_truncation_and_all_errors(monkeypatch) -> None:
    monkeypatch.setattr(search, "_fetch_with_scrapling", lambda url, max_chars: "scrapled")
    assert search.fetch_page("https://page.test", use_scrapling=True) == "scrapled"

    monkeypatch.setattr(search, "_fetch_with_scrapling", lambda url, max_chars: None)
    monkeypatch.setattr(search, "BeautifulSoup", None)
    assert "beautifulsoup4" in search.fetch_page("https://page.test", use_scrapling=True)

    soup_instances = []
    monkeypatch.setattr(
        search,
        "BeautifulSoup",
        lambda text, parser: soup_instances.append(Soup(text)) or soup_instances[-1],
    )
    monkeypatch.setattr(
        search,
        "session",
        SimpleNamespace(get=lambda url, timeout: PageResponse(text="one\n\ntwo\nthree")),
    )
    assert search.fetch_page("https://page.test", max_chars=100) == "one\ntwo\nthree"
    assert all(tag.decomposed for tag in soup_instances[-1].tags)
    assert search.fetch_page("https://page.test", max_chars=5) == "one\nt\n... [truncated at 5 chars]"

    exceptions = [
        (requests.exceptions.ConnectionError(), "Could not connect"),
        (requests.exceptions.Timeout(), "timed out"),
        (requests.exceptions.HTTPError("bad status"), "HTTP error"),
        (RuntimeError("parse failed"), "Fetch failed"),
    ]
    for exception, needle in exceptions:
        monkeypatch.setattr(
            search,
            "session",
            SimpleNamespace(get=lambda *_args, _exception=exception, **_kwargs: (_ for _ in ()).throw(_exception)),
        )
        assert needle in search.fetch_page("https://page.test")


def test_scrapling_fetch_body_fallback_truncation_status_import_and_runtime_errors(monkeypatch) -> None:
    scrapling = ModuleType("scrapling")
    pages = []

    class Fetcher:
        def fetch(self, url):
            page = pages.pop(0)
            if isinstance(page, Exception):
                raise page
            return page

    scrapling.StealthyFetcher = Fetcher
    monkeypatch.setitem(sys.modules, "scrapling", scrapling)
    body = SimpleNamespace(text=lambda **kwargs: "body\n\ntext")
    pages.append(SimpleNamespace(status=200, css_first=lambda selector: body))
    assert search._fetch_with_scrapling("https://page.test") == "body\ntext"

    pages.append(
        SimpleNamespace(
            status=200,
            css_first=lambda selector: None,
            text=lambda: "123456789",
        )
    )
    assert search._fetch_with_scrapling("https://page.test", max_chars=4) == ("1234\n... [truncated at 4 chars]")
    pages.append(SimpleNamespace(status=404))
    assert search._fetch_with_scrapling("https://page.test") is None
    pages.append(RuntimeError("browser failed"))
    assert search._fetch_with_scrapling("https://page.test") is None

    real_import = builtins.__import__

    def missing_scrapling(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "scrapling":
            raise ImportError("missing")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.delitem(sys.modules, "scrapling", raising=False)
    monkeypatch.setattr(builtins, "__import__", missing_scrapling)
    assert search._fetch_with_scrapling("https://page.test") is None


def test_searchsploit_missing_empty_success_truncation_and_error(monkeypatch) -> None:
    monkeypatch.setattr(search.shutil, "which", lambda executable: None)
    assert "not installed" in search.search_searchsploit("fixture")

    monkeypatch.setattr(search.shutil, "which", lambda executable: "/usr/bin/searchsploit")
    for stdout in ("", "No Results"):
        monkeypatch.setattr(
            search.subprocess,
            "run",
            lambda *args, _stdout=stdout, **kwargs: SimpleNamespace(stdout=_stdout),
        )
        assert "No searchsploit results" in search.search_searchsploit("fixture")

    monkeypatch.setattr(
        search.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout="short result"),
    )
    assert search.search_searchsploit("fixture") == "[SEARCHSPLOIT RESULTS]\nshort result"
    long_output = "\n".join(f"line-{index}" for index in range(25))
    monkeypatch.setattr(
        search.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=long_output),
    )
    assert search.search_searchsploit("fixture").endswith("... [TRUNCATED]")
    monkeypatch.setattr(
        search.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("failed")),
    )
    assert "searchsploit failed: failed" in search.search_searchsploit("fixture")


def test_dispatch_handles_cve_local_fallback_exception_and_explicit_searchsploit(
    monkeypatch,
    caplog,
) -> None:
    monkeypatch.setattr(search, "search_cve", lambda cve: f"cve:{cve}")
    monkeypatch.setattr(search.shutil, "which", lambda executable: "/usr/bin/searchsploit")
    monkeypatch.setattr(
        search.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout="local match " * 8),
    )
    local = search.handle_search_dispatch("details CVE-2026-12345 please")
    assert "SEARCHSPLOIT LOCAL CVE MATCH" in local and "cve:CVE-2026-12345" in local

    monkeypatch.setattr(
        search.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout="No Results"),
    )
    assert search.handle_search_dispatch("CVE-2026-12345") == "cve:CVE-2026-12345"
    monkeypatch.setattr(
        search.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("lookup failed")),
    )
    with caplog.at_level("DEBUG"):
        assert search.handle_search_dispatch("CVE-2026-12345") == "cve:CVE-2026-12345"
    assert "lookup failed" in caplog.text

    monkeypatch.setattr(search.shutil, "which", lambda executable: None)
    assert search.handle_search_dispatch("CVE-2026-12345") == "cve:CVE-2026-12345"
    monkeypatch.setattr(search, "search_searchsploit", lambda query: f"local:{query}")
    assert search.handle_search_dispatch("searchsploit apache") == "local:apache"


def test_dispatch_service_versions_keywords_fix_and_default_paths(monkeypatch, caplog) -> None:
    monkeypatch.setattr(search.shutil, "which", lambda executable: "/usr/bin/searchsploit")
    monkeypatch.setattr(
        search.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout="version match " * 8),
    )
    assert "SEARCHSPLOIT LOCAL MATCH" in search.handle_search_dispatch("OpenSSH 7.2")

    calls = []
    monkeypatch.setattr(
        search,
        "web_search",
        lambda query, max_results: calls.append((query, max_results)) or f"web:{query}",
    )
    monkeypatch.setattr(
        search.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout="No Results"),
    )
    rendered = search.handle_search_dispatch("OpenSSH 7.2 exploit")
    assert str(datetime.now().year) in rendered and "site:github.com" in rendered

    monkeypatch.setattr(
        search.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("local failed")),
    )
    with caplog.at_level("DEBUG"):
        assert "site:github.com" in search.handle_search_dispatch("OpenSSH 7.2 poc")
    assert "local failed" in caplog.text

    monkeypatch.setattr(search.shutil, "which", lambda executable: None)
    assert "site:github.com" in search.handle_search_dispatch("nginx 1.2 rce")
    monkeypatch.setattr(search, "search_fix", lambda query: f"fix:{query}")
    assert search.handle_search_dispatch("fix tls") == "fix:fix tls"
    assert search.handle_search_dispatch("general query") == "web:general query"


def test_quick_test_menu_and_main_guard_are_process_and_network_free(monkeypatch) -> None:
    monkeypatch.setattr(search, "web_search", lambda query: f"web:{query}")
    monkeypatch.setattr(search, "search_cve", lambda cve: f"cve:{cve}")
    monkeypatch.setattr(
        search,
        "fetch_page",
        lambda url, use_scrapling=False: f"page:{url}:{use_scrapling}",
    )

    cases = {
        "1": ("query", "web:query"),
        "2": ("CVE-2026-0001", "cve:CVE-2026-0001"),
        "3": ("https://page.test", "page:https://page.test:False"),
        "4": ("https://page.test", "page:https://page.test:True"),
    }
    for choice, (value, expected) in cases.items():
        answers = iter((choice, value))
        output: list[str] = []
        search._quick_test(
            lambda _prompt, answer_stream=answers: next(answer_stream),
            output.append,
        )
        assert output[-1] == expected

    output = []
    search._quick_test(lambda _prompt: "0", output.append)
    assert output[-1] == "[4] Fetch with scrapling"

    monkeypatch.setattr(builtins, "input", lambda _prompt: "0")
    runpy.run_path(str(Path(search.__file__)), run_name="__main__")
