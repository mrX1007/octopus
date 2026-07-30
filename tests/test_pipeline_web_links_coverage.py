"""Focused branch coverage for the stateless web-link pipeline helpers."""

from __future__ import annotations

import pytest

from core.ai.pipeline_web_links import PipelineWebLinksMixin

pytestmark = pytest.mark.unit


class WebLinksHarness(PipelineWebLinksMixin):
    """Supply the three collaborators owned by the concrete pipeline."""

    def __init__(
        self,
        *,
        endpoints: list[str] | None = None,
        target_host: str = "example.test",
        limits: dict[str, int | None] | None = None,
    ) -> None:
        self.endpoints = list(endpoints or [])
        self.target_host = target_host
        self.limits = dict(limits or {})
        self.limit_calls: list[tuple[str, int | None]] = []

    def _web_endpoints_from_facts(self, scan_id: str, target: str) -> list[str]:
        assert scan_id
        assert target or not self.target_host
        return list(self.endpoints)

    def _target_host(self, target: str) -> str:
        del target
        return self.target_host

    def _strategy_limit(self, name: str, default: int | None) -> int | None:
        self.limit_calls.append((name, default))
        return self.limits.get(name, default)


def test_web_path_actions_filter_facts_and_use_target_fallback() -> None:
    pipeline = WebLinksHarness(endpoints=[])
    facts = [
        {"type": "service", "value": "/ignored:200"},
        {"type": "web_path", "value": "/:200"},
        {"type": "web_path", "value": "/ordinary:404"},
        {"type": "web_path", "value": "/admin:404"},
        {"type": "web_path", "value": "healthy:200"},
    ]

    assert pipeline._web_path_action_commands("scan-1", "https://example.test:8443/root", facts) == [
        "curl_headers http://example.test/admin",
        "scrapling http://example.test/admin",
        "curl_headers http://example.test/healthy",
        "scrapling http://example.test/healthy",
    ]
    assert pipeline.limit_calls == [
        ("web_path_followup_commands", None),
        ("web_path_followup_commands", None),
    ]


def test_web_path_actions_use_discovered_endpoint_and_stop_at_limit() -> None:
    pipeline = WebLinksHarness(
        endpoints=["https://example.test:9443/base/"],
        limits={"web_path_followup_commands": 2},
    )

    assert pipeline._web_path_action_commands(
        "scan-2",
        "example.test",
        [
            {"type": "web_path", "value": "/login:403"},
            {"type": "web_path", "value": "/admin:200"},
        ],
    ) == [
        "curl_headers https://example.test:9443/base/login",
        "scrapling https://example.test:9443/base/login",
    ]


def test_web_link_actions_emit_every_specialized_command(monkeypatch: pytest.MonkeyPatch) -> None:
    pipeline = WebLinksHarness()
    urls = [
        "https://example.test/static/app.js",
        "https://example.test/openapi.json",
        "https://example.test/graphql",
        "https://example.test/account",
    ]
    monkeypatch.setattr(pipeline, "_normalized_web_link_urls", lambda *_args: urls)

    assert pipeline._web_link_action_commands("scan-3", "example.test", []) == [
        "js_route_extract https://example.test/static/app.js",
        "curl_headers https://example.test/openapi.json",
        "scrapling https://example.test/openapi.json",
        "openapi_import https://example.test/openapi.json",
        "curl_headers https://example.test/graphql",
        "scrapling https://example.test/graphql",
        "graphql_check https://example.test/graphql",
        "curl_headers https://example.test/account",
        "scrapling https://example.test/account",
    ]


@pytest.mark.parametrize(
    ("url", "limit", "expected"),
    [
        (
            "https://example.test/app.js",
            1,
            ["js_route_extract https://example.test/app.js"],
        ),
        (
            "https://example.test/account",
            1,
            ["curl_headers https://example.test/account"],
        ),
        (
            "https://example.test/account",
            2,
            [
                "curl_headers https://example.test/account",
                "scrapling https://example.test/account",
            ],
        ),
        (
            "https://example.test/openapi.json",
            3,
            [
                "curl_headers https://example.test/openapi.json",
                "scrapling https://example.test/openapi.json",
                "openapi_import https://example.test/openapi.json",
            ],
        ),
        (
            "https://example.test/graphql",
            3,
            [
                "curl_headers https://example.test/graphql",
                "scrapling https://example.test/graphql",
                "graphql_check https://example.test/graphql",
            ],
        ),
    ],
)
def test_web_link_actions_stop_at_each_command_boundary(
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    limit: int,
    expected: list[str],
) -> None:
    pipeline = WebLinksHarness(limits={"web_link_followup_commands": limit})
    monkeypatch.setattr(pipeline, "_normalized_web_link_urls", lambda *_args: [url])

    assert pipeline._web_link_action_commands("scan-4", "example.test", []) == expected


def test_normalized_urls_filter_and_deduplicate_relative_and_absolute_links() -> None:
    pipeline = WebLinksHarness(endpoints=[], target_host="Example.Test")
    facts = [
        {"type": "service", "value": "/ignored"},
        {"type": "web_link", "value": "#ignored"},
        {"type": "web_link", "value": "/admin"},
        {"type": "web_link", "value": "/admin"},
        {"type": "web_link", "value": "https://outside.test/admin"},
        {"type": "web_link", "value": "//example.test/api"},
    ]

    assert pipeline._normalized_web_link_urls("scan-5", "Example.Test", facts) == [
        "http://example.test/admin",
        "http://example.test/api",
    ]


def test_normalized_urls_handle_missing_hosts_and_each_endpoint() -> None:
    no_host = WebLinksHarness(endpoints=[], target_host="")
    assert no_host._normalized_web_link_urls("scan-6", "", []) == []

    multiple_endpoints = WebLinksHarness(
        endpoints=["https://example.test/base/", "relative-base"],
        target_host="",
    )
    assert multiple_endpoints._normalized_web_link_urls(
        "scan-7",
        "target-without-host",
        [{"type": "web_link", "value": "reports"}],
    ) == ["https://example.test/base/reports"]


def test_normalized_urls_stop_at_configured_limit() -> None:
    pipeline = WebLinksHarness(
        endpoints=["https://example.test"],
        target_host="",
        limits={"web_link_url_limit": 1},
    )

    assert pipeline._normalized_web_link_urls(
        "scan-8",
        "target-without-host",
        [
            {"type": "web_link", "value": "/admin"},
            {"type": "web_link", "value": "/api"},
        ],
    ) == ["https://example.test/admin"]


@pytest.mark.parametrize(
    ("raw_link", "base", "allowed_hosts", "expected"),
    [
        ("", "https://example.test", {"example.test"}, ""),
        ("#section", "https://example.test", {"example.test"}, ""),
        ("mailto:admin@example.test", "https://example.test", {"example.test"}, ""),
        (
            "//EXAMPLE.TEST/Admin#fragment",
            "https://example.test",
            {"example.test"},
            "https://example.test/Admin",
        ),
        (
            "HTTP://EXAMPLE.TEST:8080/api?view=1#fragment",
            "https://example.test",
            {"example.test"},
            "http://example.test:8080/api?view=1",
        ),
        (
            "../api",
            "https://example.test/base/path",
            {"example.test"},
            "https://example.test/base/api",
        ),
        ("ftp://example.test/file", "https://example.test", {"example.test"}, ""),
        ("http:///missing-host", "https://example.test", {"example.test"}, ""),
        ("https://outside.test/admin", "https://example.test", {"example.test"}, ""),
        ("https://example.test/", "https://example.test", {"example.test"}, ""),
        (
            "https://example.test/?view=1",
            "https://example.test",
            {"example.test"},
            "https://example.test/?view=1",
        ),
        ("https://example.test/assets/site.css", "https://example.test", {"example.test"}, ""),
        (
            "https://example.test/assets/app.JS",
            "https://example.test",
            {"example.test"},
            "https://example.test/assets/app.JS",
        ),
        (
            " '/reports),;' ",
            "https://example.test",
            {"example.test"},
            "https://example.test/reports",
        ),
    ],
)
def test_normalize_web_link_url(
    raw_link: str,
    base: str,
    allowed_hosts: set[str],
    expected: str,
) -> None:
    pipeline = WebLinksHarness()

    assert pipeline._normalize_web_link_url(raw_link, base, allowed_hosts) == expected


@pytest.mark.parametrize(
    ("raw_link", "expected"),
    [
        ("", False),
        ("#section", False),
        ("javascript:alert(1)", False),
        ("https://example.test/bundle.mjs", True),
        ("/styles.css", False),
        ("/admin", True),
        ("/ordinary-page", True),
        ("/", False),
        ("./", False),
        ("../", False),
    ],
)
def test_web_link_interest_filter(raw_link: str, expected: bool) -> None:
    assert WebLinksHarness()._web_link_looks_interesting(raw_link) is expected


def test_static_path_and_keyword_catalog() -> None:
    pipeline = WebLinksHarness()

    assert pipeline._web_path_is_static("/assets/logo.WEBP") is True
    assert pipeline._web_path_is_static("/dashboard") is False
    assert "admin" in pipeline._interesting_web_words()
    assert "graphql" in pipeline._interesting_web_words()


@pytest.mark.parametrize(
    ("url", "is_openapi", "is_graphql", "is_javascript"),
    [
        ("https://example.test/swagger.json", True, False, False),
        ("https://example.test/swagger/v3", True, False, False),
        ("https://example.test/docs", False, False, False),
        ("https://example.test/GRAPHQL/", False, True, False),
        ("https://example.test/assets/app.MJS?version=1", False, False, True),
        ("", False, False, False),
    ],
)
def test_special_url_classifiers(
    url: str,
    is_openapi: bool,
    is_graphql: bool,
    is_javascript: bool,
) -> None:
    pipeline = WebLinksHarness()

    assert pipeline._url_looks_openapi_spec(url) is is_openapi
    assert pipeline._url_looks_graphql_endpoint(url) is is_graphql
    assert pipeline._url_looks_javascript_asset(url) is is_javascript


def test_web_link_command_limit_uses_strategy_configuration() -> None:
    pipeline = WebLinksHarness(limits={"web_link_followup_commands": 7})

    assert pipeline._web_link_followup_command_limit() == 7
    assert pipeline.limit_calls == [("web_link_followup_commands", None)]
