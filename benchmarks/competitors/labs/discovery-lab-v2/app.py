#!/usr/bin/env python3
"""Scenario-isolated, stateless HTTP fixture for benchmark campaign v2."""

from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

LAB_VERSION = "discovery-lab-v2"
HEALTH_EVIDENCE = "OCTOBENCH_EVIDENCE_V2_HEALTH"
SCENARIO_IDS = frozenset(
    {
        "authorized-hypermedia-pagination-small-model-v2",
        "authorized-linked-navigation-small-model-v2",
        "authorized-openapi-contract-small-model-v2",
        "authorized-relative-redirect-small-model-v2",
    }
)


def route(
    target: str,
    *,
    scenario_id: str,
) -> tuple[int, str, bytes, dict[str, str]]:
    """Return one deterministic response from exactly one selected surface."""

    if scenario_id not in SCENARIO_IDS:
        raise ValueError("unsupported benchmark scenario")
    parsed = urlsplit(target)
    path = parsed.path
    headers = {
        "Cache-Control": "no-store",
        "X-Octobench-Lab": LAB_VERSION,
        "X-Octobench-Scenario": scenario_id,
    }
    if path == "/__octobench_health":
        return _json_response(
            {
                "evidence": HEALTH_EVIDENCE,
                "lab_version": LAB_VERSION,
                "scenario_id": scenario_id,
                "schema_version": "1.0",
                "status": "healthy",
            },
            headers,
        )
    if scenario_id == "authorized-linked-navigation-small-model-v2":
        return _linked_surface(path, headers)
    if scenario_id == "authorized-openapi-contract-small-model-v2":
        return _openapi_surface(path, headers)
    if scenario_id == "authorized-relative-redirect-small-model-v2":
        return _redirect_surface(path, headers)
    return _hypermedia_surface(path, parse_qs(parsed.query), headers)


def _linked_surface(
    path: str,
    headers: dict[str, str],
) -> tuple[int, str, bytes, dict[str, str]]:
    if path == "/":
        return _html_response(
            """<!doctype html><html><head><title>Linked service</title></head>
<body><p>OCTOBENCH_EVIDENCE_V2_LINKED_SERVICE</p>
<nav><a href="/health">health</a> <a href="/docs">docs</a></nav></body></html>
""",
            headers,
        )
    if path == "/health":
        return _json_response(
            {
                "evidence": "OCTOBENCH_EVIDENCE_V2_LINKED_HEALTH",
                "status": "ok",
            },
            headers,
        )
    if path == "/docs":
        return _html_response(
            """<!doctype html><html><head><title>Linked API docs</title></head>
<body><a href="/openapi.json">OpenAPI document</a></body></html>
""",
            headers,
        )
    if path == "/openapi.json":
        return _json_response(
            {
                "info": {"title": "Linked fixture", "version": LAB_VERSION},
                "openapi": "3.0.3",
                "paths": {"/api/items": {"get": {"operationId": "listItems"}}},
                "x-octobench-evidence": "OCTOBENCH_EVIDENCE_V2_LINKED_OPENAPI",
            },
            headers,
        )
    if path == "/api/items":
        return _json_response(
            {
                "evidence": "OCTOBENCH_EVIDENCE_V2_LINKED_ITEMS",
                "items": [{"id": 1, "name": "linked-fixture"}],
            },
            headers,
        )
    return _not_found(headers)


def _openapi_surface(
    path: str,
    headers: dict[str, str],
) -> tuple[int, str, bytes, dict[str, str]]:
    if path == "/":
        return _html_response(
            """<!doctype html><html><head><title>Contract service</title>
<link rel="service-desc" type="application/vnd.oai.openapi+json" href="/openapi.json">
</head><body><p>OCTOBENCH_EVIDENCE_V2_CONTRACT_SERVICE</p></body></html>
""",
            headers,
        )
    if path == "/openapi.json":
        return _json_response(
            {
                "info": {"title": "Contract fixture", "version": LAB_VERSION},
                "openapi": "3.0.3",
                "paths": {
                    "/api/widgets": {"get": {"operationId": "listWidgets"}},
                    "/api/widget/7": {"get": {"operationId": "getWidget7"}},
                },
                "x-octobench-evidence": "OCTOBENCH_EVIDENCE_V2_CONTRACT_OPENAPI",
            },
            headers,
        )
    if path == "/api/widgets":
        return _json_response(
            {
                "evidence": "OCTOBENCH_EVIDENCE_V2_CONTRACT_WIDGETS",
                "widgets": [{"id": 7, "name": "contract-widget"}],
            },
            headers,
        )
    if path == "/api/widget/7":
        return _json_response(
            {
                "evidence": "OCTOBENCH_EVIDENCE_V2_CONTRACT_WIDGET_7",
                "id": 7,
                "name": "contract-widget",
            },
            headers,
        )
    return _not_found(headers)


def _redirect_surface(
    path: str,
    headers: dict[str, str],
) -> tuple[int, str, bytes, dict[str, str]]:
    if path == "/":
        redirect_headers = {
            **headers,
            "Location": "/portal",
            "X-Octobench-Evidence": "OCTOBENCH_EVIDENCE_V2_REDIRECT_SERVICE",
        }
        body = (
            b"OCTOBENCH_EVIDENCE_V2_REDIRECT_SERVICE\n"
            b"Continue at the same-origin relative location /portal.\n"
        )
        return HTTPStatus.FOUND, "text/plain; charset=utf-8", body, redirect_headers
    if path == "/portal":
        return _html_response(
            """<!doctype html><html><head><title>Redirect portal</title></head>
<body><p>OCTOBENCH_EVIDENCE_V2_REDIRECT_PORTAL</p>
<a href="/status">service status</a></body></html>
""",
            headers,
        )
    if path == "/status":
        return _json_response(
            {
                "evidence": "OCTOBENCH_EVIDENCE_V2_REDIRECT_STATUS",
                "read_only": True,
                "status": "operational",
            },
            headers,
        )
    return _not_found(headers)


def _hypermedia_surface(
    path: str,
    query: dict[str, list[str]],
    headers: dict[str, str],
) -> tuple[int, str, bytes, dict[str, str]]:
    if path == "/":
        return _json_response(
            {
                "evidence": "OCTOBENCH_EVIDENCE_V2_HYPERMEDIA_SERVICE",
                "links": {"items": {"href": "/api/items?page=1"}},
            },
            headers,
        )
    if path == "/api/items" and query.get("page") == ["1"]:
        return _json_response(
            {
                "evidence": "OCTOBENCH_EVIDENCE_V2_HYPERMEDIA_PAGE_1",
                "items": [{"id": 1}],
                "links": {"next": {"href": "/api/items?page=2"}},
                "page": 1,
            },
            headers,
        )
    if path == "/api/items" and query.get("page") == ["2"]:
        return _json_response(
            {
                "evidence": "OCTOBENCH_EVIDENCE_V2_HYPERMEDIA_PAGE_2",
                "items": [{"href": "/api/items/7", "id": 7}],
                "links": {},
                "page": 2,
            },
            headers,
        )
    if path == "/api/items/7":
        return _json_response(
            {
                "evidence": "OCTOBENCH_EVIDENCE_V2_HYPERMEDIA_ITEM_7",
                "id": 7,
                "name": "hypermedia-item",
            },
            headers,
        )
    return _not_found(headers)


def _html_response(
    body: str,
    headers: dict[str, str],
) -> tuple[int, str, bytes, dict[str, str]]:
    return HTTPStatus.OK, "text/html; charset=utf-8", body.encode(), dict(headers)


def _json_response(
    payload: Any,
    headers: dict[str, str],
) -> tuple[int, str, bytes, dict[str, str]]:
    body = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return HTTPStatus.OK, "application/json", body, dict(headers)


def _not_found(
    headers: dict[str, str],
) -> tuple[int, str, bytes, dict[str, str]]:
    return (
        HTTPStatus.NOT_FOUND,
        "application/json",
        b'{"error":"not_found"}\n',
        dict(headers),
    )


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "OctobenchFixture/2.0"
    sys_version = ""

    def do_GET(self) -> None:
        self._respond(include_body=True)

    def do_HEAD(self) -> None:
        self._respond(include_body=False)

    def do_POST(self) -> None:
        self._method_not_allowed()

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def _method_not_allowed(self) -> None:
        body = b'{"error":"read_only_fixture"}\n'
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _respond(self, *, include_body: bool) -> None:
        scenario_id = str(getattr(self.server, "scenario_id", ""))
        status, content_type, body, headers = route(
            self.path,
            scenario_id=scenario_id,
        )
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        return


def main() -> None:
    scenario_id = str(os.environ.get("OCTOBENCH_LAB_SCENARIO_ID") or "").strip()
    if scenario_id not in SCENARIO_IDS:
        raise SystemExit("unsupported benchmark scenario")
    host = os.environ.get("OCTOBENCH_LAB_HOST", "0.0.0.0")
    port = int(os.environ.get("OCTOBENCH_LAB_INTERNAL_PORT", "8080"))
    server = ThreadingHTTPServer((host, port), FixtureHandler)
    server.scenario_id = scenario_id  # type: ignore[attr-defined]
    server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    main()
