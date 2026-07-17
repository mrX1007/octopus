#!/usr/bin/env python3
"""Stateless discovery-only HTTP fixture for authorized competitor benchmarks."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

LAB_VERSION = "discovery-lab-v1"


def route(path: str) -> tuple[int, str, bytes, dict[str, str]]:
    """Return one deterministic fixture response without mutable state."""

    clean_path = urlsplit(path).path
    headers = {
        "Cache-Control": "no-store",
        "X-Octobench-Lab": LAB_VERSION,
    }
    if clean_path == "/":
        body = b"""<!doctype html>
<html><head><title>Octobench Discovery Lab</title></head>
<body>
<h1>Authorized discovery fixture</h1>
<p>OCTOBENCH_EVIDENCE_SERVICE_HTTP_8080</p>
<nav><a href="/health">health</a> <a href="/docs">docs</a></nav>
</body></html>
"""
        headers["X-Octobench-Evidence"] = "OCTOBENCH_EVIDENCE_SERVICE_HTTP_8080"
        return 200, "text/html; charset=utf-8", body, headers
    if clean_path in {"/health", "/__octobench_health"}:
        payload = {
            "schema_version": "1.0",
            "status": "healthy",
            "lab_version": LAB_VERSION,
            "evidence": "OCTOBENCH_EVIDENCE_ENDPOINT_HEALTH",
        }
        return 200, "application/json", _json_bytes(payload), headers
    if clean_path == "/docs":
        body = b"""<!doctype html><html><head><title>API docs</title></head>
<body><a href="/openapi.json">OpenAPI document</a></body></html>
"""
        return 200, "text/html; charset=utf-8", body, headers
    if clean_path == "/robots.txt":
        return 200, "text/plain; charset=utf-8", b"User-agent: *\nDisallow: /admin/status\n", headers
    if clean_path == "/openapi.json":
        payload: dict[str, Any] = {
            "openapi": "3.0.3",
            "info": {"title": "Octobench fixture", "version": LAB_VERSION},
            "x-octobench-evidence": "OCTOBENCH_EVIDENCE_ENDPOINT_OPENAPI",
            "paths": {
                "/health": {"get": {"operationId": "health"}},
                "/api/items": {"get": {"operationId": "listItems"}},
            },
        }
        return 200, "application/json", _json_bytes(payload), headers
    if clean_path == "/api/items":
        payload = {
            "items": [{"id": 1, "name": "fixture"}],
            "evidence": "OCTOBENCH_EVIDENCE_ENDPOINT_API_ITEMS",
        }
        return 200, "application/json", _json_bytes(payload), headers
    if clean_path == "/admin/status":
        payload = {
            "component": "fixture-admin-status",
            "read_only": True,
            "evidence": "OCTOBENCH_EVIDENCE_ENDPOINT_ADMIN_STATUS",
        }
        return 200, "application/json", _json_bytes(payload), headers
    return 404, "application/json", _json_bytes({"error": "not_found"}), headers


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "OctobenchFixture/1.0"
    sys_version = ""

    def do_GET(self) -> None:
        self._respond(include_body=True)

    def do_HEAD(self) -> None:
        self._respond(include_body=False)

    def do_POST(self) -> None:
        self.send_error(405, "stateless fixture is read-only")

    def _respond(self, *, include_body: bool) -> None:
        status, content_type, body, headers = route(self.path)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        # A campaign records health attestations outside the timed run.  The lab
        # itself intentionally does not retain request or target-identifying logs.
        return


def main() -> None:
    host = os.environ.get("OCTOBENCH_LAB_HOST", "0.0.0.0")
    port = int(os.environ.get("OCTOBENCH_LAB_INTERNAL_PORT", "8080"))
    server = ThreadingHTTPServer((host, port), FixtureHandler)
    server.serve_forever(poll_interval=0.2)


def _json_bytes(payload: Any) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


if __name__ == "__main__":
    main()
