#!/usr/bin/env python3
"""Loopback-only intentionally vulnerable HTTP fixture for the E2E lane."""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

LAB_ROOT = Path(__file__).resolve().parent
PUBLIC_ROOT = LAB_ROOT / "public"
FINDING_HEADER = "path-traversal"


class VulnerableLabHandler(BaseHTTPRequestHandler):
    """Serve a deliberately unsafe file download from an isolated container."""

    server_version = "OctopusVulnerableLab/1.0"
    sys_version = ""

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/__health":
            self._send(HTTPStatus.OK, b'{"status":"ready"}\n', "application/json")
            return
        if parsed.path == "/":
            body = (
                b"<!doctype html><title>Octopus vulnerable scanner lab</title>"
                b"<h1>Octopus vulnerable scanner lab</h1>"
                b'<a href="/download?file=readme.txt">download</a>'
            )
            self._send(HTTPStatus.OK, body, "text/html; charset=utf-8")
            return
        if parsed.path == "/download":
            requested = parse_qs(parsed.query).get("file", [""])[0]
            self._download(requested)
            return
        self._send(HTTPStatus.NOT_FOUND, b"not found\n", "text/plain; charset=utf-8")

    def do_HEAD(self) -> None:
        parsed = urlsplit(self.path)
        status = HTTPStatus.OK if parsed.path in {"/", "/__health"} else HTTPStatus.NOT_FOUND
        self._send(status, b"", "text/plain; charset=utf-8")

    def log_message(self, format: str, *args: object) -> None:
        print(json.dumps({"client": self.client_address[0], "message": format % args}), flush=True)

    def _download(self, requested: str) -> None:
        if not requested:
            self._send(HTTPStatus.BAD_REQUEST, b"missing file\n", "text/plain; charset=utf-8")
            return

        # Intentionally vulnerable: the untrusted path is joined without
        # canonicalization or a containment check. The container has no host
        # mounts and is read-only, so the flaw exposes only disposable lab data.
        candidate = PUBLIC_ROOT / requested
        try:
            body = candidate.read_bytes()
        except (OSError, ValueError):
            self._send(HTTPStatus.NOT_FOUND, b"not found\n", "text/plain; charset=utf-8")
            return

        extra_headers = {}
        if ".." in Path(requested).parts:
            extra_headers["X-Octopus-Lab-Finding"] = FINDING_HEADER
        self._send(
            HTTPStatus.OK,
            body,
            "application/octet-stream",
            extra_headers=extra_headers,
        )

    def _send(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if body:
            self.wfile.write(body)


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8080), VulnerableLabHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
