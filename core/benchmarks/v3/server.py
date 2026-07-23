"""HTTP serving boundary for a controller-provisioned Lab v3 fixture."""

from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

from .fixture import (
    LAB_V3_HEALTH_EVIDENCE,
    FixtureRuntime,
    load_private_fixture,
)
from .ledger import ControlPlaneLedger


class FixtureHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], runtime: FixtureRuntime) -> None:
        self.runtime = runtime
        super().__init__(server_address, FixtureRequestHandler)


class FixtureRequestHandler(BaseHTTPRequestHandler):
    server_version = "OctobenchFixture/3.0"
    sys_version = ""

    def do_GET(self) -> None:
        self._respond(include_body=True)

    def do_HEAD(self) -> None:
        self._respond(include_body=False)

    def do_POST(self) -> None:
        self._respond(include_body=True)

    def do_PUT(self) -> None:
        self._respond(include_body=True)

    def do_PATCH(self) -> None:
        self._respond(include_body=True)

    def do_DELETE(self) -> None:
        self._respond(include_body=True)

    def do_OPTIONS(self) -> None:
        self._respond(include_body=True)

    def _respond(self, *, include_body: bool) -> None:
        runtime = cast(FixtureHTTPServer, self.server).runtime
        if self.command in {"GET", "HEAD"} and self.path == "/__octobench_health":
            body = (
                json.dumps(
                    {
                        "evidence": LAB_V3_HEALTH_EVIDENCE,
                        "lab_version": runtime.variant.lab_version,
                        "scenario_id": runtime.variant.scenario_id,
                        "schema_version": "1.0",
                        "status": "healthy",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if include_body:
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    return
            return
        response = runtime.handle(self.command, self.path)
        if response.delay_ms:
            time.sleep(response.delay_ms / 1000.0)
        self.send_response(int(response.status))
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        for name, value in sorted(response.headers.items()):
            self.send_header(name, value)
        self.end_headers()
        if include_body:
            try:
                self.wfile.write(response.body)
            except (BrokenPipeError, ConnectionResetError):
                return

    def log_message(self, format: str, *args: Any) -> None:
        return


def create_server(
    *,
    private_manifest_path: str | Path,
    ledger_path: str | Path,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> FixtureHTTPServer:
    variant = load_private_fixture(private_manifest_path)
    ledger = ControlPlaneLedger(
        variant_digest=variant.variant_digest,
        path=ledger_path,
    )
    runtime = FixtureRuntime(variant, ledger)
    return FixtureHTTPServer((str(host), int(port)), runtime)


def main() -> None:
    """Start a fixture without putting private seed/truth in product variables."""

    manifest = str(os.environ.get("OCTOBENCH_V3_PRIVATE_MANIFEST") or "").strip()
    ledger = str(os.environ.get("OCTOBENCH_V3_LEDGER_PATH") or "").strip()
    if not manifest or not ledger:
        raise SystemExit("private manifest and controller ledger paths are required")
    host = str(os.environ.get("OCTOBENCH_V3_HOST") or "127.0.0.1")
    try:
        port = int(os.environ.get("OCTOBENCH_V3_PORT") or "8080")
    except ValueError:
        raise SystemExit("invalid fixture port") from None
    if not 1 <= port <= 65535:
        raise SystemExit("invalid fixture port")
    server = create_server(
        private_manifest_path=manifest,
        ledger_path=ledger,
        host=host,
        port=port,
    )
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
