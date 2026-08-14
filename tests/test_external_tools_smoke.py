"""Loopback-only smoke for native providers through canonical dispatch."""

from __future__ import annotations

import os
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from core.execution import ExecutionContext
from core.tools import dispatch_registered_tool

pytestmark = [pytest.mark.external_tools, pytest.mark.integration, pytest.mark.platform]


def _require_executable(name: str) -> str:
    executable = shutil.which(name)
    if executable is not None:
        return executable
    if os.environ.get("OCTOPUS_REQUIRE_EXTERNAL_TOOLS") == "1":
        pytest.fail(f"nightly external-tools environment did not provision {name}")
    pytest.skip(f"{name} is not installed")


def test_nmap_can_probe_loopback_through_registered_policy_boundary() -> None:
    _require_executable("nmap")
    context = ExecutionContext.automatic(
        target_scope=("127.0.0.1",),
        max_runtime_seconds=30,
    )

    result = dispatch_registered_tool("nmap -sn -n 127.0.0.1", context)

    assert "Execution denied" not in result
    assert "127.0.0.1" in result


class _LoopbackHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_HEAD(self) -> None:
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.send_header("X-Octopus-Smoke", "canonical-dispatch")
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        return


def test_curl_headers_reaches_only_a_loopback_fixture_through_policy() -> None:
    _require_executable("curl")
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _LoopbackHandler)
    except OSError as exc:
        if os.environ.get("OCTOPUS_REQUIRE_EXTERNAL_TOOLS") == "1":
            pytest.fail(f"nightly external-tools environment cannot bind loopback: {exc}")
        pytest.skip(f"environment cannot bind a loopback smoke fixture: {exc}")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    context = ExecutionContext.automatic(
        target_scope=(url,),
        max_runtime_seconds=30,
    )
    try:
        result = dispatch_registered_tool(f"curl_headers {url}", context)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert "Execution denied" not in result
    if "dyld:" in result or "Library not loaded" in result:
        pytest.skip(f"environment cannot load curl dynamic libraries: {result}")
    assert "X-Octopus-Smoke: canonical-dispatch" in result
