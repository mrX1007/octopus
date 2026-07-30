"""Socket-free coverage of benchmark fixture HTTP and process boundaries."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from core.benchmarks.v3 import server as v3_server

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]

ROOT = Path(__file__).parents[2]
V1_APP = ROOT / "benchmarks" / "competitors" / "lab" / "app.py"
V2_APP = ROOT / "benchmarks" / "competitors" / "labs" / "discovery-lab-v2" / "app.py"


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _handler(handler_type, *, server=None, path="/", command="GET", writer=None):
    handler = object.__new__(handler_type)
    handler.server = server
    handler.path = path
    handler.command = command
    handler.wfile = writer if writer is not None else io.BytesIO()
    handler.responses = []
    handler.headers = []
    handler.ended = 0
    handler.send_response = lambda status, *args: handler.responses.append((status, args))
    handler.send_header = lambda name, value: handler.headers.append((name, value))
    handler.end_headers = lambda: setattr(handler, "ended", handler.ended + 1)
    return handler


class BrokenWriter:
    def __init__(self, exception_type=BrokenPipeError) -> None:
        self.exception_type = exception_type

    def write(self, _body: bytes) -> None:
        raise self.exception_type("closed client")


def test_v1_routes_cover_every_documented_surface_and_json_encoding() -> None:
    lab = _load(V1_APP, "fixture_v1_complete_routes")

    expected = {
        "/": (200, "text/html; charset=utf-8"),
        "/health": (200, "application/json"),
        "/__octobench_health": (200, "application/json"),
        "/docs": (200, "text/html; charset=utf-8"),
        "/robots.txt": (200, "text/plain; charset=utf-8"),
        "/openapi.json": (200, "application/json"),
        "/api/items": (200, "application/json"),
        "/admin/status": (200, "application/json"),
        "/missing": (404, "application/json"),
    }
    for path, prefix in expected.items():
        assert lab.route(path)[:2] == prefix

    assert lab.route("/?cache=bust")[0] == 200
    assert lab._json_bytes({"b": 2, "a": 1}) == b'{"a":1,"b":2}\n'


def test_v1_handler_methods_and_main_are_socket_free(monkeypatch) -> None:
    lab = _load(V1_APP, "fixture_v1_http_boundary")
    include: list[bool] = []
    handler = _handler(lab.FixtureHandler)
    handler._respond = lambda *, include_body: include.append(include_body)
    handler.send_error = lambda status, message: include.append((status, message))

    handler.do_GET()
    handler.do_HEAD()
    handler.do_POST()
    assert include == [True, False, (405, "stateless fixture is read-only")]

    get_handler = _handler(lab.FixtureHandler, path="/docs")
    get_handler._respond(include_body=True)
    assert get_handler.responses[0][0] == 200
    assert b"API docs" in get_handler.wfile.getvalue()
    assert get_handler.ended == 1

    head_handler = _handler(lab.FixtureHandler, path="/docs")
    head_handler._respond(include_body=False)
    assert head_handler.wfile.getvalue() == b""
    assert head_handler.log_message("ignored %s", "value") is None

    servers = []

    class Server:
        def __init__(self, address, handler_type) -> None:
            servers.append((address, handler_type, self))
            self.poll_interval = None

        def serve_forever(self, *, poll_interval) -> None:
            self.poll_interval = poll_interval

    monkeypatch.setattr(lab, "ThreadingHTTPServer", Server)
    monkeypatch.delenv("OCTOBENCH_LAB_HOST", raising=False)
    monkeypatch.delenv("OCTOBENCH_LAB_INTERNAL_PORT", raising=False)
    lab.main()
    assert servers[-1][0] == ("0.0.0.0", 8080)
    assert servers[-1][2].poll_interval == 0.2

    monkeypatch.setenv("OCTOBENCH_LAB_HOST", "127.0.0.2")
    monkeypatch.setenv("OCTOBENCH_LAB_INTERNAL_PORT", "9090")
    lab.main()
    assert servers[-1][0] == ("127.0.0.2", 9090)


def test_v2_routes_cover_health_docs_not_found_and_invalid_queries() -> None:
    lab = _load(V2_APP, "fixture_v2_complete_routes")
    linked = "authorized-linked-navigation-small-model-v2"
    openapi = "authorized-openapi-contract-small-model-v2"
    redirect = "authorized-relative-redirect-small-model-v2"
    hypermedia = "authorized-hypermedia-pagination-small-model-v2"

    with pytest.raises(ValueError, match="unsupported benchmark scenario"):
        lab.route("/", scenario_id="unknown")

    assert lab.route("/__octobench_health", scenario_id=linked)[0] == 200
    assert b"Linked API docs" in lab.route("/docs", scenario_id=linked)[2]
    assert lab.route("/missing", scenario_id=linked)[0] == 404
    assert lab.route("/missing", scenario_id=openapi)[0] == 404
    assert lab.route("/missing", scenario_id=redirect)[0] == 404
    assert lab.route("/api/items?page=invalid", scenario_id=hypermedia)[0] == 404
    assert lab.route("/missing", scenario_id=hypermedia)[0] == 404

    status, content_type, body, headers = lab._html_response("hello", {"A": "B"})
    assert (status, content_type, body, headers) == (
        200,
        "text/html; charset=utf-8",
        b"hello",
        {"A": "B"},
    )
    status, content_type, body, headers = lab._json_response({"ok": True}, {"A": "B"})
    assert status == 200 and content_type == "application/json"
    assert json.loads(body) == {"ok": True}
    assert headers == {"A": "B"}


def test_v2_handler_all_methods_and_main(monkeypatch) -> None:
    lab = _load(V2_APP, "fixture_v2_http_boundary")
    linked = "authorized-linked-navigation-small-model-v2"
    include: list[bool] = []
    handler = _handler(lab.FixtureHandler)
    handler._respond = lambda *, include_body: include.append(include_body)
    handler._method_not_allowed = lambda: include.append("denied")

    handler.do_GET()
    handler.do_HEAD()
    handler.do_POST()
    handler.do_PUT()
    handler.do_PATCH()
    handler.do_DELETE()
    assert include == [True, False, "denied", "denied", "denied", "denied"]

    denied = _handler(lab.FixtureHandler)
    denied._method_not_allowed()
    assert denied.responses[0][0] == 405
    assert denied.wfile.getvalue() == b'{"error":"read_only_fixture"}\n'

    get_handler = _handler(
        lab.FixtureHandler,
        server=SimpleNamespace(scenario_id=linked),
        path="/health",
    )
    get_handler._respond(include_body=True)
    assert b"LINKED_HEALTH" in get_handler.wfile.getvalue()

    head_handler = _handler(
        lab.FixtureHandler,
        server=SimpleNamespace(scenario_id=linked),
        path="/health",
    )
    head_handler._respond(include_body=False)
    assert head_handler.wfile.getvalue() == b""
    assert head_handler.log_message("ignored") is None

    monkeypatch.delenv("OCTOBENCH_LAB_SCENARIO_ID", raising=False)
    with pytest.raises(SystemExit, match="unsupported benchmark scenario"):
        lab.main()

    servers = []

    class Server:
        def __init__(self, address, handler_type) -> None:
            servers.append((address, handler_type, self))
            self.scenario_id = None
            self.poll_interval = None

        def serve_forever(self, *, poll_interval) -> None:
            self.poll_interval = poll_interval

    monkeypatch.setattr(lab, "ThreadingHTTPServer", Server)
    monkeypatch.setenv("OCTOBENCH_LAB_SCENARIO_ID", linked)
    monkeypatch.delenv("OCTOBENCH_LAB_HOST", raising=False)
    monkeypatch.delenv("OCTOBENCH_LAB_INTERNAL_PORT", raising=False)
    lab.main()
    assert servers[-1][0] == ("0.0.0.0", 8080)
    assert servers[-1][2].scenario_id == linked
    assert servers[-1][2].poll_interval == 0.2

    monkeypatch.setenv("OCTOBENCH_LAB_HOST", "127.0.0.3")
    monkeypatch.setenv("OCTOBENCH_LAB_INTERNAL_PORT", "9091")
    lab.main()
    assert servers[-1][0] == ("127.0.0.3", 9091)


def test_v3_server_constructor_and_factory_without_socket_binding(monkeypatch, tmp_path) -> None:
    initialized = []

    def fake_http_init(instance, address, handler_type) -> None:
        initialized.append((instance, address, handler_type))

    monkeypatch.setattr(v3_server.ThreadingHTTPServer, "__init__", fake_http_init)
    runtime = SimpleNamespace()
    server = v3_server.FixtureHTTPServer(("127.0.0.1", 8080), runtime)
    assert server.runtime is runtime
    assert initialized[-1][1:] == (("127.0.0.1", 8080), v3_server.FixtureRequestHandler)

    variant = SimpleNamespace(variant_digest="digest")
    ledger = SimpleNamespace()
    built_runtime = SimpleNamespace()
    constructed = []
    monkeypatch.setattr(v3_server, "load_private_fixture", lambda path: variant)
    monkeypatch.setattr(
        v3_server,
        "ControlPlaneLedger",
        lambda **kwargs: (constructed.append(("ledger", kwargs)) or ledger),
    )
    monkeypatch.setattr(
        v3_server,
        "FixtureRuntime",
        lambda selected_variant, selected_ledger: (
            constructed.append(("runtime", selected_variant, selected_ledger))
            or built_runtime
        ),
    )
    monkeypatch.setattr(
        v3_server,
        "FixtureHTTPServer",
        lambda address, selected_runtime: (
            constructed.append(("server", address, selected_runtime)) or "server"
        ),
    )

    assert v3_server.create_server(
        private_manifest_path=tmp_path / "private.json",
        ledger_path=tmp_path / "ledger.jsonl",
        host="127.0.0.4",
        port=8181,
    ) == "server"
    assert constructed == [
        ("ledger", {"variant_digest": "digest", "path": tmp_path / "ledger.jsonl"}),
        ("runtime", variant, ledger),
        ("server", ("127.0.0.4", 8181), built_runtime),
    ]


@pytest.mark.parametrize(
    ("method", "include_body"),
    [
        ("do_GET", True),
        ("do_HEAD", False),
        ("do_POST", True),
        ("do_PUT", True),
        ("do_PATCH", True),
        ("do_DELETE", True),
        ("do_OPTIONS", True),
    ],
)
def test_v3_handler_method_facades(method: str, include_body: bool) -> None:
    handler = _handler(v3_server.FixtureRequestHandler)
    observed = []
    handler._respond = lambda *, include_body: observed.append(include_body)

    getattr(handler, method)()

    assert observed == [include_body]


def test_v3_handler_health_normal_delay_headers_and_closed_clients(monkeypatch) -> None:
    variant = SimpleNamespace(lab_version="v3", scenario_id="scenario")
    response = SimpleNamespace(
        delay_ms=25,
        status=201,
        content_type="text/plain",
        body=b"response",
        headers={"Z-Header": "z", "A-Header": "a"},
    )
    requests = []
    runtime = SimpleNamespace(
        variant=variant,
        handle=lambda method, path: (requests.append((method, path)) or response),
    )
    server = SimpleNamespace(runtime=runtime)

    health = _handler(
        v3_server.FixtureRequestHandler,
        server=server,
        path="/__octobench_health",
        command="GET",
    )
    health._respond(include_body=True)
    assert json.loads(health.wfile.getvalue()) == {
        "evidence": v3_server.LAB_V3_HEALTH_EVIDENCE,
        "lab_version": "v3",
        "scenario_id": "scenario",
        "schema_version": "1.0",
        "status": "healthy",
    }

    health_head = _handler(
        v3_server.FixtureRequestHandler,
        server=server,
        path="/__octobench_health",
        command="HEAD",
    )
    health_head._respond(include_body=False)
    assert health_head.wfile.getvalue() == b""

    broken_health = _handler(
        v3_server.FixtureRequestHandler,
        server=server,
        path="/__octobench_health",
        command="GET",
        writer=BrokenWriter(),
    )
    broken_health._respond(include_body=True)

    sleeps = []
    monkeypatch.setattr(v3_server.time, "sleep", lambda value: sleeps.append(value))
    normal = _handler(
        v3_server.FixtureRequestHandler,
        server=server,
        path="/fixture",
        command="GET",
    )
    normal._respond(include_body=True)
    assert normal.responses[0][0] == 201
    assert normal.wfile.getvalue() == b"response"
    assert normal.headers[-2:] == [("A-Header", "a"), ("Z-Header", "z")]
    assert sleeps == [0.025]

    response.delay_ms = 0
    normal_head = _handler(
        v3_server.FixtureRequestHandler,
        server=server,
        path="/fixture",
        command="GET",
    )
    normal_head._respond(include_body=False)
    assert normal_head.wfile.getvalue() == b""

    reset = _handler(
        v3_server.FixtureRequestHandler,
        server=server,
        path="/__octobench_health",
        command="POST",
        writer=BrokenWriter(ConnectionResetError),
    )
    reset._respond(include_body=True)
    assert requests[-1] == ("POST", "/__octobench_health")
    assert reset.log_message("ignored %s", "value") is None


def test_v3_main_validates_environment_and_always_closes_server(monkeypatch) -> None:
    monkeypatch.delenv("OCTOBENCH_V3_PRIVATE_MANIFEST", raising=False)
    monkeypatch.delenv("OCTOBENCH_V3_LEDGER_PATH", raising=False)
    with pytest.raises(SystemExit, match="private manifest"):
        v3_server.main()

    monkeypatch.setenv("OCTOBENCH_V3_PRIVATE_MANIFEST", "private.json")
    with pytest.raises(SystemExit, match="private manifest"):
        v3_server.main()

    monkeypatch.setenv("OCTOBENCH_V3_LEDGER_PATH", "ledger.jsonl")
    monkeypatch.setenv("OCTOBENCH_V3_PORT", "invalid")
    with pytest.raises(SystemExit, match="invalid fixture port"):
        v3_server.main()

    for invalid_port in ("0", "65536"):
        monkeypatch.setenv("OCTOBENCH_V3_PORT", invalid_port)
        with pytest.raises(SystemExit, match="invalid fixture port"):
            v3_server.main()

    calls = []

    class Server:
        def serve_forever(self, *, poll_interval) -> None:
            calls.append(("serve", poll_interval))
            raise RuntimeError("stop fixture")

        def server_close(self) -> None:
            calls.append(("close",))

    monkeypatch.setattr(
        v3_server,
        "create_server",
        lambda **kwargs: (calls.append(("create", kwargs)) or Server()),
    )
    monkeypatch.setenv("OCTOBENCH_V3_PORT", "8088")
    monkeypatch.setenv("OCTOBENCH_V3_HOST", "127.0.0.8")
    with pytest.raises(RuntimeError, match="stop fixture"):
        v3_server.main()
    assert calls == [
        (
            "create",
            {
                "private_manifest_path": "private.json",
                "ledger_path": "ledger.jsonl",
                "host": "127.0.0.8",
                "port": 8088,
            },
        ),
        ("serve", 0.2),
        ("close",),
    ]

    # Exercise default host/port and normal serve_forever return as well.
    calls.clear()
    monkeypatch.delenv("OCTOBENCH_V3_HOST", raising=False)
    monkeypatch.delenv("OCTOBENCH_V3_PORT", raising=False)
    server = Server()
    server.serve_forever = lambda *, poll_interval: calls.append(("serve", poll_interval))
    monkeypatch.setattr(
        v3_server,
        "create_server",
        lambda **kwargs: (calls.append(("create", kwargs)) or server),
    )
    v3_server.main()
    assert calls[0][1]["host"] == "127.0.0.1"
    assert calls[0][1]["port"] == 8080
    assert calls[-1] == ("close",)

