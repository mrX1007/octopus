from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from enum import Enum

import pytest

from core.plugins import events, protocol
from core.plugins.base import (
    CheckResult,
    KillChainStage,
    OctopusPlugin,
    PluginContext,
    PluginResult,
    PluginType,
)

pytestmark = pytest.mark.contract


def test_plugin_sdk_types_and_result_factories_are_independent() -> None:
    assert {member.value for member in PluginType} == {
        "recon",
        "exploit",
        "post",
        "evasion",
        "osint",
        "persistence",
        "lateral",
        "auxiliary",
    }
    assert [stage.value for stage in KillChainStage] == list(range(1, 10))
    assert CheckResult() == CheckResult(
        vulnerable=False,
        confidence=0.0,
        details="",
        version="",
        evidence="",
    )

    first = PluginResult()
    second = PluginResult()
    first.data["result"] = True
    first.artifacts.append("artifact")
    first.credentials.append({"user": "alice"})
    first.sessions.append({"id": "session-1"})
    assert second == PluginResult()

    first_context = PluginContext()
    second_context = PluginContext()
    first_context.credentials["user"] = "alice"
    first_context.config["enabled"] = True
    assert second_context.credentials == {}
    assert second_context.config == {}


def test_base_plugin_lifecycle_context_events_and_representation() -> None:
    class ExamplePlugin(OctopusPlugin):
        name = "example"
        version = "1.2.3"
        plugin_type = PluginType.RECON

    class RecordingBus:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, object], str]] = []

        def emit(self, event_type: str, data: dict[str, object], *, source: str) -> None:
            self.calls.append((event_type, data, source))

    plugin = ExamplePlugin()
    default_context = plugin.context
    assert default_context == PluginContext()
    assert default_context is not plugin.context
    plugin.emit_event("ignored", {"value": 0})

    without_bus = PluginContext(target="example.invalid")
    assert plugin.setup(without_bus) is True
    assert plugin.context is without_bus
    plugin.emit_event("ignored", {"value": 1})

    bus = RecordingBus()
    context = PluginContext(target="example.invalid", event_bus=bus)
    assert plugin.setup(context) is True
    plugin.emit_event("credential.found", {"user": "alice"})
    assert bus.calls == [("credential.found", {"user": "alice"}, "example")]

    assert plugin.check("example.invalid", aggressive=False) == CheckResult(
        vulnerable=False,
        details="check() not implemented",
    )
    with pytest.raises(NotImplementedError, match="Plugin 'example' must implement run"):
        plugin.run(mode="safe")
    assert plugin.cleanup() is None
    assert plugin.on_credential_found({"user": "alice"}) is None
    assert plugin.on_session_opened({"id": "session-1"}) is None
    assert plugin.on_vulnerability_confirmed({"id": "CVE-test"}) is None
    assert repr(plugin) == "<Plugin example v1.2.3 (recon)>"


@pytest.mark.parametrize(
    ("level", "color"),
    (
        ("error", "91"),
        ("warn", "93"),
        ("success", "92"),
        ("info", "96"),
    ),
)
def test_plugin_log_formats_each_level(
    capsys: pytest.CaptureFixture[str],
    level: str,
    color: str,
) -> None:
    plugin = OctopusPlugin()
    plugin.log("message", level=level)
    assert capsys.readouterr().out == f"  \033[{color}m[base_plugin] message\033[0m\n"


def test_event_bus_subscriptions_dispatch_and_persistence(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class RecordingStore:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def append(self, **kwargs: object) -> None:
            self.calls.append(kwargs)

    store = RecordingStore()
    bus = events.PluginEventBus(store)
    received: list[tuple[str, str]] = []

    def exact(event: events.PluginEvent) -> None:
        received.append(("exact", event.event_type))

    def prefix(event: events.PluginEvent) -> None:
        received.append(("prefix", event.event_type))

    def all_events(event: events.PluginEvent) -> None:
        received.append(("all", event.event_type))

    def broken(_event: events.PluginEvent) -> None:
        raise RuntimeError("handler failed")

    bus.on("credential.found", exact)
    bus.on("credential.found", broken)
    bus.on("credential.*", prefix)
    bus.on("*", all_events)
    bus.on("session.opened", lambda _event: None)

    with caplog.at_level(logging.ERROR):
        matched = bus.emit("credential.found", {"user": "alice"}, source="scanner")

    assert matched == 3
    assert received == [
        ("exact", "credential.found"),
        ("prefix", "credential.found"),
        ("all", "credential.found"),
    ]
    assert store.calls == [
        {
            "event_type": "plugin.credential.found",
            "aggregate_type": "plugin",
            "aggregate_id": "scanner",
            "payload": {"user": "alice"},
        }
    ]
    assert "handler error for credential.found: handler failed" in caplog.text
    assert bus.history[0].source == "scanner"


def test_event_bus_logs_persistence_failure_without_blocking_dispatch(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class BrokenStore:
        def append(self, **_kwargs: object) -> None:
            raise OSError("store unavailable")

    received: list[events.PluginEvent] = []
    bus = events.PluginEventBus(BrokenStore())
    bus.on("*", received.append)

    with caplog.at_level(logging.DEBUG):
        assert bus.emit("task.completed", {"id": 7}) == 1

    assert received[0].data == {"id": 7}
    assert "failed to persist event: store unavailable" in caplog.text


def test_event_bus_unsubscribe_matching_and_history_queries() -> None:
    bus = events.PluginEventBus()

    def first(_event: events.PluginEvent) -> None:
        return None

    def second(_event: events.PluginEvent) -> None:
        return None

    bus.off("missing", first)
    bus.on("task.done", first)
    bus.on("task.done", second)
    bus.off("task.done", first)
    assert bus._handlers["task.done"] == [second]
    bus.off("task.done", lambda _event: None)
    assert bus._handlers["task.done"] == [second]
    bus.off("task.done")
    assert "task.done" not in bus._handlers

    assert bus._matches("*", "anything") is True
    assert bus._matches("credential.*", "credential.found") is True
    assert bus._matches("credential.*", "session.opened") is False
    assert bus._matches("task.done", "task.done") is True
    assert bus._matches("task.done", "task.failed") is False

    bus.emit("credential.found", {"id": 1}, source="scanner")
    bus.emit("credential.used", {"id": 2}, source="runner")
    bus.emit("session.opened", {"id": 3}, source="runner")
    bus._history[0].timestamp = 10
    bus._history[1].timestamp = 20
    bus._history[2].timestamp = 30

    assert [event.data["id"] for event in bus.get_events()] == [1, 2, 3]
    assert [event.data["id"] for event in bus.get_events(event_type="credential.*")] == [1, 2]
    assert [event.data["id"] for event in bus.get_events(source="runner")] == [2, 3]
    assert [event.data["id"] for event in bus.get_events(since=20)] == [2, 3]
    assert [
        event.data["id"]
        for event in bus.get_events(event_type="credential.*", source="runner", since=15)
    ] == [2]

    history_copy = bus.history
    history_copy.clear()
    assert len(bus.history) == 3
    bus.clear()
    assert bus.history == []


class _Mode(Enum):
    ACTIVE = "active"


@dataclass
class _Payload:
    name: str
    content: bytes


@pytest.mark.parametrize("value", (None, True, 7, 2.5, "text"))
def test_wire_encode_preserves_json_primitives(value: object) -> None:
    assert protocol.encode_value(value) is value
    assert protocol.decode_value(value) is value


def test_wire_round_trip_supports_bytes_enums_dataclasses_and_sequences() -> None:
    value = {
        "raw": b"\x00\xff",
        "mutable": bytearray(b"bytes"),
        "mode": _Mode.ACTIVE,
        "payload": _Payload(name="sample", content=b"payload"),
        "items": (1, [2, b"three"]),
    }

    encoded = protocol.encode_value(value)
    assert encoded["raw"] == {
        "__octopus_wire_type__": "bytes",
        "base64": "AP8=",
    }
    assert encoded["mutable"]["base64"] == "Ynl0ZXM="
    assert encoded["mode"] == "active"
    assert encoded["payload"]["name"] == "sample"
    assert protocol.decode_value(encoded) == {
        "raw": b"\x00\xff",
        "mutable": b"bytes",
        "mode": "active",
        "payload": {"name": "sample", "content": b"payload"},
        "items": [1, [2, b"three"]],
    }


@pytest.mark.parametrize(
    ("value", "message"),
    (
        ({1: "value"}, "JSON object keys must be strings"),
        ({"set"}, "unsupported wire value: set"),
        (_Payload, "unsupported wire value: type"),
    ),
)
def test_wire_encode_rejects_unsafe_values(value: object, message: str) -> None:
    with pytest.raises(protocol.WireError, match=message):
        protocol.encode_value(value)


def test_wire_decode_validates_bytes_envelopes_and_regular_mappings() -> None:
    marker = "__octopus_wire_type__"
    assert protocol.decode_value({marker: "bytes", "base64": "YQ=="}) == b"a"
    assert protocol.decode_value({marker: "bytes", "base64": "YQ==", "extra": True}) == {
        marker: "bytes",
        "base64": "YQ==",
        "extra": True,
    }
    assert protocol.decode_value({1: ["value"]}) == {"1": ["value"]}
    assert protocol.decode_value([]) == []

    with pytest.raises(protocol.WireError, match="invalid bytes envelope"):
        protocol.decode_value({marker: "bytes", "base64": 7})
    with pytest.raises(protocol.WireError, match="invalid base64 bytes envelope"):
        protocol.decode_value({marker: "bytes", "base64": "%%%"})
    with pytest.raises(protocol.WireError, match="invalid base64 bytes envelope"):
        protocol.decode_value({marker: "bytes", "base64": "é"})


def test_message_serialization_is_compact_utf8_and_round_trips() -> None:
    message = {"greeting": "Grüezi", "payload": b"data"}
    raw = protocol.dumps_message(message)
    assert raw == (
        b'{"greeting":"Gr\xc3\xbcezi","payload":'
        b'{"__octopus_wire_type__":"bytes","base64":"ZGF0YQ=="}}'
    )
    assert protocol.loads_message(raw) == message


def test_message_serialization_preserves_wire_errors_and_wraps_json_errors() -> None:
    with pytest.raises(protocol.WireError, match="unsupported wire value: object") as unsupported:
        protocol.dumps_message(object())
    assert unsupported.value.__cause__ is None

    with pytest.raises(protocol.WireError, match="Out of range float values") as invalid_float:
        protocol.dumps_message(math.nan)
    assert isinstance(invalid_float.value.__cause__, ValueError)

    recursive: list[object] = []
    recursive.append(recursive)
    with pytest.raises(protocol.WireError) as recursion:
        protocol.dumps_message(recursive)
    assert isinstance(recursion.value.__cause__, RecursionError)


@pytest.mark.parametrize("raw", (b"\xff", b"{not-json"))
def test_message_parser_rejects_invalid_utf8_and_json(raw: bytes) -> None:
    with pytest.raises(protocol.WireError, match="invalid worker JSON response"):
        protocol.loads_message(raw)
