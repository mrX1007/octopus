"""Hermetic statement and branch coverage for the pivoting helpers."""

from __future__ import annotations

import builtins
import importlib
import runpy
import socket
import struct
import subprocess
import sys
from collections import deque
from types import SimpleNamespace
from typing import ClassVar
from unittest.mock import Mock

import pytest

pivot = importlib.import_module("core.killchain.pivot")

pytestmark = pytest.mark.unit


class FakeSocket:
    """In-memory socket double; it never opens an operating-system socket."""

    def __init__(self, *, recv=(), accept=(), bind_error: Exception | None = None):
        self.recv_values = deque(recv)
        self.accept_values = deque(accept)
        self.bind_error = bind_error
        self.sent: list[bytes] = []
        self.calls: list[tuple[str, object]] = []
        self.closed = False

    def recv(self, size):
        self.calls.append(("recv", size))
        value = self.recv_values.popleft()
        if isinstance(value, BaseException):
            raise value
        return value

    def sendall(self, data):
        self.sent.append(data)

    def getpeername(self):
        return ("198.51.100.8", 4242)

    def bind(self, address):
        self.calls.append(("bind", address))
        if self.bind_error is not None:
            raise self.bind_error

    def setsockopt(self, *args):
        self.calls.append(("setsockopt", args))

    def listen(self, backlog):
        self.calls.append(("listen", backlog))

    def settimeout(self, timeout):
        self.calls.append(("settimeout", timeout))

    def connect(self, address):
        self.calls.append(("connect", address))

    def accept(self):
        value = self.accept_values.popleft()
        if isinstance(value, BaseException):
            raise value
        return value

    def close(self):
        self.closed = True


class FakeEvent:
    def __init__(self, states=(False, True)):
        self.states = deque(states)

    def is_set(self):
        if len(self.states) > 1:
            return self.states.popleft()
        return self.states[0]

    def set_states(self, *states):
        self.states = deque(states)


class FakeThread:
    instances: ClassVar[list[FakeThread]] = []

    def __init__(self, target=None, args=(), **kwargs):
        self.target = target
        self.args = args
        self.kwargs = kwargs
        self.started = False
        type(self).instances.append(self)

    def start(self):
        self.started = True

    def invoke(self):
        assert self.target is not None
        return self.target(*self.args)


class FakeTransport:
    def __init__(self, *, active=True, channel=None):
        self.active = active
        self.channel = channel or SimpleNamespace(closed=True)
        self.open_calls = []
        self.request_calls = []
        self.accept_values = deque()

    def is_active(self):
        return self.active

    def open_channel(self, *args, **kwargs):
        self.open_calls.append((args, kwargs))
        if isinstance(self.channel, BaseException):
            raise self.channel
        return self.channel

    def request_port_forward(self, *args):
        self.request_calls.append(args)

    def accept(self, timeout):
        value = self.accept_values.popleft()
        if isinstance(value, BaseException):
            raise value
        return value


def _client(transport):
    return SimpleNamespace(get_transport=lambda: transport)


def _install_thread_doubles(monkeypatch):
    FakeThread.instances.clear()
    monkeypatch.setattr(pivot.threading, "Thread", FakeThread)
    monkeypatch.setattr(pivot.threading, "Event", FakeEvent)


def _block_socks_import(monkeypatch):
    real_import = builtins.__import__

    def blocked(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "socks":
            raise ImportError("PySocks deliberately unavailable")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", blocked)
    monkeypatch.delitem(sys.modules, "socks", raising=False)


def test_optional_import_fallbacks(monkeypatch):
    real_import = builtins.__import__

    def blocked(name, globals=None, locals=None, fromlist=(), level=0):
        if name in {"config", "paramiko"}:
            raise ImportError(f"blocked {name}")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", blocked)
    namespace = runpy.run_path(pivot.__file__, run_name="_pivot_without_optional_deps")

    assert namespace["paramiko"] is None
    assert namespace["CFG"] == {}


def test_socks_handler_run_closes_on_success_and_failure(monkeypatch):
    client = FakeSocket()
    handler = pivot._Socks5Handler(client, FakeTransport())
    called = []
    monkeypatch.setattr(handler, "_handle", lambda: called.append(True))
    handler.run()
    assert called == [True]
    assert client.closed

    client = FakeSocket()
    handler = pivot._Socks5Handler(client, FakeTransport())
    monkeypatch.setattr(handler, "_handle", Mock(side_effect=RuntimeError("malformed greeting")))
    handler.run()
    assert client.closed


@pytest.mark.parametrize(
    "recv_values, expected_status",
    [
        ([b""], None),
        ([b"\x04\x01"], None),
        ([b"\x05\x01", b"\x00", b"\x05"], None),
        ([b"\x05\x01", b"\x00", b"\x05\x02\x00\x01"], 0x07),
        ([b"\x05\x01", b"\x00", b"\x05\x01\x00\x04"], 0x08),
    ],
)
def test_socks_handler_rejects_invalid_requests(recv_values, expected_status):
    client = FakeSocket(recv=recv_values)
    handler = pivot._Socks5Handler(client, FakeTransport())
    handler._handle()

    if expected_status is None:
        assert len(client.sent) <= 1
    else:
        assert client.sent[-1][1] == expected_status


def test_socks_handler_ipv4_and_domain_requests(monkeypatch):
    channel = SimpleNamespace(closed=False)
    transport = FakeTransport(channel=channel)
    ipv4 = FakeSocket(
        recv=[
            b"\x05\x01",
            b"\x00",
            b"\x05\x01\x00\x01",
            b"\xc0\x00\x02\x09",
            struct.pack("!H", 443),
        ]
    )
    handler = pivot._Socks5Handler(ipv4, transport)
    relay = Mock()
    monkeypatch.setattr(handler, "_relay", relay)
    handler._handle()

    assert transport.open_calls[0][0][1] == ("192.0.2.9", 443)
    assert ipv4.sent[-1][1] == 0
    relay.assert_called_once_with(channel)

    transport = FakeTransport(channel=RuntimeError("channel refused"))
    domain = b"internal.test"
    client = FakeSocket(
        recv=[
            b"\x05\x01",
            b"\x00",
            b"\x05\x01\x00\x03",
            bytes([len(domain)]),
            domain,
            struct.pack("!H", 8080),
        ]
    )
    pivot._Socks5Handler(client, transport)._handle()
    assert transport.open_calls[0][0][1] == ("internal.test", 8080)
    assert client.sent[-1][1] == 5


def test_socks_relay_all_paths(monkeypatch):
    client = FakeSocket(recv=[b"client-data", b""])
    channel = FakeSocket(recv=[b"channel-data", b""])
    channel.closed = False
    selections = deque(
        [
            ([], [], []),
            ([client], [], []),
            ([channel], [], []),
            ([client], [], []),
        ]
    )

    def choose(*_args):
        if len(selections) == 4:
            channel.closed = False
        return selections.popleft()

    monkeypatch.setattr(pivot.select, "select", choose)
    pivot._Socks5Handler(client, FakeTransport())._relay(channel)
    assert channel.sent == [b"client-data"]
    assert client.sent == [b"channel-data"]
    assert channel.closed

    client = FakeSocket()
    channel = FakeSocket()
    channel.closed = True
    monkeypatch.setattr(pivot.select, "select", lambda *_args: ([], [], []))
    pivot._Socks5Handler(client, FakeTransport())._relay(channel)
    assert channel.closed

    client = FakeSocket(recv=[])
    channel = FakeSocket(recv=[b""])
    monkeypatch.setattr(pivot.select, "select", lambda *_args: ([channel], [], []))
    pivot._Socks5Handler(client, FakeTransport())._relay(channel)
    assert channel.closed


def test_forward_handler_all_paths(monkeypatch):
    local = FakeSocket(recv=[b"local-data", b""])
    channel = FakeSocket(recv=[b"remote-data", b""])
    channel.closed = False
    selections = deque(
        [
            ([], [], []),
            ([local], [], []),
            ([channel], [], []),
            ([local], [], []),
        ]
    )
    monkeypatch.setattr(pivot.select, "select", lambda *_args: selections.popleft())
    pivot._forward_handler(local, channel)
    assert channel.sent == [b"local-data"]
    assert local.sent == [b"remote-data"]
    assert local.closed and channel.closed

    local = FakeSocket()
    channel = FakeSocket()
    channel.closed = True
    monkeypatch.setattr(pivot.select, "select", lambda *_args: ([], [], []))
    pivot._forward_handler(local, channel)
    assert local.closed and channel.closed

    local = FakeSocket()
    channel = FakeSocket(recv=[b""])
    monkeypatch.setattr(pivot.select, "select", lambda *_args: ([channel], [], []))
    pivot._forward_handler(local, channel)

    local = FakeSocket()
    channel = FakeSocket()
    monkeypatch.setattr(pivot.select, "select", Mock(side_effect=RuntimeError("relay failed")))
    pivot._forward_handler(local, channel)
    assert local.closed and channel.closed


def test_setup_socks_proxy_preconditions(monkeypatch):
    monkeypatch.setattr(pivot, "paramiko", None)
    assert "paramiko not installed" in pivot.setup_socks_proxy(_client(None))

    monkeypatch.setattr(pivot, "paramiko", object())
    assert "transport is not active" in pivot.setup_socks_proxy(_client(None))
    assert "transport is not active" in pivot.setup_socks_proxy(_client(FakeTransport(active=False)))

    busy = FakeSocket(bind_error=OSError("busy"))
    monkeypatch.setattr(pivot.socket, "socket", lambda *_args: busy)
    assert "already in use" in pivot.setup_socks_proxy(_client(FakeTransport()), 1081)
    assert busy.closed


def test_setup_socks_proxy_listener_paths(monkeypatch):
    _install_thread_doubles(monkeypatch)
    test_socket = FakeSocket()
    accepted = FakeSocket()
    server = FakeSocket()
    sockets = deque([test_socket, server])
    monkeypatch.setattr(pivot, "paramiko", object())
    monkeypatch.setattr(pivot.socket, "socket", lambda *_args: sockets.popleft())

    class Handler:
        instances: ClassVar[list[Handler]] = []

        def __init__(self, client, transport):
            self.client = client
            self.transport = transport
            self.started = False
            type(self).instances.append(self)

        def start(self):
            self.started = True

    monkeypatch.setattr(pivot, "_Socks5Handler", Handler)
    pivot._active_tunnels.clear()
    output = pivot.setup_socks_proxy(_client(FakeTransport()), 1082)
    listener = FakeThread.instances[-1]
    assert listener.started
    assert "SOCKS5 proxy listening" in output
    assert "socks5:1082" in pivot._active_tunnels

    event = pivot._active_tunnels["socks5:1082"]["stop_event"]
    server.accept_values = deque([(accepted, ("local", 1))])
    event.set_states(False, True)
    listener.invoke()
    assert Handler.instances[-1].started
    assert server.closed

    server.closed = False
    server.accept_values = deque([socket.timeout()])
    event.set_states(False, True)
    listener.invoke()
    assert server.closed

    server.closed = False
    server.accept_values = deque([RuntimeError("accept failed")])
    event.set_states(False, False)
    listener.invoke()
    assert server.closed

    server.closed = False
    server.accept_values = deque([RuntimeError("shutdown race")])
    event.set_states(False, True)
    listener.invoke()
    assert server.closed


def test_setup_local_forward_preconditions(monkeypatch):
    monkeypatch.setattr(pivot, "paramiko", None)
    args = (_client(None), 9000, "internal.test", 80)
    assert "paramiko not installed" in pivot.setup_local_forward(*args)

    monkeypatch.setattr(pivot, "paramiko", object())
    assert "transport is not active" in pivot.setup_local_forward(*args)
    assert "transport is not active" in pivot.setup_local_forward(
        _client(FakeTransport(active=False)), 9000, "internal.test", 80
    )

    server = FakeSocket(bind_error=OSError("denied"))
    monkeypatch.setattr(pivot.socket, "socket", lambda *_args: server)
    assert "Cannot bind" in pivot.setup_local_forward(_client(FakeTransport()), 9000, "internal.test", 80)


def test_setup_local_forward_listener_paths(monkeypatch):
    _install_thread_doubles(monkeypatch)
    server = FakeSocket()
    client_socket = FakeSocket()
    channel = FakeSocket()
    transport = FakeTransport(channel=channel)
    monkeypatch.setattr(pivot, "paramiko", object())
    monkeypatch.setattr(pivot.socket, "socket", lambda *_args: server)
    pivot._active_tunnels.clear()

    output = pivot.setup_local_forward(_client(transport), 9001, "internal.test", 443)
    listener = FakeThread.instances[-1]
    assert "Local forward active" in output
    event = pivot._active_tunnels["local:9001->internal.test:443"]["stop_event"]

    server.accept_values = deque([(client_socket, ("local", 2))])
    event.set_states(False, True)
    listener.invoke()
    assert transport.open_calls[-1][0][1] == ("internal.test", 443)
    assert FakeThread.instances[-1].started

    server.accept_values = deque([socket.timeout()])
    event.set_states(False, True)
    listener.invoke()

    server.accept_values = deque([RuntimeError("accept failed")])
    event.set_states(False, False)
    listener.invoke()

    server.accept_values = deque([RuntimeError("shutdown race")])
    event.set_states(False, True)
    listener.invoke()


def test_setup_remote_forward_preconditions(monkeypatch):
    monkeypatch.setattr(pivot, "paramiko", None)
    args = (_client(None), 8000, "127.0.0.1", 4444)
    assert "paramiko not installed" in pivot.setup_remote_forward(*args)

    monkeypatch.setattr(pivot, "paramiko", object())
    assert "transport is not active" in pivot.setup_remote_forward(*args)
    assert "transport is not active" in pivot.setup_remote_forward(
        _client(FakeTransport(active=False)), 8000, "127.0.0.1", 4444
    )

    transport = FakeTransport()
    transport.request_port_forward = Mock(side_effect=RuntimeError("disabled"))
    output = pivot.setup_remote_forward(_client(transport), 8000, "127.0.0.1", 4444)
    assert "Remote forward request failed" in output
    assert "GatewayPorts" in output


def test_setup_remote_forward_handler_paths(monkeypatch):
    _install_thread_doubles(monkeypatch)
    transport = FakeTransport()
    local_socket = FakeSocket()
    channel = FakeSocket()
    monkeypatch.setattr(pivot, "paramiko", object())
    monkeypatch.setattr(pivot.socket, "socket", lambda *_args: local_socket)
    pivot._active_tunnels.clear()

    output = pivot.setup_remote_forward(_client(transport), 8001, "127.0.0.1", 4445)
    handler = FakeThread.instances[-1]
    assert "Remote forward active" in output
    event = pivot._active_tunnels["remote:8001->127.0.0.1:4445"]["stop_event"]

    transport.accept_values = deque([None, channel])
    event.set_states(False, False, True)
    handler.invoke()
    assert ("connect", ("127.0.0.1", 4445)) in local_socket.calls
    assert FakeThread.instances[-1].started

    transport.accept_values = deque([RuntimeError("accept failed")])
    event.set_states(False, False, True)
    handler.invoke()

    transport.accept_values = deque([RuntimeError("shutdown race")])
    event.set_states(False, True, True)
    handler.invoke()


class ChainClient:
    def __init__(self, transport, *, connect_error=None, close_error=None):
        self.transport = transport
        self.connect_error = connect_error
        self.close_error = close_error
        self.connect_calls = []
        self.policy = None
        self.closed = False

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, **kwargs):
        self.connect_calls.append(kwargs)
        if self.connect_error is not None:
            raise self.connect_error

    def get_transport(self):
        return self.transport

    def close(self):
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


def _paramiko_with(clients):
    queue = deque(clients)
    return SimpleNamespace(
        SSHClient=lambda: queue.popleft(),
        AutoAddPolicy=lambda: "accept-new-host-key",
    )


def test_create_ssh_chain_preconditions(monkeypatch):
    monkeypatch.setattr(pivot, "paramiko", None)
    assert pivot.create_ssh_chain([{"host": "hop"}])[0] is None

    monkeypatch.setattr(pivot, "paramiko", object())
    client, output = pivot.create_ssh_chain([])
    assert client is None
    assert "Empty hop list" in output


def test_create_ssh_chain_success_and_history_failure(monkeypatch):
    first_transport = FakeTransport(channel="hop-channel")
    first = ChainClient(first_transport)
    second = ChainClient(FakeTransport())
    monkeypatch.setattr(pivot, "paramiko", _paramiko_with([first, second]))
    responses = deque([RuntimeError("history denied"), "uid=1000(user)\nhop-one", "", ""])

    def fake_exec(*_args, **_kwargs):
        value = responses.popleft()
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(pivot, "_ssh_exec", fake_exec)
    hops = [
        {"host": "hop-one", "user": "alice", "password": "one", "port": 2222},
        {"host": "hop-two"},
    ]
    client, output = pivot.create_ssh_chain(hops)

    assert client is second
    assert "SSH chain established (2 hops)" in output
    assert "uid=1000(user)" in output
    assert "      ?" in output
    assert "sock" not in first.connect_calls[0]
    assert second.connect_calls[0]["sock"] == "hop-channel"
    assert first_transport.open_calls[0][0][1] == ("hop-two", 22)


@pytest.mark.parametrize("close_error", [None, RuntimeError("close failed")])
def test_create_ssh_chain_failure_closes_previous_clients(monkeypatch, close_error):
    first = ChainClient(FakeTransport(channel="nested"), close_error=close_error)
    second = ChainClient(FakeTransport(), connect_error=RuntimeError("auth failed"))
    monkeypatch.setattr(pivot, "paramiko", _paramiko_with([first, second]))
    monkeypatch.setattr(pivot, "_ssh_exec", lambda *_args, **_kwargs: "uid=0(root)")

    client, output = pivot.create_ssh_chain([{"host": "one"}, {"host": "two"}])

    assert client is None
    assert "FAILED: auth failed" in output
    assert first.closed


def test_create_ssh_chain_first_hop_failure_has_no_cleanup_clients(monkeypatch):
    failed = ChainClient(FakeTransport(), connect_error=RuntimeError("offline"))
    monkeypatch.setattr(pivot, "paramiko", _paramiko_with([failed]))
    client, output = pivot.create_ssh_chain([{"host": "one"}])
    assert client is None
    assert "FAILED: offline" in output


class FakeSocksSocket(FakeSocket):
    outcomes: ClassVar[deque] = deque()

    def set_proxy(self, *args):
        self.calls.append(("set_proxy", args))

    def connect(self, address):
        self.calls.append(("connect", address))
        outcome = type(self).outcomes.popleft()
        if isinstance(outcome, BaseException):
            raise outcome


def test_scan_through_pysocks_success_failure_and_default_ports(monkeypatch):
    FakeSocksSocket.outcomes = deque([None, RuntimeError("closed")])
    fake_socks = SimpleNamespace(SOCKS5=5, socksocket=FakeSocksSocket)
    monkeypatch.setitem(sys.modules, "socks", fake_socks)
    output = pivot.scan_through_proxy(1080, "internal.test", [443, 80], timeout=1)
    assert "443/tcp  OPEN" in output
    assert "Closed/filtered: 1" in output

    FakeSocksSocket.outcomes = deque(RuntimeError("closed") for _port in pivot.COMMON_PORTS)
    output = pivot.scan_through_proxy(1080, "internal.test", None, timeout=1)
    assert f"Scanning {len(pivot.COMMON_PORTS)} ports" in output
    assert "Open ports: 0" in output


@pytest.mark.parametrize(
    "effect, expected",
    [
        (SimpleNamespace(stdout="443/tcp open https\n80/tcp closed http\n"), "443"),
        (subprocess.TimeoutExpired("fake-command", 2), "timed out"),
        (RuntimeError("scanner failed"), "Proxy scan error: scanner failed"),
    ],
)
def test_scan_through_mocked_proxychains(monkeypatch, effect, expected):
    _block_socks_import(monkeypatch)
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: f"/fake/{name}")

    def fake_run(*_args, **_kwargs):
        if isinstance(effect, BaseException):
            raise effect
        return effect

    monkeypatch.setattr(pivot.subprocess, "run", fake_run)
    output = pivot.scan_through_proxy(1080, "192.0.2.1", [443], timeout=2)
    assert expected in output


def test_scan_through_raw_socks_all_protocol_outcomes(monkeypatch):
    _block_socks_import(monkeypatch)
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _name: None)
    sockets = deque(
        [
            FakeSocket(recv=[b""]),
            FakeSocket(recv=[b"\x05\x02"]),
            FakeSocket(recv=[b"\x05\x00", b"\x05\x00" + b"\x00" * 8]),
            FakeSocket(recv=[b"\x05\x00", b"\x05\x05" + b"\x00" * 8]),
            FakeSocket(recv=[RuntimeError("proxy unavailable")]),
        ]
    )
    monkeypatch.setattr(pivot.socket, "socket", lambda *_args: sockets.popleft())
    output = pivot.scan_through_proxy(1080, "192.0.2.10", [21, 22, 23, 24, 25], timeout=1)
    assert "23/tcp  OPEN" in output
    assert "Closed/filtered: 2" in output
    assert "Open: 23" in output


def test_get_network_info_success_fallbacks_and_filtering(monkeypatch):
    results = {
        "ip -4 addr show 2>/dev/null": "[!] unavailable",
        "ifconfig 2>/dev/null": ("inet 10.0.0.2/24 inet 10.0.0.2/24 inet 127.0.0.1/8"),
        "ip route show 2>/dev/null": "",
        "route -n 2>/dev/null": "10.1.0.0/16 via 10.0.0.1",
        "ip neigh show 2>/dev/null": "",
        "arp -an 2>/dev/null": ("10.0.0.1 10.0.0.1 127.0.0.1 0.0.0.0 255.255.255.255"),
        "cat /etc/resolv.conf 2>/dev/null": "nameserver 10.0.0.53",
        "ss -tlnp 2>/dev/null": "",
        "netstat -tlnp 2>/dev/null": "LISTEN 10.0.0.2:22",
        "ss -tnp state established 2>/dev/null | head -30": "",
        "netstat -tnp 2>/dev/null | grep ESTABLISHED | head -30": ("ESTABLISHED 10.0.0.2:22 10.0.0.9:50000"),
    }
    monkeypatch.setattr(pivot, "_ssh_exec", lambda _client, cmd, timeout: results.get(cmd, ""))
    output = pivot.get_network_info(object())

    assert "10.0.0.2/24" in output
    assert "10.1.0.0/16" in output
    assert "127.0.0.1/8" not in output.split("[SUMMARY]", 1)[1]
    assert "→ 10.0.0.53" in output
    assert "255.255.255.255" not in output.split("[SUMMARY]", 1)[1]


def test_get_network_info_all_enumeration_failures(monkeypatch):
    monkeypatch.setattr(pivot, "_ssh_exec", lambda *_args, **_kwargs: "[!] denied")
    output = pivot.get_network_info(object())
    assert "Could not enumerate interfaces" in output
    assert "Could not enumerate routes" in output
    assert "Could not enumerate ARP table" in output
    assert "Subnets: none" in output
    assert "Hosts:   0" in output


def test_get_network_info_first_commands_succeed(monkeypatch):
    monkeypatch.setattr(
        pivot,
        "_ssh_exec",
        lambda _client, cmd, timeout: "192.0.2.5/32" if cmd.startswith(("ip ", "ss ")) else "",
    )
    output = pivot.get_network_info(object())
    assert "192.0.2.5/32" in output
    assert "→ 192.0.2.5" in output
