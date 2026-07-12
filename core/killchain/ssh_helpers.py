#!/usr/bin/env python3

import logging
import os
import socket
import time

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    from config import CFG, find_all_wordlists, find_wordlist
except ImportError:
    CFG = {}
    def find_wordlist(cat): return ""
    def find_all_wordlists(cat): return []

# ANSI Colors
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_CYAN   = "\033[96m"
C_GREY   = "\033[90m"
C_BLUE   = "\033[94m"
C_MAGENTA = "\033[95m"
C_RESET  = "\033[0m"


# PARAMIKO SSH HELPERS (shared across stages)


def _ssh_connect(host: str, user: str, password: str, port: int = 22, timeout: int = 15):
    """Connect via paramiko. Returns (client, error_str).
    Supports key-based authentication via the ``__KEY_AUTH__`` marker."""
    if paramiko is None:
        return None, "paramiko not installed"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Key-based authentication.
    if password == "__KEY_AUTH__":
        key_path = os.path.expanduser("~/.ssh/id_rsa")
        if os.path.isfile(key_path):
            try:
                pkey = paramiko.RSAKey.from_private_key_file(key_path)
                client.connect(
                    hostname=host, port=port, username=user, pkey=pkey,
                    timeout=timeout, allow_agent=False, look_for_keys=False,
                    banner_timeout=10, auth_timeout=15
                )
                try:
                    _ssh_exec(client, "unset HISTFILE; export HISTFILE=/dev/null; export HISTSIZE=0", timeout=5)
                except Exception as _exc:
                    logging.debug(f"Suppressed in ssh_helpers.py: {_exc}")
                return client, None
            except Exception as e:
                return None, f"Key auth failed: {user}@{host}: {e}"
        return None, f"No SSH key found at {key_path}"

    # Standard password auth
    try:
        client.connect(
            hostname=host, port=port, username=user, password=password,
            timeout=timeout, look_for_keys=False, allow_agent=False,
            banner_timeout=10, auth_timeout=15
        )
        # Disable history immediately
        try:
            _ssh_exec(client, "unset HISTFILE; export HISTFILE=/dev/null; export HISTSIZE=0", timeout=5)
        except Exception as _exc:
            logging.debug(f"Suppressed in ssh_helpers.py: {_exc}")
        return client, None
    except paramiko.AuthenticationException:
        # Fall back to key authentication for root.
        if user == "root":
            key_path = os.path.expanduser("~/.ssh/id_rsa")
            if os.path.isfile(key_path):
                try:
                    client2 = paramiko.SSHClient()
                    client2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    pkey = paramiko.RSAKey.from_private_key_file(key_path)
                    client2.connect(
                        hostname=host, port=port, username="root", pkey=pkey,
                        timeout=timeout, allow_agent=False, look_for_keys=False,
                        banner_timeout=10, auth_timeout=15
                    )
                    try:
                        _ssh_exec(client2, "unset HISTFILE; export HISTFILE=/dev/null; export HISTSIZE=0", timeout=5)
                    except Exception as _exc:
                        logging.debug(f"Suppressed in ssh_helpers.py: {_exc}")
                    print(f"  {C_GREEN}[+] Password auth failed but SSH key auth succeeded for root{C_RESET}")
                    return client2, None
                except Exception as _exc:
                    logging.debug(f"Suppressed in ssh_helpers.py: {_exc}")
        return None, f"Auth failed: {user}:{password}@{host}"
    except Exception as e:
        return None, str(e)


def _ssh_exec(client, cmd: str, timeout: int = 30) -> str:
    """Execute command on SSH client. Returns stdout+stderr.
    Uses an incremental ``channel.recv()`` loop to prevent deadlock when
    stdout buffer fills before command exits (e.g. large find output).
    """
    try:
        transport = client.get_transport()
        if not transport or not transport.is_active():
            return "[!] SSH transport is closed"
        channel = transport.open_session()
        channel.settimeout(timeout)
        channel.exec_command(cmd)

        stdout_chunks = []
        stderr_chunks = []
        start_time = time.time()
        # Read incrementally while command runs — no deadlock
        while not channel.exit_status_ready():
            # Enforce a wall-clock timeout even when the SSH library stalls.
            if time.time() - start_time > timeout:
                channel.close()
                partial = b"".join(stdout_chunks).decode("utf-8", errors="replace")
                return partial.strip() if partial else f"[!] Command timed out after {timeout}s (force killed)"
            if channel.recv_ready():
                stdout_chunks.append(channel.recv(65536))
            if channel.recv_stderr_ready():
                stderr_chunks.append(channel.recv_stderr(65536))
            time.sleep(0.02)
        # Drain any remaining data after command exits
        while channel.recv_ready():
            stdout_chunks.append(channel.recv(65536))
        while channel.recv_stderr_ready():
            stderr_chunks.append(channel.recv_stderr(65536))

        exit_code = channel.recv_exit_status()
        channel.close()

        out = b"".join(stdout_chunks).decode("utf-8", errors="replace")
        err = b"".join(stderr_chunks).decode("utf-8", errors="replace")

        # Filter binary and non-printable content.
        def _filter_bin(text):
            if not text:
                return text
            printable_count = sum(1 for c in text[:500] if c.isprintable() or c in '\n\r\t')
            total = min(len(text), 500)
            if total > 20 and printable_count / total < 0.7:
                return "[BINARY DATA — not displayed]"
            clean_lines = []
            for line in text.splitlines():
                if len(line) > 10:
                    lp = sum(1 for c in line if c.isprintable() or c in '\t')
                    if lp / len(line) < 0.6:
                        continue
                clean_lines.append(line)
            return "\n".join(clean_lines)

        out = _filter_bin(out)
        err = _filter_bin(err)

        result = (out + err).strip()
        if not result and exit_code != 0:
            result = f"[!] Command exited with code {exit_code} (no output)"
        return result
    except socket.timeout:
        return f"[!] Command timed out after {timeout}s: {cmd[:60]}"
    except Exception as e:
        return f"[!] Command failed: {e}"


def _is_port_open(host: str, port: int, timeout: int = 5) -> bool:
    """Quick TCP port check."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((host, port)) == 0
    except Exception:
        return False
    finally:
        sock.close()
