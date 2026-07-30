"""Hermetic branch coverage for the legacy evasion compatibility module."""

from __future__ import annotations

import builtins
import io
import runpy
import sys
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

import evasion

pytestmark = pytest.mark.unit


class AuthError(Exception):
    pass


class SSHError(Exception):
    pass


class FakeSocket:
    def __init__(
        self,
        *,
        connect_error: Exception | None = None,
        connect_ex_result: int = 0,
        recv_values: tuple[bytes, ...] = (b"250 OK", b"250 OK"),
    ) -> None:
        self.connect_error = connect_error
        self.connect_ex_result = connect_ex_result
        self.recv_values = list(recv_values)
        self.timeout: float | None = None
        self.connected_to: Any = None
        self.sent: list[bytes] = []
        self.closed = False
        self.proxy: tuple[Any, ...] | None = None

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def connect(self, address: Any) -> None:
        if self.connect_error is not None:
            raise self.connect_error
        self.connected_to = address

    def connect_ex(self, address: Any) -> int:
        self.connected_to = address
        return self.connect_ex_result

    def send(self, value: bytes) -> None:
        self.sent.append(value)

    def recv(self, _size: int) -> bytes:
        return self.recv_values.pop(0)

    def close(self) -> None:
        self.closed = True

    def set_proxy(self, *args: Any) -> None:
        self.proxy = args


class FakeTransport:
    def __init__(self, spec: dict[str, Any] | None = None) -> None:
        self.spec = spec or {}
        self.auth_actions = list(self.spec.get("auth", [None]))
        self.local_version = ""
        self.closed = False

    def connect(self) -> None:
        error = self.spec.get("connect_error")
        if error is not None:
            raise error

    def auth_password(self, _user: str, _password: str) -> None:
        action = self.auth_actions.pop(0) if self.auth_actions else None
        if isinstance(action, BaseException):
            raise action

    def close(self) -> None:
        self.closed = True
        if self.spec.get("close_error"):
            raise RuntimeError("close failed")


class TransportFactory:
    def __init__(self, specs: list[dict[str, Any]]) -> None:
        self.specs = list(specs)
        self.transports: list[FakeTransport] = []

    def __call__(self, _socket_or_address: Any) -> FakeTransport:
        spec = self.specs.pop(0) if self.specs else {"auth": [AuthError()]}
        transport = FakeTransport(spec)
        self.transports.append(transport)
        return transport


class FakeCookies:
    def __init__(self, values: dict[str, str] | None = None) -> None:
        self.values = values or {}

    def get_dict(self) -> dict[str, str]:
        return dict(self.values)


class FakeHTMLNode:
    def __init__(self, tag: str, attrs: list[tuple[str, str | None]] | None = None) -> None:
        self.tag = tag
        self.attrs = dict(attrs or [])
        self.children: list[FakeHTMLNode] = []

    def get(self, name: str, default: str = "") -> str:
        return self.attrs.get(name) or default

    def find_all(self, names, attrs: dict[str, str] | None = None) -> list[FakeHTMLNode]:
        accepted = {names} if isinstance(names, str) else set(names)
        found = []
        for child in self.children:
            matches_attrs = not attrs or all(child.get(key) == value for key, value in attrs.items())
            if child.tag in accepted and matches_attrs:
                found.append(child)
            found.extend(child.find_all(names, attrs))
        return found

    def find(self, name: str) -> FakeHTMLNode | None:
        matches = self.find_all(name)
        return matches[0] if matches else None


class FakeBeautifulSoup(HTMLParser):
    _VOID_TAGS: ClassVar[set[str]] = {"input", "meta", "link", "br", "hr", "img"}

    def __init__(self, source: str, _parser: str) -> None:
        super().__init__()
        self.root = FakeHTMLNode("document")
        self._stack = [self.root]
        self.feed(source)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = FakeHTMLNode(tag, attrs)
        self._stack[-1].children.append(node)
        if tag not in self._VOID_TAGS:
            self._stack.append(node)

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self._stack) - 1, 0, -1):
            if self._stack[index].tag == tag:
                del self._stack[index:]
                return

    def find_all(self, names, attrs: dict[str, str] | None = None) -> list[FakeHTMLNode]:
        return self.root.find_all(names, attrs)

    def find(self, name: str) -> FakeHTMLNode | None:
        return self.root.find(name)


@pytest.fixture(autouse=True)
def _fake_beautiful_soup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "bs4", SimpleNamespace(BeautifulSoup=FakeBeautifulSoup))


class FakeResponse:
    def __init__(
        self,
        status_code: int = 200,
        text: str = "ok",
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.cookies = FakeCookies(cookies)


class FakeHTTPSession:
    def __init__(
        self,
        gets: list[FakeResponse | BaseException] | None = None,
        posts: list[FakeResponse | BaseException] | None = None,
    ) -> None:
        self.gets = list(gets or [FakeResponse()])
        self.posts = list(posts or [FakeResponse()])
        self.proxies: dict[str, str] = {}
        self.mounts: list[tuple[str, Any]] = []
        self.get_calls: list[tuple[str, dict[str, Any]]] = []
        self.post_calls: list[tuple[str, dict[str, Any]]] = []

    def mount(self, prefix: str, adapter: Any) -> None:
        self.mounts.append((prefix, adapter))

    @staticmethod
    def _next(items: list[FakeResponse | BaseException]) -> FakeResponse:
        item = items.pop(0) if len(items) > 1 else items[0]
        if isinstance(item, BaseException):
            raise item
        return item

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.get_calls.append((url, kwargs))
        return self._next(self.gets)

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        self.post_calls.append((url, kwargs))
        return self._next(self.posts)


def _patch_ssh(
    monkeypatch: pytest.MonkeyPatch,
    specs: list[dict[str, Any]],
    socket_factory: Any | None = None,
) -> TransportFactory:
    factory = TransportFactory(specs)
    fake_paramiko = SimpleNamespace(
        AuthenticationException=AuthError,
        SSHException=SSHError,
        Transport=factory,
    )
    monkeypatch.setattr(evasion, "_PARAMIKO_OK", True)
    monkeypatch.setattr(evasion, "paramiko", fake_paramiko)
    monkeypatch.setattr(
        evasion.socket,
        "socket",
        socket_factory or (lambda *_args, **_kwargs: FakeSocket()),
    )
    monkeypatch.setattr(evasion.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(evasion.time, "time", lambda: 100.0)
    monkeypatch.setattr(evasion.random, "choice", lambda values: values[0])
    monkeypatch.setattr(evasion.random, "uniform", lambda _start, _end: 0.0)
    monkeypatch.setattr(evasion.random, "randint", lambda _start, _end: 0)
    return factory


def _patch_http_constructor(
    monkeypatch: pytest.MonkeyPatch,
    session: FakeHTTPSession,
    *,
    tor_available: bool = False,
) -> None:
    monkeypatch.setattr(
        evasion,
        "_requests",
        SimpleNamespace(Session=lambda: session),
    )
    monkeypatch.setattr(evasion, "_REQUESTS_OK", True)
    monkeypatch.setattr(evasion, "HTTPAdapter", lambda **kwargs: kwargs)
    monkeypatch.setattr(evasion, "_check_tor_running", lambda: tor_available)
    monkeypatch.setattr(evasion.time, "sleep", lambda _seconds: None)


def test_optional_import_fallbacks_and_unavailable_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import = builtins.__import__

    def blocked_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.split(".", 1)[0] in {"paramiko", "requests", "socks", "config"}:
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(builtins, "__import__", blocked_import)
        namespace = runpy.run_path(
            str(Path(evasion.__file__)),
            run_name="evasion_optional_import_fallbacks",
        )

    assert namespace["_PARAMIKO_OK"] is False
    assert namespace["_REQUESTS_OK"] is False
    assert namespace["_SOCKS_OK"] is False
    assert namespace["CFG"] == {}
    assert "paramiko not installed" in namespace["ssh_bruteforce_stealth"]("host")
    with pytest.raises(ImportError, match="requests not installed"):
        namespace["WebEvasionSession"]()


def test_tor_and_proxy_socket_helpers_never_leave_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sockets = iter(
        [
            FakeSocket(connect_ex_result=0),
            FakeSocket(connect_ex_result=1),
            FakeSocket(recv_values=(b"250 AUTH", b"250 NEWNYM")),
            FakeSocket(recv_values=(b"515 denied",)),
        ]
    )
    monkeypatch.setattr(evasion.socket, "socket", lambda *_args: next(sockets))
    monkeypatch.setattr(evasion.time, "sleep", lambda _seconds: None)

    assert evasion._check_tor_running() is True
    assert evasion._check_tor_running() is False
    evasion._get_tor_new_identity()
    evasion._get_tor_new_identity()

    monkeypatch.setattr(
        evasion.socket,
        "socket",
        lambda *_args: (_ for _ in ()).throw(OSError("blocked")),
    )
    assert evasion._check_tor_running() is False
    evasion._get_tor_new_identity()

    proxy_sockets: list[FakeSocket] = []

    def proxy_factory() -> FakeSocket:
        result = FakeSocket()
        proxy_sockets.append(result)
        return result

    monkeypatch.setattr(
        evasion,
        "socks",
        SimpleNamespace(
            socksocket=proxy_factory,
            SOCKS5="socks5",
            SOCKS4="socks4",
            HTTP="http",
        ),
    )
    monkeypatch.setattr(evasion, "_SOCKS_OK", True)
    for proxy_type in ("socks5", "socks4", "http", "unknown"):
        assert evasion._create_proxy_socket("host", 22, proxy_type=proxy_type).closed is False
    assert [item.proxy for item in proxy_sockets] == [
        ("socks5", "127.0.0.1", 9050),
        ("socks4", "127.0.0.1", 9050),
        ("http", "127.0.0.1", 9050),
        None,
    ]

    direct = FakeSocket()
    monkeypatch.setattr(evasion, "_SOCKS_OK", False)
    monkeypatch.setattr(evasion.socket, "socket", lambda *_args: direct)
    assert evasion._create_proxy_socket("host", 80) is direct


def test_ssh_bruteforce_defaults_success_and_summaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_ssh(monkeypatch, [{"auth": [None]}])
    result = evasion.ssh_bruteforce_stealth("host")
    assert "VALID CREDENTIALS: root:root" in result
    assert "CREDENTIALS FOUND" in result

    _patch_ssh(monkeypatch, [{"auth": [None, AuthError()]}])
    result = evasion.ssh_bruteforce_stealth(
        "host",
        users=["alice"],
        passwords=["a-very-long-password-value", "wrong"],
        max_attempts_per_conn=3,
        base_delay=0,
        jitter=0,
    )
    assert "alice:a-very-long-password-value" in result
    assert "Attempts: 2" in result
    assert "No credentials found" in evasion._format_brute_summary([], 1, 1, 0, 0)
    assert evasion._fmt_time(119) == "119s"
    assert evasion._fmt_time(125) == "2m05s"
    assert evasion._fmt_time(7_265) == "2h01m"


def test_ssh_password_file_loading_caps_and_ignores_bad_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_text(
        "\n# comment\nalice:pass\nbob:" + "x" * 64 + "\n$6$hash:salt\npass\nlast\n",
        encoding="utf-8",
    )
    real_open = builtins.open
    real_isfile = evasion.os.path.isfile

    def fake_open(path: Any, *args: Any, **kwargs: Any) -> Any:
        if str(path).endswith("unreadable"):
            raise OSError("unreadable")
        return real_open(path, *args, **kwargs)

    def fake_isfile(path: Any) -> bool:
        return str(path).endswith("unreadable") or real_isfile(path)

    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr(evasion.os.path, "isfile", fake_isfile)
    _patch_ssh(monkeypatch, [{"auth": [AuthError()] * 4}])
    result = evasion.ssh_bruteforce_stealth(
        "host",
        users=["alice"],
        password_files=[
            str(tmp_path / "missing"),
            str(tmp_path / "unreadable"),
            str(wordlist),
        ],
        max_passwords=4,
        max_attempts_per_conn=10,
        base_delay=0,
        jitter=0,
    )
    assert "Passwords: 4" in result
    assert "Attempts: 4" in result


@pytest.mark.parametrize(
    "first_error",
    [
        SSHError("too many authentication failures"),
        SSHError("method not allowed"),
        SSHError("no authentication methods"),
        SSHError("other protocol failure"),
        EOFError(),
        RuntimeError("unexpected auth error"),
    ],
)
def test_ssh_authentication_interrupts_retry_same_credential(
    first_error: BaseException,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = _patch_ssh(
        monkeypatch,
        [
            {"auth": [first_error]},
            {"auth": [AuthError()]},
        ],
    )
    result = evasion.ssh_bruteforce_stealth(
        "host",
        users=["alice"],
        passwords=["wrong"],
        max_attempts_per_conn=1,
        base_delay=0,
        jitter=0,
    )
    assert "Attempts: 2" in result
    assert len(factory.transports) == 2


def test_ssh_tor_rotation_and_ban_recovery_are_mocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_ssh(monkeypatch, [{"auth": [AuthError()]} for _ in range(4)])
    monkeypatch.setattr(evasion, "_SOCKS_OK", True)
    monkeypatch.setattr(evasion, "_check_tor_running", lambda: True)
    monkeypatch.setattr(evasion, "_create_proxy_socket", lambda *_args: FakeSocket())
    identities: list[bool] = []
    monkeypatch.setattr(evasion, "_get_tor_new_identity", lambda: identities.append(True))
    result = evasion.ssh_bruteforce_stealth(
        "host",
        users=["alice"],
        passwords=["one", "two", "three", "four"],
        use_tor=True,
        max_attempts_per_conn=1,
        base_delay=0,
        jitter=0,
    )
    assert "Routing: TOR" in result
    assert identities == [True]

    calls = 0

    def flaky_proxy(*_args: Any) -> FakeSocket:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ConnectionRefusedError("mocked ban")
        return FakeSocket()

    _patch_ssh(monkeypatch, [{"auth": [AuthError()]}])
    monkeypatch.setattr(evasion, "_SOCKS_OK", True)
    monkeypatch.setattr(evasion, "_check_tor_running", lambda: True)
    monkeypatch.setattr(evasion, "_create_proxy_socket", flaky_proxy)
    monkeypatch.setattr(evasion, "_get_tor_new_identity", lambda: identities.append(True))
    result = evasion.ssh_bruteforce_stealth(
        "host",
        users=["alice"],
        passwords=["wrong"],
        use_tor=True,
        max_attempts_per_conn=1,
        max_ban_retries=2,
        base_delay=0,
        jitter=0,
    )
    assert "Bans detected: 1" in result


def test_ssh_direct_ban_countdown_and_max_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    socket_items = iter(
        [
            FakeSocket(connect_error=ConnectionRefusedError("mocked ban")),
            FakeSocket(connect_ex_result=1),
            FakeSocket(connect_ex_result=0),
            FakeSocket(),
        ]
    )
    _patch_ssh(
        monkeypatch,
        [{"auth": [AuthError()]}],
        socket_factory=lambda *_args: next(socket_items),
    )
    result = evasion.ssh_bruteforce_stealth(
        "host",
        users=["alice"],
        passwords=["wrong"],
        ban_wait=31,
        max_ban_retries=2,
        max_attempts_per_conn=1,
        base_delay=0,
        jitter=0,
    )
    assert "Bans detected: 1" in result

    _patch_ssh(
        monkeypatch,
        [],
        socket_factory=lambda *_args: FakeSocket(connect_error=ConnectionRefusedError("mocked ban")),
    )
    result = evasion.ssh_bruteforce_stealth(
        "host",
        users=["alice"],
        passwords=["wrong"],
        max_ban_retries=0,
        base_delay=0,
        jitter=0,
    )
    assert "max ban retries exceeded" in result


@pytest.mark.parametrize("outer_error", [OSError("ban"), SSHError("protocol"), RuntimeError("other")])
def test_ssh_outer_failures_roll_back_completed_attempt(
    outer_error: BaseException,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_ssh(
        monkeypatch,
        [
            {"auth": [AuthError()]},
            {"auth": [AuthError()]},
        ],
    )
    sleep_calls = 0

    def fake_sleep(_seconds: float) -> None:
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls == 1:
            raise outer_error

    monkeypatch.setattr(evasion.time, "sleep", fake_sleep)
    result = evasion.ssh_bruteforce_stealth(
        "host",
        users=["alice"],
        passwords=["wrong"],
        max_attempts_per_conn=1,
        max_ban_retries=0 if isinstance(outer_error, OSError) else 2,
        base_delay=0,
        jitter=0,
    )
    expected = 1 if isinstance(outer_error, OSError) else 2
    assert f"Attempts: {expected}" in result


def test_web_session_headers_throttle_requests_and_challenges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http = FakeHTTPSession(
        gets=[
            FakeResponse(403, headers={"cf-ray": "ray"}),
            FakeResponse(200, "retried"),
        ],
        posts=[
            FakeResponse(503, "cloudflare"),
            FakeResponse(200, "retried"),
        ],
    )
    _patch_http_constructor(monkeypatch, http, tor_available=True)
    identities: list[bool] = []
    monkeypatch.setattr(evasion, "_get_tor_new_identity", lambda: identities.append(True))
    monkeypatch.setattr(evasion.random, "choice", lambda values: values[0])
    monkeypatch.setattr(evasion.random, "randint", lambda start, _end: start)

    session = evasion.WebEvasionSession(use_tor=True, rotate_ua=True)
    assert session.session.proxies["http"].startswith("socks5h")
    headers = session._get_headers("https://example.com/path", {"X-Test": "yes"})
    assert headers["User-Agent"] == evasion._USER_AGENTS[0]
    assert headers["Referer"].startswith("https://www.google.com")
    assert headers["X-Test"] == "yes"
    session.rotate_ua = False
    assert session._get_headers()["User-Agent"] == evasion._USER_AGENTS[0]

    sleeps: list[float] = []
    times = iter([10.0, 11.0])
    monkeypatch.setattr(evasion.time, "time", lambda: next(times))
    monkeypatch.setattr(evasion.time, "sleep", sleeps.append)
    monkeypatch.setattr(evasion.random, "uniform", lambda _start, _end: 0.0)
    session._last_request_time = 9.5
    session._throttle()
    assert sleeps == [0.5]

    monkeypatch.setattr(session, "_throttle", lambda: None)
    monkeypatch.setattr(evasion.time, "sleep", lambda _seconds: None)
    session.request_count = 19
    assert session.get("https://example.com").text == "retried"
    session.request_count = 19
    assert (
        session.post(
            "https://example.com/login",
            content_type="application/json",
        ).text
        == "retried"
    )
    assert len(identities) == 4

    no_wait_http = FakeHTTPSession(gets=[FakeResponse()], posts=[FakeResponse()])
    _patch_http_constructor(monkeypatch, no_wait_http, tor_available=False)
    no_wait = evasion.WebEvasionSession(use_tor=False, rotate_ua=False)
    monkeypatch.setattr(no_wait, "_throttle", lambda: None)
    assert no_wait.get("http://example.com").status_code == 200
    assert no_wait.post("http://example.com").status_code == 200


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (FakeResponse(403, headers={"cf-ray": "x"}), True),
        (FakeResponse(403), False),
        (FakeResponse(503, "cloudflare challenge"), True),
        (FakeResponse(503, headers={"cf-test": "x"}), True),
        (FakeResponse(503, "plain"), False),
        (FakeResponse(200, "Checking Your Browser"), True),
        (FakeResponse(429), True),
        (FakeResponse(200), False),
    ],
)
def test_cloudflare_challenge_detection(response: FakeResponse, expected: bool) -> None:
    session = evasion.WebEvasionSession.__new__(evasion.WebEvasionSession)
    assert session._is_cloudflare_challenge(response) is expected


def test_detect_waf_signatures_blocks_and_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = evasion.WebEvasionSession.__new__(evasion.WebEvasionSession)
    responses: list[FakeResponse | BaseException] = [
        FakeResponse(
            headers={"CF-RAY": "ray", "X-Other": "ok"},
            cookies={"incap_ses_1": "yes"},
        ),
        FakeResponse(403),
        FakeResponse(200),
        RuntimeError("probe failed"),
    ]

    def fake_get(_url: str, **_kwargs: Any) -> FakeResponse:
        item = responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    monkeypatch.setattr(session, "get", fake_get)
    result = session.detect_waf("https://example.com")
    assert result["waf_detected"] is True
    assert any("Signature" in item for item in result["details"])
    assert any("Blocked payload" in item for item in result["details"])

    monkeypatch.setattr(
        session,
        "get",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("offline")),
    )
    assert session.detect_waf("https://example.com")["details"] == ["Error: offline"]


LOGIN_HTML = """
<form action="/login" method="post">
  <input>
  <input type="text" name="username" value="">
  <input type="password" name="password" value="">
  <input type="hidden" name="csrf" value="token">
  <input type="submit" name="submit" value="">
  <select name="ignored"><option>one</option></select>
</form>
"""


def test_web_bruteforce_form_detection_success_and_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeHTTPSession(
        gets=[FakeResponse(text=LOGIN_HTML)],
        posts=[
            FakeResponse(500, "error"),
            FakeResponse(200, "invalid password"),
            FakeResponse(200, "plain page"),
            FakeResponse(302, "redirect"),
            FakeResponse(200, "welcome dashboard"),
        ],
    )
    monkeypatch.setattr(evasion, "WebEvasionSession", lambda **_kwargs: fake)
    monkeypatch.setattr(evasion.time, "sleep", lambda _seconds: None)
    output = evasion.web_bruteforce_stealth(
        "https://example.com/login",
        users=["one", "two", "three", "four", "five"],
        passwords=["password"],
    )
    assert "Found 2 valid credential" in output
    assert fake.post_calls[0][0] == "https://example.com/login"

    no_form = FakeHTTPSession(gets=[FakeResponse(text="<html></html>")])
    monkeypatch.setattr(evasion, "WebEvasionSession", lambda **_kwargs: no_form)
    assert "No login form" in evasion.web_bruteforce_stealth("https://example.com")

    missing_fields = FakeHTTPSession(gets=[FakeResponse(text='<form><input type="password" name="password"></form>')])
    monkeypatch.setattr(evasion, "WebEvasionSession", lambda **_kwargs: missing_fields)
    assert "Could not identify" in evasion.web_bruteforce_stealth(
        "https://example.com",
        users=["one"],
        passwords=["one"],
    )

    failed_fetch = FakeHTTPSession(gets=[RuntimeError("offline")])
    monkeypatch.setattr(evasion, "WebEvasionSession", lambda **_kwargs: failed_fetch)
    assert "Failed to fetch login page" in evasion.web_bruteforce_stealth(
        "https://example.com",
        users=["one"],
        passwords=["one"],
    )


def test_web_bruteforce_password_files_refresh_and_rate_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wordlist = tmp_path / "web-passwords.txt"
    wordlist.write_text("# ignore\none\none\ntwo\n", encoding="utf-8")
    fake = FakeHTTPSession(
        gets=[FakeResponse(text=LOGIN_HTML)],
        posts=[RuntimeError("429 rate limited"), RuntimeError("offline")],
    )
    monkeypatch.setattr(evasion, "WebEvasionSession", lambda **_kwargs: fake)
    monkeypatch.setattr(evasion.time, "sleep", lambda _seconds: None)
    output = evasion.web_bruteforce_stealth(
        "https://example.com/login",
        users=["alice"],
        password_files=[str(tmp_path / "missing"), str(wordlist)],
    )
    assert "No valid credentials" in output

    many_users = [f"user-{index}" for index in range(50)]
    fresh_html = '<form><input type="hidden" name="fresh" value="yes"><input type="hidden"></form>'
    refresh = FakeHTTPSession(
        gets=[FakeResponse(text=LOGIN_HTML), FakeResponse(text=fresh_html)],
        posts=[FakeResponse(200, "invalid")],
    )
    monkeypatch.setattr(evasion, "WebEvasionSession", lambda **_kwargs: refresh)
    output = evasion.web_bruteforce_stealth(
        "https://example.com/login",
        users=many_users,
        passwords=["wrong"],
    )
    assert "Attempts: 50/50" in output
    assert refresh.post_calls[-1][1]["data"]["fresh"] == "yes"

    huge_words = "\n".join(f"password-{index}" for index in range(5_001))
    real_open = builtins.open

    def fake_open(path: Any, *args: Any, **kwargs: Any) -> Any:
        if str(path) == "huge":
            return io.StringIO(huge_words)
        raise OSError("unreadable")

    monkeypatch.setattr(builtins, "open", fake_open)
    no_form = FakeHTTPSession(gets=[FakeResponse(text="<html></html>")])
    monkeypatch.setattr(evasion, "WebEvasionSession", lambda **_kwargs: no_form)
    assert "No login form" in evasion.web_bruteforce_stealth(
        "https://example.com/login",
        users=["alice"],
        password_files=["bad", "huge"],
    )
    monkeypatch.setattr(builtins, "open", real_open)


def test_service_dispatch_and_credential_spray(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ssh_calls: list[tuple[Any, ...]] = []
    web_calls: list[str] = []
    monkeypatch.setattr(
        evasion,
        "ssh_bruteforce_stealth",
        lambda target, **kwargs: ssh_calls.append((target, kwargs)) or "ssh",
    )
    monkeypatch.setattr(
        evasion,
        "web_bruteforce_stealth",
        lambda url, **_kwargs: web_calls.append(url) or "web",
    )
    assert evasion.service_bruteforce_stealth("ssh", "host") == "ssh"
    assert evasion.service_bruteforce_stealth("sftp", "host", 2222) == "ssh"
    assert evasion.service_bruteforce_stealth("http", "host", 80) == "web"
    assert evasion.service_bruteforce_stealth("web", "host", 8080) == "web"
    assert evasion.service_bruteforce_stealth("https", "host", 443) == "web"
    assert evasion.service_bruteforce_stealth("https-post-form", "host", 8443) == "web"
    assert evasion.service_bruteforce_stealth("ftp", "host") is None
    assert web_calls == [
        "http://host",
        "http://host:8080",
        "https://host",
        "https://host:8443",
    ]

    monkeypatch.setattr(evasion, "_PARAMIKO_OK", False)
    assert evasion.credential_spray(["host"], [("u", "p")]) == []
    monkeypatch.setattr(evasion, "_PARAMIKO_OK", True)
    assert evasion.credential_spray([], [("u", "p")]) == []
    assert evasion.credential_spray(["host"], []) == []

    factory = _patch_ssh(
        monkeypatch,
        [
            {"auth": [None]},
            {"auth": [AuthError()]},
            {"auth": [RuntimeError("offline")], "close_error": True},
        ],
    )
    monkeypatch.setattr(evasion.random, "shuffle", lambda _items: None)
    successes = evasion.credential_spray(
        ["one", "two", "three"],
        [("alice", "password"), ("bob", "password")],
        delay=0,
    )
    assert successes[0]["target"] == "one"
    assert factory.transports
    assert (
        evasion.credential_spray(
            ["one"],
            [("alice", "password")],
            service="ftp",
            delay=0,
        )
        == []
    )


@pytest.mark.parametrize("mode", ["ssh", "web", "detect", "unknown"])
def test_main_modes_are_hermetic(
    mode: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    responses = [FakeResponse(text="<html></html>")]
    if mode == "detect":
        responses = [FakeResponse() for _ in range(4)]
    fake_http = FakeHTTPSession(gets=responses)
    import requests

    monkeypatch.setattr(requests, "Session", lambda: fake_http)
    monkeypatch.setattr(evasion.socket, "socket", lambda *_args: FakeSocket())
    monkeypatch.setattr(evasion.time, "sleep", lambda _seconds: None)
    answers = iter(["example.com", mode] + (["https://example.com/login"] if mode == "web" else []))
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(answers))

    real_import = builtins.__import__

    def safe_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if mode == "ssh" and name == "paramiko":
            raise ImportError("blocked in main test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", safe_import)
    runpy.run_path(str(Path(evasion.__file__)), run_name="__main__")
    assert "OCTOPUS Evasion Engine" in capsys.readouterr().out
