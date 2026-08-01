"""Hermetic coverage for reconnaissance command builders and parsers."""

from __future__ import annotations

import base64
import builtins
import importlib.util
import json
import socket
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar
from unittest.mock import MagicMock, mock_open

import pytest

from core.execution import ExecutionContext, bind_execution_context
from core.tools import recon_tools

pytestmark = pytest.mark.unit


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def test_config_path_profile_and_jwt_helpers(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert recon_tools._path_or_target("") == "."
    assert recon_tools._path_or_target("  ") == "."
    assert recon_tools._path_or_target(" path ") == "path"
    assert recon_tools._config_int({"x": "bad"}, "x", 7) == 7
    assert recon_tools._config_int({"x": -1}, "x", 7, minimum=2) == 2
    assert recon_tools._config_csv({"x": ["200", "", 201]}, "x", "all") == "200,201"
    assert recon_tools._config_csv({"x": ""}, "x", "all") == "all"
    assert recon_tools._config_bool({"x": "yes"}, "x", False) is False
    assert recon_tools._config_bool({"x": True}, "x", False) is True
    assert recon_tools._config_flags({"x": "bad"}, "x", ["-a"]) == ["-a"]
    assert recon_tools._config_flags({"x": [" -a ", ""]}, "x", []) == ["-a"]

    monkeypatch.setattr(recon_tools, "CFG", None)
    assert recon_tools._config_section("x") == {}
    monkeypatch.setattr(recon_tools, "CFG", {"x": "bad", "y": {"ok": True}})
    assert recon_tools._config_section("x") == {}
    assert recon_tools._config_section("y") == {"ok": True}

    assert recon_tools._load_session_profile("") == {"headers": {}, "cookies": {}}
    profile_path = tmp_path / "profile.json"
    profile_path.write_text('{"headers":{"X":"1"},"cookies":{"sid":"2"}}')
    assert recon_tools._load_session_profile(str(profile_path))["headers"] == {"X": "1"}
    bad_path = tmp_path / "bad.json"
    bad_path.write_text("not-json")
    assert recon_tools._load_session_profile(str(bad_path)) == {"headers": {}, "cookies": {}}

    encoded = _b64({"alg": "none"})
    assert recon_tools._decode_jwt_segment(encoded) == {"alg": "none"}
    assert recon_tools._decode_jwt_segment("%%%") == {}


def test_optional_config_fallback_and_scrapling_success_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import core.tools.registry as registry

    original_import = builtins.__import__

    def controlled_import(name, *args, **kwargs):
        if name == "config":
            raise ImportError("config unavailable")
        if name == "scrapling":
            return SimpleNamespace(StealthyFetcher=object)
        return original_import(name, *args, **kwargs)

    def inert_tool(**_metadata):
        return lambda function: function

    monkeypatch.setattr(builtins, "__import__", controlled_import)
    monkeypatch.setattr(registry, "tool", inert_tool)
    module_path = Path(recon_tools.__file__)
    spec = importlib.util.spec_from_file_location("recon_tools_optional_coverage", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.CFG == {}
    assert module.find_wordlist("web") == ""
    assert module._SCRAPLING_OK is True


def test_nmap_cache_regular_many_ports_and_write_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], int]] = []
    monkeypatch.setattr(
        recon_tools,
        "get_tool_config",
        lambda _name: {
            "timeout": 12,
            "default_flags": ["-sV"],
            "aggressive_flags": ["-A", "-p-"],
        },
    )
    monkeypatch.setattr(
        recon_tools,
        "run_tool",
        lambda command, timeout: calls.append((command, timeout)) or "ok",
    )
    context = ExecutionContext.automatic(("host",), actor="recon-provider-contract", origin="tests")
    with bind_execution_context(context):
        assert recon_tools.run_nmap("host") == "ok"
        assert calls[-1][0] == ["nmap", "-sV", "host"]
        recon_tools.run_nmap("host", extra_flags=["-Pn", "-sT"])

        monkeypatch.setattr(
            recon_tools,
            "get_tool_config",
            lambda _name: {"timeout": "11", "default_flags": ["--", "-sV"]},
        )
        assert recon_tools.run_rustscan("host") == "ok"
        assert calls[-1] == (["rustscan", "-a", "host", "--no-config", "--", "-sV"], 11)
        assert recon_tools.run_rustscan("host", extra_flags=[" -- ", "", " -sC "]) == "ok"
        assert calls[-1] == (["rustscan", "-a", "host", "--no-config", "--", "-sC"], 11)

        monkeypatch.setattr(recon_tools.os.path, "exists", lambda _path: True)
        monkeypatch.setattr("builtins.open", mock_open(read_data="cached"))
        assert recon_tools.run_nmap("host", extra_flags=["-p-"]) == "cached"

        outputs = iter(["\n".join(f"{port}/tcp open svc" for port in range(1, 6)), "deep"])
        monkeypatch.setattr(recon_tools.os.path, "exists", lambda _path: False)
        monkeypatch.setattr(
            recon_tools,
            "run_tool",
            lambda command, timeout: calls.append((command, timeout)) or next(outputs),
        )
        monkeypatch.setattr("builtins.open", MagicMock(side_effect=OSError("readonly")))
        result = recon_tools.run_nmap("host", extra_flags=["-p-", "-Pn", "-sT"])
        assert "Deep Scan" in result
        assert "8443,8000" in calls[-1][0][-2]

        outputs = iter(["80/tcp closed", "deep"])
        monkeypatch.setattr("builtins.open", mock_open())
        monkeypatch.setattr(
            recon_tools,
            "run_tool",
            lambda command, timeout: calls.append((command, timeout)) or next(outputs),
        )
        assert "Deep Scan" in recon_tools.run_nmap("host", extra_flags=["-p-", "-Pn", "-sT"])


def test_command_wrappers_are_process_free(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], int]] = []
    monkeypatch.setattr(
        recon_tools,
        "get_tool_config",
        lambda name: {
            "timeout": 9,
            "flags": ["-x"],
            "aggression": 4,
            "record_types": ["A", "MX"],
            "level": 2,
            "risk": 3,
        },
    )
    monkeypatch.setattr(
        recon_tools,
        "run_tool",
        lambda command, timeout: calls.append((command, timeout)) or "tool-output",
    )
    monkeypatch.setattr(recon_tools, "_target_host", lambda target: f"host-{target}")
    monkeypatch.setattr(recon_tools, "_is_probably_domain", lambda target: target.endswith("domain"))
    monkeypatch.setattr(recon_tools, "_as_url", lambda target: f"https://{target}")
    monkeypatch.setattr(recon_tools, "_ensure_url", lambda target: f"http://{target}")

    assert "tool-output" in recon_tools.run_whois("x")
    assert "tool-output" in recon_tools.run_whatweb("x")
    assert "A Records" in recon_tools.run_dig("x")
    assert "skipped" in recon_tools.run_subfinder("ip")
    assert "skipped" in recon_tools.run_amass_enum("ip")
    assert "SUBFINDER" in recon_tools.run_subfinder("domain")
    assert "AMASS" in recon_tools.run_amass_enum("domain")
    for function in (
        recon_tools.run_dnsx,
        recon_tools.run_httpx_probe,
        recon_tools.run_naabu,
        recon_tools.run_tlsx,
        recon_tools.run_wayback_urls,
        recon_tools.run_gau_urls,
        recon_tools.run_katana_crawl,
        recon_tools.run_gitleaks_scan,
        recon_tools.run_trufflehog_scan,
        recon_tools.run_semgrep_scan,
        recon_tools.run_trivy_scan,
        recon_tools.run_checkov_scan,
        recon_tools.run_sslscan,
        recon_tools.run_enum4linux,
        recon_tools.run_smbclient,
        recon_tools.run_wpscan,
        recon_tools.run_sqlmap,
        recon_tools.run_security_headers_check,
        recon_tools.run_cors_check,
        recon_tools.run_js_route_extract,
    ):
        assert function("target")

    assert "unsupported" in recon_tools.run_prowler_scan("other")
    assert "PROWLER" in recon_tools.run_prowler_scan("")
    assert "unsupported" in recon_tools.run_scoutsuite_scan("other")
    assert "SCOUTSUITE" in recon_tools.run_scoutsuite_scan("GCP")
    assert len(calls) > 20

    monkeypatch.setattr(
        recon_tools,
        "run_tool",
        lambda _command, timeout: "const x='/api/users?id=1'; const y='https://x.test/z';",
    )
    assert "Routes: 2" in recon_tools.run_js_route_extract("target")


def test_curl_nuclei_nikto_and_graphql_completion_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = iter(
        [
            "headers-http",
            "headers-https",
            "[!] nuclei returned no output.",
            "killed after 1s",
            "nikto ok",
            "timed out after 1s",
            "graphql",
            "graphql-existing",
        ]
    )
    calls = []
    monkeypatch.setattr(
        recon_tools,
        "get_tool_config",
        lambda name: (
            {"flags": ["-sI", "--insecure"], "timeout": 0}
            if name == "curl"
            else {"timeout": 0, "request_timeout": 0, "retries": -1}
        ),
    )
    monkeypatch.setattr(
        recon_tools,
        "_url_candidates",
        lambda _target: ["http://x", "https://x"],
    )
    monkeypatch.setattr(recon_tools, "_as_url", lambda target: f"https://{target}")
    monkeypatch.setattr(recon_tools, "_ensure_url", lambda target: f"https://{target}")
    monkeypatch.setattr(
        recon_tools,
        "run_tool",
        lambda command, timeout: calls.append((command, timeout)) or next(outputs),
    )
    assert "headers-http" in recon_tools.run_curl_headers("x")
    assert "-k" not in calls[0][0]
    assert "-k" in calls[1][0]
    assert "No nuclei findings" in recon_tools.run_nuclei_safe("x")
    assert "NUCLEI COMPLETE" not in recon_tools.run_nuclei_safe("x")
    assert "NIKTO COMPLETE" in recon_tools.run_nikto("x")
    assert "NIKTO COMPLETE" not in recon_tools.run_nikto("x")
    assert "graphql" in recon_tools.run_graphql_check("api")
    monkeypatch.setattr(recon_tools, "_as_url", lambda _target: "https://api/graphql")
    assert "graphql-existing" in recon_tools.run_graphql_check("api")


def test_openapi_local_yaml_remote_and_failure_paths(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert "missing source" in recon_tools.run_openapi_import("")
    data = {
        "info": {"title": "API"},
        "security": [{"key": []}],
        "paths": {
            "/users": {"get": {}, "parameters": []},
            "/health": {"post": {"security": []}},
            "/ignored": "not-a-map",
        },
    }
    json_path = tmp_path / "openapi.json"
    json_path.write_text(json.dumps(data))
    output = recon_tools.run_openapi_import(str(json_path))
    assert "GET /users auth=required" in output
    assert "POST /health auth=required" in output

    yaml_path = tmp_path / "openapi.yaml"
    yaml_path.write_text("info:\n  title: YAML\npaths:\n  /x:\n    delete: {}\n")
    assert "DELETE /x" in recon_tools.run_openapi_import(str(yaml_path))

    session = SimpleNamespace(
        trust_env=True,
        get=MagicMock(return_value=SimpleNamespace(text=json.dumps({"paths": {}}))),
    )
    monkeypatch.setattr("requests.Session", lambda: session)
    assert "OPENAPI IMPORT" in recon_tools.run_openapi_import("https://spec.test")
    session.get = MagicMock(side_effect=RuntimeError("offline"))
    assert "import failed" in recon_tools.run_openapi_import("https://spec.test")


def test_session_authenticated_crawl_and_api_auth_paths(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = tmp_path / "profile.json"
    profile.write_text('{"headers":{"Authorization":"Bearer x"},"cookies":{"sid":"v"}}')
    imported = recon_tools.run_session_profile_import(str(profile))
    assert "HEADER Authorization" in imported
    assert "COOKIE sid" in imported

    responses = iter(
        [
            SimpleNamespace(
                status_code=200,
                url="https://site.test/final",
                text="<title> Site </title><form></form><input name='csrf'><a href='/next'>n</a>",
            ),
            SimpleNamespace(status_code=200, url="https://site.test", text="plain"),
        ]
    )
    session = SimpleNamespace(
        trust_env=True,
        get=MagicMock(side_effect=lambda *_args, **_kwargs: next(responses)),
    )
    monkeypatch.setattr("requests.Session", lambda: session)
    first = recon_tools.run_authenticated_crawl("site.test", str(profile))
    second = recon_tools.run_authenticated_crawl("site.test")
    assert "Title: Site" in first and "LINK https://site.test/next" in first
    assert "CSRF token observed: no" in second
    session.get = MagicMock(side_effect=RuntimeError("offline"))
    assert "failed" in recon_tools.run_authenticated_crawl("site.test")

    def api_responses(*_args, **kwargs):
        if kwargs.get("headers"):
            return SimpleNamespace(status_code=200)
        return SimpleNamespace(status_code=200)

    session.get = MagicMock(side_effect=api_responses)
    assert "possible_missing_auth" in recon_tools.run_api_auth_check("api.test", str(profile))

    both_denied = iter([SimpleNamespace(status_code=500), SimpleNamespace(status_code=500)])
    session.get = MagicMock(side_effect=lambda *_args, **_kwargs: next(both_denied))
    assert "NOTE" not in recon_tools.run_api_auth_check("api.test", str(profile))

    status = iter([SimpleNamespace(status_code=401), SimpleNamespace(status_code=200)])
    session.get = MagicMock(side_effect=lambda *_args, **_kwargs: next(status))
    assert "auth_required" in recon_tools.run_api_auth_check("api.test", str(profile))
    session.get = MagicMock(return_value=SimpleNamespace(status_code=200))
    assert "anonymous_accessible" in recon_tools.run_api_auth_check("api.test")
    session.get = MagicMock(return_value=SimpleNamespace(status_code=500))
    assert "NOTE" not in recon_tools.run_api_auth_check("api.test")
    session.get = MagicMock(side_effect=RuntimeError("offline"))
    assert "failed" in recon_tools.run_api_auth_check("api.test")


def test_ftp_probe_success_denied_network_generic_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ftplib

    class FTP:
        welcome = "FTP ready"
        listing: object = ["one", "two"]
        connect_error: Exception | None = None
        login_error: Exception | None = None
        quit_error: Exception | None = None
        close_error: Exception | None = None

        def connect(self, *_args, **_kwargs):
            if self.connect_error:
                raise self.connect_error

        def getwelcome(self):
            return self.welcome

        def login(self, *_args):
            if self.login_error:
                raise self.login_error

        def nlst(self):
            if isinstance(self.listing, Exception):
                raise self.listing
            return self.listing

        def quit(self):
            if self.quit_error:
                raise self.quit_error

        def close(self):
            if self.close_error:
                raise self.close_error

    monkeypatch.setattr(ftplib, "FTP", FTP)
    monkeypatch.setattr(recon_tools, "_split_host_port", lambda _target, _port: ("host", None))
    assert "Entries (2)" in recon_tools.run_ftp_anonymous_check("host", 21)
    FTP.welcome = ""
    FTP.listing = RuntimeError("no list")
    FTP.quit_error = RuntimeError("quit")
    assert "listing: unavailable" in recon_tools.run_ftp_anonymous_check("host", 21)

    FTP.login_error = ftplib.error_perm("denied")
    assert "login: denied" in recon_tools.run_ftp_anonymous_check("host", 21)
    FTP.login_error = None
    FTP.connect_error = OSError("network")
    assert "probe failed" in recon_tools.run_ftp_anonymous_check("host", 21)
    FTP.connect_error = ValueError("generic")
    FTP.close_error = RuntimeError("close")
    assert "probe failed" in recon_tools.run_ftp_anonymous_check("host", 21)


def test_smtp_probe_ssl_plain_error_and_close_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    import smtplib

    class SMTP:
        features: ClassVar[dict] = {"auth": "plain login", "size": ""}
        ehlo_value: object = b"hello"
        connect_error: Exception | None = None
        quit_error: Exception | None = None
        close_error: Exception | None = None

        def __init__(self, **_kwargs):
            self.esmtp_features = dict(self.features)

        def connect(self, *_args):
            if self.connect_error:
                raise self.connect_error
            return (220, b"ready")

        def ehlo(self, _name):
            return (250, self.ehlo_value)

        @staticmethod
        def has_extn(_name):
            return True

        def quit(self):
            if self.quit_error:
                raise self.quit_error

        def close(self):
            if self.close_error:
                raise self.close_error

    monkeypatch.setattr(smtplib, "SMTP", SMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", SMTP)
    monkeypatch.setattr(recon_tools, "_split_host_port", lambda _target, port: ("host", port))
    assert "AUTH mechanisms" in recon_tools.run_smtp_probe("host", 465)
    SMTP.features = {}
    SMTP.ehlo_value = ""
    assert "Open relay test" in recon_tools.run_smtp_probe("host", 25)
    SMTP.connect_error = OSError("network")
    SMTP.quit_error = RuntimeError("quit")
    SMTP.close_error = RuntimeError("close")
    assert "probe failed" in recon_tools.run_smtp_probe("host", 25)


def test_content_discovery_failure_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    import requests

    monkeypatch.setattr(recon_tools.shutil, "which", lambda _name: None)
    assert "not installed" in recon_tools.run_ffuf("site")
    monkeypatch.setattr(recon_tools.shutil, "which", lambda _name: "/bin/ffuf")
    monkeypatch.setattr(recon_tools, "get_tool_config", lambda _name: {"timeout": 0})
    monkeypatch.setattr(recon_tools, "_url_candidates", lambda _target: ["http://x", "https://x"])
    session = SimpleNamespace(
        trust_env=True,
        get=MagicMock(side_effect=requests.RequestException("offline")),
    )
    monkeypatch.setattr(requests, "Session", lambda: session)
    assert "no HTTP(S) response" in recon_tools.run_ffuf("site")

    session.get = MagicMock(side_effect=RuntimeError("unexpected"))
    monkeypatch.setattr(recon_tools, "find_wordlist", lambda _category: "")
    assert "No common web wordlists" in recon_tools.run_ffuf("site")
    assert "No common web wordlists" in recon_tools.run_gobuster("site")
    assert "No common web wordlists" in recon_tools.run_dirb("site")


def test_jwt_burp_and_zap_import_boundaries(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert "no JWT" in recon_tools.run_jwt_analyze("not-a-token")
    token = (
        f"{_b64({'alg': 'HS256', 'typ': 'JWT', 'kid': 'k'})}.{_b64({'sub': 'a', 'iss': 'i', 'aud': 'a', 'exp': 1})}.sig"
    )
    token_path = tmp_path / "token.txt"
    token_path.write_text(token)
    assert "alg: HS256" in recon_tools.run_jwt_analyze(str(token_path))
    monkeypatch.setattr("builtins.open", MagicMock(side_effect=OSError("denied")))
    monkeypatch.setattr(recon_tools.os.path, "exists", lambda _path: True)
    assert "failed to read" in recon_tools.run_jwt_analyze("file")
    monkeypatch.undo()

    assert "file not found" in recon_tools.run_burp_import(str(tmp_path / "missing"))
    assert "file not found" in recon_tools.run_zap_import(str(tmp_path / "missing"))
    burp = tmp_path / "burp.xml"
    burp.write_text(
        "<url><![CDATA[https://x]]></url><url><![CDATA[]]></url><name><![CDATA[Issue]]></name><name><![CDATA[]]></name>"
    )
    assert "URL https://x" in recon_tools.run_burp_import(str(burp))
    zap = tmp_path / "zap.xml"
    zap.write_text("<uri>https://x</uri><uri></uri><alert>Issue</alert><alert></alert><riskdesc>High</riskdesc>")
    imported = recon_tools.run_zap_import(str(zap))
    assert "ALERT High Issue" in imported

    monkeypatch.setattr(recon_tools.os.path, "exists", lambda _path: True)
    monkeypatch.setattr("builtins.open", MagicMock(side_effect=OSError("denied")))
    assert "failed" in recon_tools.run_burp_import("file")
    assert "failed" in recon_tools.run_zap_import("file")


class _Element:
    def __init__(self, text: str = "", attributes: dict | None = None, children=None) -> None:
        self._text = text
        self.attributes = attributes or {}
        self.children = children or []

    def text(self, *_args, **_kwargs):
        return self._text

    def css(self, _selector):
        return list(self.children)


class _Page:
    status = 200

    def __init__(self, *, title=True, body=True, status=200) -> None:
        self.status = status
        self.title = _Element("Title") if title else None
        self.body = _Element("Body") if body else None
        self.links = [
            _Element("good", {"href": "/next"}),
            _Element("hash", {"href": "#x"}),
            _Element("js", {"href": "javascript:x"}),
            _Element("empty", {"href": ""}),
        ]
        self.forms = [
            _Element(
                attributes={"action": "/login", "method": "post"},
                children=[
                    _Element(attributes={"name": "user", "type": "text"}),
                    _Element(attributes={"name": ""}),
                ],
            )
        ]
        self.meta = [
            _Element(attributes={"name": "description", "content": "desc"}),
            _Element(attributes={"name": "empty", "content": ""}),
        ]

    def css_first(self, selector):
        return self.title if selector == "title" else self.body

    def css(self, selector):
        return {"a[href]": self.links, "form": self.forms, "meta": self.meta}.get(selector, [])

    @staticmethod
    def text(*_args, **_kwargs):
        return "Page text"


def test_scrapling_fetch_uses_closed_requests_session_without_alt_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Fetcher:
        def __init__(self):
            raise AssertionError("browser-backed stealth fetch must stay disabled")

    class Response:
        def __init__(self, text, status_code):
            self.text = text
            self.status_code = status_code

    class Tag:
        def __init__(self, text="", attrs=None, children=None):
            self.text = text
            self.attrs = attrs or {}
            self.children = children or []

        def get_text(self, **_kwargs):
            return self.text

        def get(self, key, default=""):
            return self.attrs.get(key, default)

        def __getitem__(self, key):
            return self.attrs[key]

        def find_all(self, _names):
            return self.children

        def __call__(self, _names):
            return [SimpleNamespace(decompose=lambda: None)]

    class Soup:
        def __init__(self, html, _parser):
            self.rich = "<title>" in html
            self.title = Tag("T") if self.rich else None
            self.body = Tag("Body") if self.rich else None

        def find(self, name):
            return self.title if name == "title" else self.body

        def get_text(self, **_kwargs):
            return "plain text"

        def find_all(self, name, **_kwargs):
            if not self.rich:
                return []
            if name == "a":
                return [Tag("A", {"href": "/a"}), Tag("bad", {"href": "#x"})]
            if name == "form":
                return [
                    Tag(
                        attrs={"action": "/login", "method": "post"},
                        children=[Tag(attrs={"name": "x", "type": "text"}), Tag()],
                    )
                ]
            if name == "meta":
                return [Tag(attrs={"name": "d", "content": "c"}), Tag()]
            return []

    class Session:
        responses: ClassVar[list[object]] = []

        @staticmethod
        def mount(*_args):
            pass

        def get(self, *_args, **_kwargs):
            item = self.responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

    monkeypatch.setattr("requests.Session", Session)
    monkeypatch.setitem(sys.modules, "bs4", SimpleNamespace(BeautifulSoup=Soup))
    monkeypatch.setattr(recon_tools, "CFG", {"scrapling": {"use_stealth": True}})
    monkeypatch.setattr(recon_tools, "_SCRAPLING_OK", True)
    monkeypatch.setattr(recon_tools, "_StealthyFetcher", Fetcher)
    Session.responses = [
        Response("<title>T</title><a href='/a'>A</a><form><input name='x'></form><meta name='d' content='c'>", 200)
    ]
    output = recon_tools.run_scrapling_fetch("site.test")
    assert "REQUESTS+BS4 RESULT" in output
    assert "Title: T" in output and "Forms (1)" in output and "Meta Info" in output
    Session.responses = [Response("plain text", 200)]
    assert "plain text" in recon_tools.run_scrapling_fetch("site.test")

    Session.responses = [Response("", 404)]
    assert "Status: 404" in recon_tools.run_scrapling_fetch("http://site.test")

    Session.responses = [RuntimeError("primary"), Response("no", 500), Response("alt ok", 200)]
    assert "All scrapling/requests attempts failed" in recon_tools.run_scrapling_fetch(
        "http://site.test:8080"
    )
    assert len(Session.responses) == 2


def test_scrapling_crawl_disables_stealth_and_keeps_requests_in_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Fetcher:
        def __init__(self):
            raise AssertionError("browser-backed stealth fetch must stay disabled")

    class Anchor:
        def __init__(self, href):
            self.href = href

        def get(self, _name, _default=""):
            return self.href

    class Title:
        @staticmethod
        def get_text(**_kwargs):
            return "Title"

    class Soup:
        def __init__(self, html, _parser):
            self.html = html

        def find(self, _name):
            return Title() if self.html == "first" else None

        def find_all(self, _name, **_kwargs):
            if self.html != "first":
                return []
            return [
                Anchor("/next"),
                Anchor("/next"),
                Anchor("https://other.test"),
                Anchor("#x"),
                Anchor(""),
            ]

    class Session:
        responses: ClassVar[list[object]] = []

        def get(self, *_args, **_kwargs):
            item = self.responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

    monkeypatch.setattr(
        recon_tools,
        "CFG",
        {"scrapling": {"enabled": True, "use_stealth": True, "max_crawl_pages": 5}},
    )
    monkeypatch.setattr(recon_tools, "_SCRAPLING_OK", True)
    monkeypatch.setattr(recon_tools, "_StealthyFetcher", Fetcher)
    monkeypatch.setattr("requests.Session", Session)
    monkeypatch.setitem(sys.modules, "bs4", SimpleNamespace(BeautifulSoup=Soup))
    Session.responses = [
        SimpleNamespace(status_code=200, text="first"),
        SimpleNamespace(status_code=404, text="second"),
    ]
    output = recon_tools.run_scrapling_crawl("site.test")
    assert "[200]" in output and "[404]" in output
    assert "requests+bs4 fallback" in output
    assert "other.test" not in output

    Session.responses = [RuntimeError("page")]
    assert "[ERR]" in recon_tools.run_scrapling_crawl("site.test", max_pages=1)


def test_scrapling_crawl_requests_bs4_success(monkeypatch: pytest.MonkeyPatch) -> None:
    class Anchor:
        def __init__(self, href):
            self.href = href

        def get(self, _name, _default=""):
            return self.href

    class Title:
        @staticmethod
        def get_text(**_kwargs):
            return "Fallback title"

    class Soup:
        def __init__(self, html, _parser):
            self.html = html

        def find(self, _name):
            return Title() if "title" in self.html else None

        def find_all(self, _name, **_kwargs):
            return [Anchor("/next"), Anchor("https://outside.test")]

    responses = iter(
        [
            SimpleNamespace(status_code=200, text="title"),
            SimpleNamespace(status_code=200, text="no heading"),
        ]
    )

    class Session:
        def get(self, *_args, **_kwargs):
            return next(responses)

    monkeypatch.setitem(sys.modules, "bs4", SimpleNamespace(BeautifulSoup=Soup))
    monkeypatch.setattr("requests.Session", Session)
    monkeypatch.setattr(
        recon_tools,
        "CFG",
        {"scrapling": {"enabled": True, "use_stealth": False, "max_crawl_pages": 2}},
    )
    output = recon_tools.run_scrapling_crawl("site.test")
    assert "Fallback title" in output
    assert "No title" in output


class _Socket:
    result = 0
    error: Exception | None = None

    def settimeout(self, _timeout):
        pass

    def connect_ex(self, _address):
        if self.error:
            raise self.error
        return self.result

    def close(self):
        pass


class _Future:
    def __init__(self, value=None, error: Exception | None = None) -> None:
        self.value = value
        self.error = error

    def result(self):
        if self.error:
            raise self.error
        return self.value


class _Executor:
    future_errors: ClassVar[set[str]] = set()

    def __init__(self, *args, **kwargs) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def submit(self, function, username):
        if username in self.future_errors:
            return _Future(error=RuntimeError("future"))
        return _Future(function(username))


def test_ssh_enum_closed_connect_error_patched_and_full_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import concurrent.futures

    import paramiko

    original_import = builtins.__import__

    def no_paramiko(name, *args, **kwargs):
        if name == "paramiko":
            raise ImportError("missing")
        return original_import(name, *args, **kwargs)

    with monkeypatch.context() as missing:
        missing.setattr(builtins, "__import__", no_paramiko)
        assert "paramiko not installed" in recon_tools.run_ssh_user_enum("host")

    monkeypatch.setattr(socket, "socket", lambda *_args: _Socket())
    _Socket.result = 1
    assert "not open" in recon_tools.run_ssh_user_enum("host")
    _Socket.result = 0
    _Socket.error = RuntimeError("connect")
    assert "Cannot connect" in recon_tools.run_ssh_user_enum("host")
    _Socket.error = None

    class Transport:
        mode = "all-valid"
        close_error = False
        construct_error = False

        def __init__(self, _address):
            if self.construct_error:
                raise RuntimeError("transport")

        def connect(self):
            pass

        def auth_password(self, username, _password):
            if self.mode == "all-valid":
                raise paramiko.AuthenticationException()
            if self.mode == "none":
                return None
            if self.mode == "some":
                if username == "valid":
                    raise paramiko.AuthenticationException()
                return None
            if username in {"aaa_fake_user_m7k", "invalid"}:
                raise paramiko.ssh_exception.SSHException("no existing session")
            if username == "root":
                raise paramiko.ssh_exception.SSHException("other")
            if username == "admin":
                raise ValueError("unknown")
            raise paramiko.AuthenticationException()

        def close(self):
            if self.close_error:
                raise RuntimeError("close")

    monkeypatch.setattr(paramiko, "Transport", Transport)
    monkeypatch.setattr(concurrent.futures, "ThreadPoolExecutor", _Executor)
    monkeypatch.setattr(concurrent.futures, "as_completed", lambda futures: list(futures))
    assert "PATCHED" in recon_tools.run_ssh_user_enum("host")

    Transport.mode = "mixed"
    monkeypatch.setattr(
        recon_tools,
        "CFG",
        {"default_users": ["root", "admin", "support", "valid", "invalid"]},
    )
    output = recon_tools.run_ssh_user_enum("host")
    assert "Tested:" in output

    Transport.close_error = True
    assert "Tested:" in recon_tools.run_ssh_user_enum("host")
    Transport.close_error = False
    Transport.construct_error = True
    assert "No valid users" in recon_tools.run_ssh_user_enum("host")
    Transport.construct_error = False

    Transport.mode = "some"
    _Executor.future_errors = {"root", "www-data"}
    some = recon_tools.run_ssh_user_enum("host")
    assert "CONFIRMED VALID USERS" in some
    assert "Errors: 1" in some
    _Executor.future_errors = set()
    Transport.mode = "none"
    none = recon_tools.run_ssh_user_enum("host")
    assert "No valid users confirmed" in none
