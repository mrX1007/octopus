from unittest.mock import mock_open

import pytest

pytestmark = pytest.mark.unit


def test_nmap_smart_phases_use_configured_aggressive_flags_and_timeout(monkeypatch):
    import core.tools.recon_tools as recon_tools
    from core.execution import ExecutionContext, bind_execution_context

    calls = []

    monkeypatch.setattr(
        recon_tools,
        "get_tool_config",
        lambda name: (
            {
                "timeout": 77,
                "aggressive_flags": ["-A", "-T2"],
            }
            if name == "nmap"
            else {}
        ),
    )
    monkeypatch.setattr(recon_tools.os.path, "exists", lambda _path: False)
    monkeypatch.setattr("builtins.open", mock_open())

    def fake_run_tool(command, timeout):
        calls.append((command, timeout))
        return "80/tcp closed" if len(calls) == 1 else "deep scan complete"

    monkeypatch.setattr(recon_tools, "run_tool", fake_run_tool)

    context = ExecutionContext.automatic(
        ("scan.example",),
        actor="recon-config-contract",
        origin="tests",
    )
    with bind_execution_context(context):
        output = recon_tools.run_nmap("scan.example", extra_flags=["-p-", "-sV"])

    assert calls == [
        (
            ["nmap", "-Pn", "-sT", "-sV", "--top-ports", "1000", "scan.example"],
            77,
        ),
        (["nmap", "-A", "-T2", "-p-", "scan.example"], 77),
    ]
    assert "deep scan complete" in output


def test_curl_headers_uses_code_owned_flags_and_configured_timeout(monkeypatch):
    import core.tools.recon_tools as recon_tools

    calls = []
    monkeypatch.setattr(
        recon_tools,
        "get_tool_config",
        lambda name: {"timeout": 41, "flags": ["-sS", "--max-time", "7"]} if name == "curl" else {},
    )
    monkeypatch.setattr(recon_tools, "_url_candidates", lambda _target: ["https://app.example/login"])
    monkeypatch.setattr(
        recon_tools,
        "run_tool",
        lambda command, timeout: calls.append((command, timeout)) or "HTTP/2 200",
    )

    output = recon_tools.run_curl_headers("app.example")

    assert calls == [
        (
            [
                "curl",
                "-sI",
                "--max-time",
                "10",
                "--noproxy",
                "*",
                "-k",
                "https://app.example/login",
            ],
            41,
        )
    ]
    assert "HTTP/2 200" in output


def test_ffuf_uses_configured_flags_and_limits(monkeypatch):
    import requests

    import core.tools.recon_tools as recon_tools

    calls = []
    monkeypatch.setattr(recon_tools.shutil, "which", lambda _name: "/usr/bin/ffuf")
    monkeypatch.setattr(recon_tools, "find_wordlist", lambda _category: "/tmp/web-dirs.txt")
    monkeypatch.setattr(
        recon_tools,
        "get_tool_config",
        lambda name: (
            {
                "threads": 11,
                "timeout": 93,
                "match_codes": [200, 302],
                "flags": ["-s"],
                "maxtime": 73,
                "request_timeout": 9,
            }
            if name == "ffuf"
            else {}
        ),
    )
    class FakeSession:
        def __init__(self):
            self.trust_env = True

        @staticmethod
        def get(*_args, **_kwargs):
            return object()

    monkeypatch.setattr(requests, "Session", FakeSession)
    monkeypatch.setattr(
        recon_tools,
        "run_tool",
        lambda command, timeout: calls.append((command, timeout)) or "ffuf complete",
    )

    output = recon_tools.run_ffuf("web.example")

    assert calls == [
        (
            [
                "ffuf",
                "-w",
                "/tmp/web-dirs.txt",
                "-u",
                "http://web.example/FUZZ",
                "-t",
                "11",
                "-mc",
                "200,302",
                "-s",
                "-timeout",
                "9",
                "-maxtime",
                "73",
            ],
            93,
        )
    ]
    assert output == "ffuf complete"


def test_native_content_discovery_providers_use_their_config(monkeypatch):
    import core.tools.recon_tools as recon_tools
    from core.tools.registry import get_tool

    configs = {
        "gobuster": {"threads": 7, "timeout": 81, "flags": ["--no-error"]},
        "dirb": {"timeout": 62, "flags": ["-S"]},
    }
    calls = []
    monkeypatch.setattr(recon_tools, "get_tool_config", lambda name: configs.get(name, {}))
    monkeypatch.setattr(recon_tools, "find_wordlist", lambda _category: "/tmp/web-dirs.txt")
    monkeypatch.setattr(
        recon_tools,
        "run_tool",
        lambda command, timeout: calls.append((command, timeout)) or "complete",
    )

    recon_tools.run_gobuster("https://web.example/base")
    recon_tools.run_dirb("https://web.example/base")

    assert calls == [
        (
            [
                "gobuster",
                "dir",
                "-u",
                "https://web.example/base",
                "-w",
                "/tmp/web-dirs.txt",
                "-t",
                "7",
                "--no-error",
            ],
            81,
        ),
        (["dirb", "https://web.example/base", "/tmp/web-dirs.txt", "-S"], 62),
    ]
    assert get_tool("gobuster").name == "gobuster"
    assert get_tool("dirb").name == "dirb"
    assert get_tool("dirb_fuzz").name == "ffuf"


def test_scrapling_enabled_is_a_hard_feature_gate(monkeypatch):
    import core.tools.recon_tools as recon_tools

    monkeypatch.setattr(recon_tools, "CFG", {"scrapling": {"enabled": False}})

    assert "disabled by config" in recon_tools.run_scrapling_fetch("web.example")
    assert "disabled by config" in recon_tools.run_scrapling_crawl("web.example")


def test_scrapling_stealth_config_cannot_bypass_nonstealth_hardening(monkeypatch):
    import sys
    from types import SimpleNamespace

    import requests

    import core.tools.recon_tools as recon_tools

    fetcher_calls = []
    request_calls = []

    class ForbiddenFetcher:
        def __init__(self):
            fetcher_calls.append("constructed")

    class FakeResponse:
        status_code = 200
        text = "<html><body>page body</body></html>"

    class FakeSession:
        def __init__(self):
            self.trust_env = True

        @staticmethod
        def mount(*_args, **_kwargs):
            return None

        def get(self, url, **kwargs):
            request_calls.append((url, kwargs))
            return FakeResponse()

    class FakeBody:
        @staticmethod
        def __call__(*args, **kwargs):
            return []

        @staticmethod
        def get_text(*args, **kwargs):
            return "page body"

    class FakeSoup:
        @staticmethod
        def find(name):
            return FakeBody() if name == "body" else None

        @staticmethod
        def find_all(*args, **kwargs):
            return []

        @staticmethod
        def get_text(*args, **kwargs):
            return "page body"

    monkeypatch.setattr(
        recon_tools,
        "CFG",
        {"scrapling": {"enabled": True, "timeout": 12, "use_stealth": True}},
    )
    monkeypatch.setattr(recon_tools, "_SCRAPLING_OK", True)
    monkeypatch.setattr(recon_tools, "_StealthyFetcher", ForbiddenFetcher)
    monkeypatch.setattr(requests, "Session", FakeSession)
    monkeypatch.setitem(
        sys.modules,
        "bs4",
        SimpleNamespace(BeautifulSoup=lambda html, parser: FakeSoup()),
    )

    output = recon_tools.run_scrapling_fetch("https://web.example")

    assert fetcher_calls == []
    assert request_calls[0][0] == "https://web.example"
    assert request_calls[0][1]["timeout"] == (5, 12)
    assert request_calls[0][1]["allow_redirects"] is False
    assert "page body" in output


def test_scrapling_crawl_caps_pages_and_uses_requests_timeout_when_stealth_is_off(monkeypatch):
    import requests

    import core.tools.recon_tools as recon_tools

    calls = []

    class FakeResponse:
        status_code = 200
        text = "<html><title>Page</title><a href='/one'>one</a><a href='/two'>two</a></html>"

    def fake_get(url, **kwargs):
        calls.append((url, kwargs.get("timeout")))
        return FakeResponse()

    monkeypatch.setattr(
        recon_tools,
        "CFG",
        {
            "scrapling": {
                "enabled": True,
                "timeout": 4,
                "max_crawl_pages": 2,
                "use_stealth": False,
            }
        },
    )
    monkeypatch.setattr(recon_tools, "_SCRAPLING_OK", True)
    class FakeSession:
        def __init__(self):
            self.trust_env = True

        def get(self, url, **kwargs):
            return fake_get(url, **kwargs)

    monkeypatch.setattr(requests, "Session", FakeSession)

    output = recon_tools.run_scrapling_crawl("http://web.example", max_pages=20)

    assert calls == [
        ("http://web.example", (4, 4)),
        ("http://web.example/one", (4, 4)),
    ]
    assert "Mode: requests+bs4 fallback" in output
    assert "Pages crawled: 2" in output
