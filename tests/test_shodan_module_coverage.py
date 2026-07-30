"""Hermetic statement and branch coverage for ``shodan_module``."""

from __future__ import annotations

import builtins
import runpy
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

import pytest

import shodan_module as sm

pytestmark = pytest.mark.contract


class FakeAPIError(Exception):
    pass


def _recon(**attributes):
    recon = sm.ShodanRecon.__new__(sm.ShodanRecon)
    defaults = {
        "api": None,
        "cfg": {},
        "max_results": 10,
        "save_results": False,
        "results_dir": "/tmp/unused",
        "_last_results": [],
        "_db_conn": None,
    }
    defaults.update(attributes)
    for name, value in defaults.items():
        setattr(recon, name, value)
    return recon


def test_optional_import_fallbacks_and_environment_secret(monkeypatch):
    fake_shodan = ModuleType("shodan")
    monkeypatch.setitem(sys.modules, "shodan", fake_shodan)
    real_import = builtins.__import__

    def optional_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name in {"config", "mysql"}:
            raise ImportError(f"{name} unavailable")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", optional_import)
    monkeypatch.setenv("FALLBACK_SECRET", "from-environment")
    namespace = runpy.run_path(sm.__file__, run_name="shodan_optional_fallbacks")

    assert namespace["shodan"] is fake_shodan
    assert namespace["mysql"] is None
    assert namespace["CFG"] == {}
    assert namespace["get_secret"]("FALLBACK_SECRET") == "from-environment"
    assert namespace["get_secret"]("ABSENT", "default") == "default"


def test_scalar_and_http_timeout_helpers():
    assert sm._safe_file_component("***", "fallback") == "fallback"
    assert sm._as_bool(True) is True
    assert sm._as_bool(None, True) is True
    assert sm._as_bool(0) is False
    assert sm._as_bool(2) is True
    assert sm._as_bool(" YES ") is True
    assert sm._as_bool("off", True) is False
    assert sm._as_bool("unknown", True) is True
    assert sm._positive_timeout("bad", 4.0) == 4.0
    assert sm._positive_timeout(0, 4.0) == 4.0
    assert sm._positive_timeout(2, 4.0) == 2.0
    assert sm._configure_http_timeout(object(), 2.0) is False
    assert sm._configure_http_timeout(SimpleNamespace(_session=object()), 2.0) is False


def test_recon_initialization_paths(monkeypatch, capsys):
    monkeypatch.setattr(sm, "CFG", {"shodan": {"timeout": "bad"}})
    monkeypatch.setattr(sm, "get_secret", lambda *_args: "")
    no_key = sm.ShodanRecon()
    assert no_key.api is None

    monkeypatch.setattr(sm, "get_secret", lambda *_args: "key")
    monkeypatch.setattr(sm, "shodan", None)
    no_library = sm.ShodanRecon()
    assert no_library.api is None

    class Client:
        def __init__(self, key):
            self.key = key
            self._session = SimpleNamespace(request=lambda *_args, **_kwargs: None)

        def info(self):
            return {"query_credits": 3, "scan_credits": 4}

    monkeypatch.setattr(sm, "shodan", SimpleNamespace(Shodan=Client))
    connected = sm.ShodanRecon("explicit")
    assert connected.api.key == "explicit"
    assert connected.timeout == 30.0

    class BrokenClient:
        def __init__(self, _key):
            raise RuntimeError("offline")

    monkeypatch.setattr(sm, "shodan", SimpleNamespace(Shodan=BrokenClient))
    failed = sm.ShodanRecon("key")
    assert failed.api is None
    assert "offline" in capsys.readouterr().out


def test_directory_database_connection_and_table_paths(monkeypatch, tmp_path, capsys):
    recon = _recon(results_dir=str(tmp_path / "nested"))
    assert Path(recon._ensure_dir()).is_dir()

    connected = MagicMock()
    connected.is_connected.return_value = True
    recon._db_conn = connected
    assert recon._get_db() is connected

    new_connection = MagicMock()
    connector = MagicMock(return_value=new_connection)
    monkeypatch.setattr(sm, "CFG", {"db": {}})
    monkeypatch.setattr(sm, "mysql", SimpleNamespace(connector=SimpleNamespace(connect=connector)))
    recon._db_conn = None
    recon._ensure_table = MagicMock()
    assert recon._get_db() is new_connection
    recon._ensure_table.assert_called_once()
    recon._ensure_table = sm.ShodanRecon._ensure_table.__get__(recon, sm.ShodanRecon)

    monkeypatch.setattr(sm, "mysql", None)
    recon._db_conn = None
    assert recon._get_db() is None

    recon._db_conn = None
    assert recon._ensure_table() is None

    table_connection = MagicMock()
    recon._db_conn = table_connection
    recon._ensure_table()
    table_connection.commit.assert_called_once()
    table_connection.cursor.return_value.close.assert_called_once()

    table_connection = MagicMock()
    table_connection.cursor.return_value.execute.side_effect = RuntimeError("ddl failed")
    recon._db_conn = table_connection
    recon._ensure_table()
    table_connection.rollback.assert_called_once()

    table_connection = MagicMock()
    table_connection.cursor.side_effect = RuntimeError("no cursor")
    recon._db_conn = table_connection
    recon._ensure_table()
    assert "no cursor" in capsys.readouterr().out


def test_search_all_outcomes(monkeypatch):
    assert _recon().search("query")["error"]

    match = {
        "ip_str": "192.0.2.1",
        "port": 443,
        "transport": "tcp",
        "_shodan": {"module": "https"},
        "data": "banner",
        "vulns": {"CVE-1": {}},
        "location": {"country_code": "CH"},
    }
    api = SimpleNamespace(search=lambda _query, limit: {"total": 1, "matches": [match]})
    recon = _recon(api=api, save_results=True)
    recon.save_to_db = MagicMock()
    recon._save_json = MagicMock()
    result = recon.search("port:443", max_results=2)
    assert result["matches"][0]["service"] == "https"
    assert result["matches"][0]["vulns"] == ["CVE-1"]
    recon.save_to_db.assert_called_once()
    recon._save_json.assert_called_once()

    class RaisingAPI:
        def __init__(self, error):
            self.error = error

        def search(self, *_args, **_kwargs):
            raise self.error

    monkeypatch.setattr(sm, "shodan", SimpleNamespace(APIError=FakeAPIError))
    assert "Shodan API error" in _recon(api=RaisingAPI(FakeAPIError("quota"))).search("q")["error"]
    assert "search failed" in _recon(api=RaisingAPI(RuntimeError("offline"))).search("q")["error"]


def test_host_info_all_outcomes(monkeypatch):
    assert _recon().host_info("192.0.2.1")["error"]

    host = {
        "ip_str": "192.0.2.1",
        "os": "TestOS",
        "org": "Example",
        "country_code": "CH",
        "ports": [443],
        "vulns": ["CVE-1"],
        "hostnames": ["host.test"],
        "data": [
            {
                "port": 443,
                "product": "https",
                "data": "banner",
                "vulns": {"CVE-1": {}},
            }
        ],
    }
    recon = _recon(api=SimpleNamespace(host=lambda _ip: host), save_results=True)
    recon.save_to_db = MagicMock()
    recon._save_json = MagicMock()
    result = recon.host_info("192.0.2.1")
    assert result["services"][0]["vulns"] == ["CVE-1"]
    recon.save_to_db.assert_called_once()
    recon._save_json.assert_called_once()

    empty = _recon(api=SimpleNamespace(host=lambda _ip: {"data": []}), save_results=False)
    assert empty.host_info("192.0.2.2")["services"] == []

    class RaisingHost:
        def __init__(self, error):
            self.error = error

        def host(self, _ip):
            raise self.error

    monkeypatch.setattr(sm, "shodan", SimpleNamespace(APIError=FakeAPIError))
    assert "Shodan host error" in _recon(api=RaisingHost(FakeAPIError("missing"))).host_info("x")["error"]
    assert _recon(api=RaisingHost(RuntimeError("offline"))).host_info("x") == {"error": "offline"}


def test_exploit_search_all_outcomes():
    assert _recon().search_exploits("query") == []
    api = SimpleNamespace(
        exploits=SimpleNamespace(
            search=lambda _query, limit: {"matches": [{"description": "x" * 300, "source": "db", "cve": ["CVE-1"]}]}
        )
    )
    result = _recon(api=api).search_exploits("query")
    assert len(result[0]["description"]) == 200

    api.exploits.search = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("offline"))
    assert _recon(api=api).search_exploits("query") == []


def test_database_save_guards_success_and_cursor_failure(capsys):
    recon = _recon(save_results=False)
    recon._get_db = MagicMock()
    assert recon.save_to_db({"matches": [{}]}) is None
    recon._get_db.assert_not_called()

    recon.save_results = True
    recon._get_db.return_value = None
    assert recon.save_to_db({"matches": [{}]}) is None

    connection = MagicMock()
    recon._get_db.return_value = connection
    assert recon.save_to_db({"matches": []}) is None

    payload = {
        "query": "port:443",
        "matches": [{"ip": "192.0.2.1", "port": 443, "banner": "x" * 2100}],
    }
    recon.save_to_db(payload)
    connection.cursor.return_value.executemany.assert_called_once()
    connection.commit.assert_called_once()

    connection = MagicMock()
    connection.cursor.side_effect = RuntimeError("cursor unavailable")
    recon._get_db.return_value = connection
    recon.save_to_db(payload)
    connection.rollback.assert_called_once()
    assert "cursor unavailable" in capsys.readouterr().out


def test_json_save_guards_and_both_cleanup_paths(monkeypatch, tmp_path):
    recon = _recon(save_results=False, results_dir=str(tmp_path))
    assert recon._save_json({}) == ""

    recon.save_results = True
    monkeypatch.setattr(sm.tempfile, "mkstemp", lambda **_kwargs: (_ for _ in ()).throw(OSError("full")))
    assert recon._save_json({}) == ""

    monkeypatch.undo()
    recon = _recon(save_results=True, results_dir=str(tmp_path))
    real_fdopen = sm.os.fdopen
    monkeypatch.setattr(sm.os, "fdopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("open failed")))
    assert recon._save_json({"a": 1}, "fd-error") == ""
    assert not list(tmp_path.glob("fd-error*.json"))

    monkeypatch.setattr(sm.os, "fdopen", real_fdopen)
    monkeypatch.setattr(sm.json, "dump", lambda *_args, **_kwargs: (_ for _ in ()).throw(TypeError("bad json")))
    assert recon._save_json({"a": object()}, "json-error") == ""
    assert not list(tmp_path.glob("json-error*.json"))


def test_pipeline_and_llm_formatting_branches():
    recon = _recon()
    assert recon.format_for_pipeline() == []
    matches = [
        {"ip": "", "port": 1},
        {"ip": "192.0.2.1", "port": 443, "service": "https", "vulns": ["CVE-2"]},
        {"ip": "192.0.2.1", "port": 443, "service": "https", "vulns": ["CVE-1"]},
        {"ip": "192.0.2.1", "port": 0, "service": "unknown", "vulns": []},
        {"ip": "192.0.2.2", "port": 22, "service": "ssh", "vulns": []},
    ]
    targets = recon.format_for_pipeline({"matches": matches})
    assert targets[0]["ports"] == [443]
    assert targets[0]["vulns"] == ["CVE-1", "CVE-2"]
    assert "No results" in recon.format_for_llm({"matches": []})
    rendered = recon.format_for_llm({"matches": matches, "total": 25})
    assert "and 5 more hosts" in rendered
    assert "none known" in rendered
    assert "CVE-1" in rendered
    assert "and" not in recon.format_for_llm({"matches": matches, "total": 2}).split("AI:")[0][-25:]


def test_auto_pipeline_failure_and_configuration_branches():
    recon = _recon(save_results=True, cfg={"auto_pipeline": True}, results_dir="reports")
    recon.search = MagicMock(return_value={"error": "quota", "matches": []})
    assert "failed" in recon.auto_pipeline("query")

    targets = [
        {"ip": "192.0.2.1", "vulns": ["CVE-1"]},
        {"ip": "192.0.2.2", "vulns": []},
    ]
    recon.search.return_value = {"matches": [{}]}
    recon.format_for_pipeline = MagicMock(return_value=targets)
    recon.format_for_llm = MagicMock(return_value="formatted")
    output = recon.auto_pipeline("query")
    assert "Results saved" in output
    assert "nmap" in output

    recon.save_results = False
    recon.cfg = {"auto_pipeline": False}
    output = recon.auto_pipeline("query")
    assert "persistence disabled" in output
    assert "nmap" not in output


class WrapperRecon:
    def __init__(self, *, api=True):
        self.api = object() if api else None
        self.cfg = {"auto_pipeline": True}
        self.search_result = {"matches": []}
        self.host_result = {}
        self.targets = []
        self.exploits = []

    def auto_pipeline(self, query):
        return f"auto:{query}"

    def search(self, query, max_results=None):
        self.seen = (query, max_results)
        return self.search_result

    def format_for_llm(self, _results):
        return "formatted"

    def format_for_pipeline(self, _results):
        return self.targets

    def host_info(self, _ip):
        return self.host_result

    def search_exploits(self, _query):
        return self.exploits


def test_search_wrapper_paths(monkeypatch):
    fixture = WrapperRecon(api=False)
    monkeypatch.setattr(sm, "ShodanRecon", lambda: fixture)
    assert "not available" in sm.run_shodan_search("q")

    fixture.api = object()
    assert sm.run_shodan_search("q") == "auto:q"
    fixture.cfg["auto_pipeline"] = False
    assert sm.run_shodan_search("q") == "formatted"


def test_host_wrapper_paths(monkeypatch):
    fixture = WrapperRecon(api=False)
    monkeypatch.setattr(sm, "ShodanRecon", lambda: fixture)
    assert "not available" in sm.run_shodan_host("192.0.2.1")

    fixture.api = object()
    fixture.host_result = {"error": "missing"}
    assert "missing" in sm.run_shodan_host("192.0.2.1")

    fixture.host_result = {
        "os": "TestOS",
        "org": "Example",
        "isp": "ISP",
        "city": "Bern",
        "country": "CH",
        "hostnames": ["host.test"],
        "ports": [22, 443],
        "vulns": ["CVE-1"],
        "services": [
            {
                "port": 443,
                "transport": "tcp",
                "product": "https",
                "version": "1",
                "vulns": ["CVE-1"],
                "banner": "hello",
            },
            {"port": 22, "transport": "tcp", "product": "ssh", "version": "2", "vulns": [], "banner": ""},
        ],
    }
    output = sm.run_shodan_host("192.0.2.1")
    assert "CVE-1" in output
    assert "Banner: hello" in output

    fixture.host_result = {"services": [], "vulns": []}
    assert "Services" in sm.run_shodan_host("192.0.2.2")


def test_vulnerability_wrapper_paths(monkeypatch):
    fixture = WrapperRecon(api=False)
    monkeypatch.setattr(sm, "ShodanRecon", lambda: fixture)
    assert "not available" in sm.run_shodan_vulns("192.0.2.1")
    fixture.api = object()
    fixture.host_result = {"error": "missing"}
    assert "missing" in sm.run_shodan_vulns("192.0.2.1")
    fixture.host_result = {"vulns": []}
    assert "No known CVEs" in sm.run_shodan_vulns("192.0.2.1")
    fixture.host_result = {
        "vulns": ["CVE-1"],
        "services": [
            {"port": 443, "transport": "tcp", "product": "https", "version": "1", "vulns": ["CVE-1"]},
            {"port": 22, "transport": "tcp", "product": "ssh", "version": "2", "vulns": []},
        ],
    }
    output = sm.run_shodan_vulns("192.0.2.1")
    assert "SEARCHSPLOIT: CVE-1" in output
    assert "443/tcp" in output


def test_interactive_no_api_target_and_interrupt(monkeypatch):
    fixture = WrapperRecon(api=False)
    monkeypatch.setattr(sm, "ShodanRecon", lambda: fixture)
    assert "not configured" in sm.run_shodan_interactive()
    fixture.api = object()
    monkeypatch.setattr(sm, "run_shodan_smart", lambda target: f"smart:{target}")
    assert sm.run_shodan_interactive("target") == "smart:target"
    monkeypatch.setattr(builtins, "input", lambda _prompt: (_ for _ in ()).throw(EOFError))
    assert sm.run_shodan_interactive() == ""


@pytest.mark.parametrize(
    ("answers", "expected"),
    [
        (("1", "query"), "search:query"),
        (("1", ""), "Cancelled"),
        (("2", "192.0.2.1"), "host:192.0.2.1"),
        (("2", ""), "Cancelled"),
        (("3", "192.0.2.1"), "vulns:192.0.2.1"),
        (("3", ""), "Cancelled"),
        (("5", "query"), "auto:query"),
        (("5", ""), "Cancelled"),
        (("6", "192.0.2.0/24"), "range:192.0.2.0/24"),
        (("6", ""), "Cancelled"),
        (("invalid",), "Cancelled"),
    ],
)
def test_interactive_menu_branches(monkeypatch, answers, expected):
    fixture = WrapperRecon()
    responses = iter(answers)
    monkeypatch.setattr(sm, "ShodanRecon", lambda: fixture)
    monkeypatch.setattr(builtins, "input", lambda _prompt: next(responses))
    monkeypatch.setattr(sm, "run_shodan_search", lambda query: f"search:{query}")
    monkeypatch.setattr(sm, "run_shodan_host", lambda ip: f"host:{ip}")
    monkeypatch.setattr(sm, "run_shodan_vulns", lambda ip: f"vulns:{ip}")
    monkeypatch.setattr(sm, "run_shodan_range", lambda cidr: f"range:{cidr}")
    assert expected in sm.run_shodan_interactive()


def test_interactive_exploit_menu_branches(monkeypatch):
    fixture = WrapperRecon()
    fixture.exploits = [
        {"source": "db", "description": "first", "cve": ["CVE-1"]},
        {"source": "db", "description": "second", "cve": []},
    ]
    monkeypatch.setattr(sm, "ShodanRecon", lambda: fixture)
    answers = iter(("4", "query"))
    monkeypatch.setattr(builtins, "input", lambda _prompt: next(answers))
    output = sm.run_shodan_interactive()
    assert "CVE-1" in output
    assert "second" in output

    answers = iter(("4", ""))
    assert "Cancelled" in sm.run_shodan_interactive()


def test_range_wrapper_paths(monkeypatch):
    fixture = WrapperRecon(api=False)
    monkeypatch.setattr(sm, "ShodanRecon", lambda: fixture)
    assert "not available" in sm.run_shodan_range("192.0.2.0/24")

    fixture.api = object()
    fixture.search_result = {"error": "quota", "matches": []}
    assert "No hosts" in sm.run_shodan_range("192.0.2.0/24")

    fixture.search_result = {"matches": [{}]}
    fixture.targets = [
        {"ip": "192.0.2.1", "ports": [443, 80], "vulns": ["CVE-1"]},
        {"ip": "192.0.2.2", "ports": [443], "vulns": []},
    ]
    output = sm.run_shodan_range("net:192.0.2.0/24")
    assert "443: 2 hosts" in output
    assert "CVE-1" in output

    fixture.targets = [{"ip": "192.0.2.3", "ports": [], "vulns": []}]
    output = sm.run_shodan_range("192.0.2.0/24")
    assert "Port distribution" not in output
    assert "known CVEs" not in output


@pytest.mark.parametrize(
    ("target", "handler"),
    [
        ("192.0.2.0/24", "range"),
        ("net:192.0.2.0/24", "range"),
        ("192.0.2.1", "host"),
        ("port:443", "search"),
    ],
)
def test_smart_routing(monkeypatch, target, handler):
    monkeypatch.setattr(sm, "run_shodan_range", lambda value: f"range:{value}")
    monkeypatch.setattr(sm, "run_shodan_host", lambda value: f"host:{value}")
    monkeypatch.setattr(sm, "run_shodan_search", lambda value: f"search:{value}")
    assert sm.run_shodan_smart(f" {target} ").startswith(handler)


class MainClient:
    def __init__(self, _key):
        pass

    def info(self):
        return {}

    def host(self, ip):
        return {"ip_str": ip, "data": [], "ports": []}

    def search(self, _query, limit):
        return {"total": 0, "matches": []}


def _run_main(monkeypatch, argv, *, api_key="key"):
    import config

    fake_shodan = ModuleType("shodan")
    fake_shodan.Shodan = MainClient
    fake_shodan.APIError = FakeAPIError
    monkeypatch.setitem(sys.modules, "shodan", fake_shodan)
    monkeypatch.setattr(config, "CFG", {"shodan": {"save_results": False}})
    monkeypatch.setattr(config, "get_secret", lambda *_args: api_key)
    monkeypatch.setattr(sys, "argv", [sm.__file__, *argv])
    runpy.run_path(sm.__file__, run_name="__main__")


def test_main_all_routes(monkeypatch, capsys):
    _run_main(monkeypatch, [])
    _run_main(monkeypatch, ["192.0.2.1"])
    _run_main(monkeypatch, ["port:443"])
    _run_main(monkeypatch, [], api_key="")
    output = capsys.readouterr().out
    assert "Usage:" in output
    assert "SHODAN HOST" in output
    assert "no results" in output.lower()
    assert "API not available" in output
