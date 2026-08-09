"""Hermetic branch coverage for :mod:`config`."""

import builtins
import copy
import os
import runpy
import sys
import types

import pytest

import config

pytestmark = pytest.mark.unit


_ENV_OVERRIDES = (
    "OCTOPUS_CONFIG",
    "OCTOPUS_DB_HOST",
    "OCTOPUS_DB_USER",
    "OCTOPUS_DB_PASS",
    "OCTOPUS_DB_NAME",
    "OCTOPUS_OLLAMA_URL",
    "OCTOPUS_OLLAMA_MODEL",
    "OCTOBENCH_OLLAMA_CONTEXT_LENGTH",
)


def _clear_config_env(monkeypatch):
    for name in _ENV_OVERRIDES:
        monkeypatch.delenv(name, raising=False)


def test_find_config_returns_empty_without_any_candidate(monkeypatch):
    _clear_config_env(monkeypatch)
    monkeypatch.setattr(config, "_USER_CONFIG_PATH", "/virtual/user.yaml")
    monkeypatch.setattr(config, "_SYSTEM_CONFIG_PATH", "/virtual/system.yaml")
    monkeypatch.setattr(config, "_BUNDLED_CONFIG_PATH", "/virtual/bundled.yaml")
    monkeypatch.setattr(config.os.path, "isfile", lambda _path: False)

    assert config._find_config() == ""


@pytest.mark.parametrize(
    ("default", "expected"),
    [
        (1, "integer"),
        (1.5, "number"),
        ([], "list"),
        ({}, "mapping"),
        (None, "NoneType"),
    ],
)
def test_expected_type_name_covers_each_remaining_kind(default, expected):
    assert config._expected_type_name(default) == expected


def test_type_matching_covers_list_mapping_and_fallback_guards():
    assert not config._matches_default_type("not-a-list", [])
    assert config._matches_default_type({}, {})
    assert not config._matches_default_type([], {})
    assert config._matches_default_type(None, None)
    assert not config._matches_default_type(0, None)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("ollama", "top_p"), 2, r"ollama\.top_p must be <= 1"),
        (
            ("bruteforce", "ssh_thread_levels"),
            [0],
            r"bruteforce\.ssh_thread_levels\[0\] must be >= 1",
        ),
        (
            ("bruteforce", "ssh_thread_levels"),
            [257],
            r"bruteforce\.ssh_thread_levels\[0\] must be <= 256",
        ),
    ],
)
def test_value_validation_rejects_remaining_out_of_range_cases(
    path,
    value,
    message,
):
    with pytest.raises(config.ConfigValidationError, match=message):
        config._validate_value(path, value)


def test_deep_merge_rejects_non_mapping_inputs():
    with pytest.raises(config.ConfigValidationError, match="<root> must be a mapping"):
        config._deep_merge([], {})


def test_load_config_accepts_empty_yaml(monkeypatch, tmp_path):
    _clear_config_env(monkeypatch)
    config_path = tmp_path / "empty.yaml"
    config_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(config, "_find_config", lambda: str(config_path))

    loaded = config.load_config()

    assert loaded["db"] == config.DEFAULTS["db"]


def test_load_config_wraps_filesystem_errors(monkeypatch, tmp_path):
    _clear_config_env(monkeypatch)
    config_path = tmp_path / "unreadable.yaml"
    monkeypatch.setattr(config, "_find_config", lambda: str(config_path))

    def fail_open(*_args, **_kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(builtins, "open", fail_open)
    with pytest.raises(
        config.ConfigValidationError,
        match=r"failed to read configuration .*permission denied",
    ):
        config.load_config()


def test_load_config_defensive_paths_and_url_override(monkeypatch):
    _clear_config_env(monkeypatch)
    monkeypatch.setattr(config, "_find_config", lambda: "")

    defaults = copy.deepcopy(config.DEFAULTS)
    defaults["paths"] = "not-a-mapping"
    monkeypatch.setattr(config, "DEFAULTS", defaults)
    assert config.load_config()["paths"] == "not-a-mapping"

    defaults["paths"] = {"reports": 7}
    monkeypatch.setenv("OCTOPUS_OLLAMA_URL", "http://ollama.test/api")
    loaded = config.load_config()

    assert loaded["paths"]["reports"] == 7
    assert loaded["ollama"]["url"] == "http://ollama.test/api"


def test_wordlist_and_tool_helpers_cover_defensive_and_success_paths(
    monkeypatch,
    tmp_path,
):
    present = tmp_path / "present.txt"
    present.write_text("value\n", encoding="utf-8")
    missing = tmp_path / "missing.txt"
    wordlist_cfg = {
        "wordlists": {"category": [7, str(missing), str(present)]},
    }

    assert config.find_wordlist("category", None) in {"", str(present)}
    assert config.find_wordlist("category", "not-a-mapping") == ""
    assert config.find_wordlist("category", {"wordlists": {"category": 7}}) == ""
    assert config.find_wordlist("category", wordlist_cfg) == str(present)

    assert config.find_all_wordlists("category", "not-a-mapping") == []
    assert (
        config.find_all_wordlists(
            "category",
            {"wordlists": {"category": 7}},
        )
        == []
    )
    assert config.find_all_wordlists("category", wordlist_cfg) == [str(present)]

    assert isinstance(config.get_tool_config("nmap"), dict)
    assert config.get_tool_config("nmap", "not-a-mapping") == {}
    assert config.get_tool_config("custom", {"tools": {"custom": "bad"}}) == {}


def test_get_secret_covers_yaml_and_malformed_sections(monkeypatch):
    for name in ("SHODAN_API_KEY", "OCTOPUS_DB_PASS"):
        monkeypatch.delenv(name, raising=False)

    monkeypatch.setattr(config, "CFG", {"shodan": {"api_key": "from-yaml"}})
    assert config.get_secret("SHODAN_API_KEY") == "from-yaml"

    monkeypatch.setattr(config, "CFG", {"db": "not-a-mapping"})
    assert config.get_secret("OCTOPUS_DB_PASS", "fallback") == "fallback"

    monkeypatch.setattr(config, "CFG", {})
    assert config.get_secret("UNKNOWN_SECRET", "fallback") == "fallback"


def test_module_entrypoint_loads_first_dotenv_and_prints_summary(
    monkeypatch,
    tmp_path,
    capsys,
):
    _clear_config_env(monkeypatch)
    config_path = tmp_path / "config.yaml"
    config_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("OCTOPUS_CONFIG", str(config_path))

    dotenv_calls = []
    fake_dotenv = types.ModuleType("dotenv")
    fake_dotenv.load_dotenv = lambda path=None: dotenv_calls.append(path)
    monkeypatch.setitem(sys.modules, "dotenv", fake_dotenv)

    expected_dotenv = os.path.join(os.path.dirname(config.__file__), ".env")
    existing = {expected_dotenv, str(config_path)}
    monkeypatch.setattr(os.path, "isfile", lambda path: os.fspath(path) in existing)

    runpy.run_path(config.__file__, run_name="__main__")

    output = capsys.readouterr().out
    assert dotenv_calls == [expected_dotenv]
    assert "OCTOPUS — Config Loader" in output
    assert "[ WORDLIST AVAILABILITY ]" in output
    assert "[ TOOL TIMEOUTS ]" in output


def test_module_import_tolerates_missing_dotenv(monkeypatch, tmp_path):
    _clear_config_env(monkeypatch)
    config_path = tmp_path / "config.yaml"
    config_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("OCTOPUS_CONFIG", str(config_path))
    monkeypatch.setitem(sys.modules, "dotenv", None)
    monkeypatch.setattr(
        os.path,
        "isfile",
        lambda path: os.fspath(path) == str(config_path),
    )

    namespace = runpy.run_path(config.__file__, run_name="_config_without_dotenv")

    assert namespace["CFG"]["db"] == namespace["DEFAULTS"]["db"]
