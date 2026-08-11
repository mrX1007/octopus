#!/usr/bin/env python3
"""Tests for config.py — configuration loading, merging, env overrides."""

import os
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit


class TestLoadDefaults:
    """Test that default config values are correct."""

    def test_defaults_have_db_section(self):
        from config import DEFAULTS

        assert "db" in DEFAULTS
        assert "host" in DEFAULTS["db"]
        assert "user" in DEFAULTS["db"]
        assert "password" in DEFAULTS["db"]
        assert "database" in DEFAULTS["db"]

    def test_defaults_do_not_embed_a_database_password(self):
        from config import DEFAULTS

        assert DEFAULTS["db"]["password"] == ""

    def test_checked_in_config_does_not_embed_a_database_password(self):
        from pathlib import Path

        import yaml

        import config

        checked_in = yaml.safe_load(Path(config.__file__).with_name("config.yaml").read_text(encoding="utf-8"))
        assert checked_in["db"]["password"] == ""

    def test_defaults_have_ollama_section(self):
        from config import DEFAULTS

        assert "ollama" in DEFAULTS
        assert "url" in DEFAULTS["ollama"]
        assert "model" in DEFAULTS["ollama"]

    def test_defaults_have_paths_section(self):
        from config import DEFAULTS

        assert "paths" in DEFAULTS


class TestDeepMerge:
    """Test the _deep_merge function."""

    def test_merge_overwrites_scalars(self):
        from config import _deep_merge

        base = {"a": 1, "b": 2}
        override = {"b": 3}
        result = _deep_merge(base, override)
        assert result["a"] == 1
        assert result["b"] == 3

    def test_merge_nested_dicts(self):
        from config import _deep_merge

        base = {"db": {"host": "localhost", "port": 3306}}
        override = {"db": {"host": "remote"}}
        result = _deep_merge(base, override)
        assert result["db"]["host"] == "remote"
        assert result["db"]["port"] == 3306

    def test_merge_rejects_unknown_keys(self):
        from config import ConfigValidationError, _deep_merge

        base = {"a": 1}
        override = {"b": 2}

        with pytest.raises(ConfigValidationError, match="unknown configuration key 'b'"):
            _deep_merge(base, override)

    def test_merge_does_not_mutate_base(self):
        from config import _deep_merge

        base = {"a": {"x": 1, "y": 0}}
        override = {"a": {"y": 2}}
        result = _deep_merge(base, override)
        # Base should not be mutated
        assert base["a"]["y"] == 0
        assert result["a"]["y"] == 2

    def test_merge_detaches_untouched_nested_values_and_override(self):
        from config import _deep_merge

        base = {
            "nested": {"items": ["base"]},
            "extension": {"items": ["default"]},
        }
        override = {"extension": {"items": ["override"]}}
        result = _deep_merge(base, override)

        result["nested"]["items"].append("changed")
        result["extension"]["items"].append("changed")
        assert base["nested"]["items"] == ["base"]
        assert override["extension"]["items"] == ["override"]

    def test_default_loads_do_not_share_nested_state(self):
        import config

        with patch("config._find_config", return_value=""):
            first = config.load_config()
            second = config.load_config()
        first["wordlists"]["passwords"].append("/tmp/leak")

        assert "/tmp/leak" not in second["wordlists"]["passwords"]
        assert "/tmp/leak" not in config.DEFAULTS["wordlists"]["passwords"]


class TestConfigValidation:
    def test_invalid_nested_sections_fail_closed(self, tmp_path):
        import config

        path = tmp_path / "invalid.yaml"
        path.write_text(
            "db: null\npaths: broken\nwordlists: []\ntools: null\n",
            encoding="utf-8",
        )
        with (
            patch("config._find_config", return_value=str(path)),
            pytest.raises(
                config.ConfigValidationError,
                match=r"invalid configuration .*db must be a mapping",
            ),
        ):
            config.load_config()

    def test_invalid_known_leaf_fails_closed(self, tmp_path):
        import config

        path = tmp_path / "invalid-leaf.yaml"
        path.write_text("db:\n  host: null\n  user: 42\n", encoding="utf-8")
        with (
            patch("config._find_config", return_value=str(path)),
            pytest.raises(
                config.ConfigValidationError,
                match=r"db.host must be string; got NoneType",
            ),
        ):
            config.load_config()

    def test_non_mapping_yaml_fails_closed(self, tmp_path):
        import config

        path = tmp_path / "list.yaml"
        path.write_text("- not\n- a\n- mapping\n", encoding="utf-8")
        with (
            patch("config._find_config", return_value=str(path)),
            pytest.raises(
                config.ConfigValidationError,
                match="top-level YAML value must be a mapping",
            ),
        ):
            config.load_config()

    def test_unknown_killchain_stage_names_fail_closed(self, tmp_path):
        import config

        path = tmp_path / "misspelled-stage.yaml"
        path.write_text(
            "killchain:\n  stages:\n    data_exfill: false\n",
            encoding="utf-8",
        )
        with (
            patch("config._find_config", return_value=str(path)),
            pytest.raises(
                config.ConfigValidationError,
                match=r"unknown killchain stage 'killchain\.stages\.data_exfill'",
            ) as exc_info,
        ):
            config.load_config()

        assert "data_exfil" in str(exc_info.value)
        assert "cleanup" in str(exc_info.value)

    def test_known_killchain_stage_requires_a_boolean(self, tmp_path):
        import config

        path = tmp_path / "invalid-stage-type.yaml"
        path.write_text(
            'killchain:\n  stages:\n    cleanup: "false"\n',
            encoding="utf-8",
        )
        with (
            patch("config._find_config", return_value=str(path)),
            pytest.raises(
                config.ConfigValidationError,
                match=r"killchain\.stages\.cleanup must be boolean",
            ),
        ):
            config.load_config()

    def test_out_of_range_numeric_values_fail_closed(self, tmp_path):
        import config

        path = tmp_path / "invalid-range.yaml"
        path.write_text(
            "strategy:\n  parallel_tools: 0\n",
            encoding="utf-8",
        )
        with (
            patch("config._find_config", return_value=str(path)),
            pytest.raises(
                config.ConfigValidationError,
                match=r"strategy\.parallel_tools must be >= 1",
            ),
        ):
            config.load_config()

    def test_plan_enrichment_limit_zero_is_an_explicit_disable(self, tmp_path):
        import config

        path = tmp_path / "disable-enrichment.yaml"
        path.write_text(
            "strategy:\n  plan_enrichment_limit: 0\n",
            encoding="utf-8",
        )
        with patch("config._find_config", return_value=str(path)):
            loaded = config.load_config()

        assert loaded["strategy"]["plan_enrichment_limit"] == 0

    def test_typed_task_inputs_accept_explicit_scopes_and_plugin_parameters(self, tmp_path):
        import config

        path = tmp_path / "typed-inputs.yaml"
        path.write_text(
            """strategy:
  task_inputs:
    filesystem_scopes: [/srv/authorized-source]
    session_profiles: [/srv/authorized-source/session.json]
    jwt_artifacts: [/srv/authorized-source/token.txt]
    burp_exports: [/srv/authorized-source/burp.xml]
    zap_exports: [/srv/authorized-source/zap.json]
    openapi_specs: [https://api.example.test/openapi.json]
    cloud_providers: [AWS, gcp]
    plugin_actions:
      payload_keying:
        payload: artifact://sha256/example
        attempts: 2
        enabled: true
""",
            encoding="utf-8",
        )

        with patch("config._find_config", return_value=str(path)):
            loaded = config.load_config()

        inputs = loaded["strategy"]["task_inputs"]
        assert inputs["cloud_providers"] == ["AWS", "gcp"]
        assert inputs["plugin_actions"]["payload_keying"] == {
            "payload": "artifact://sha256/example",
            "attempts": 2,
            "enabled": True,
        }

    def test_plugin_action_control_and_nested_json_are_preserved(self, tmp_path):
        import config

        path = tmp_path / "plugin-action-inputs.yaml"
        path.write_text(
            """strategy:
  task_inputs:
    plugin_actions:
      synthetic_active:
        action: run
        label: neutral fixture
        target_info:
          hostname: host one
          roles: [web, api worker]
        tags: [alpha, two words]
""",
            encoding="utf-8",
        )

        with patch("config._find_config", return_value=str(path)):
            loaded = config.load_config()

        assert loaded["strategy"]["task_inputs"]["plugin_actions"] == {
            "synthetic_active": {
                "action": "run",
                "label": "neutral fixture",
                "target_info": {
                    "hostname": "host one",
                    "roles": ["web", "api worker"],
                },
                "tags": ["alpha", "two words"],
            }
        }

    @pytest.mark.parametrize("action", [123, "delete"])
    def test_plugin_action_control_rejects_invalid_values(self, tmp_path, action):
        import yaml

        import config

        path = tmp_path / "invalid-plugin-action.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "strategy": {
                        "task_inputs": {
                            "plugin_actions": {
                                "synthetic_active": {"action": action},
                            }
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        with (
            patch("config._find_config", return_value=str(path)),
            pytest.raises(
                config.ConfigValidationError,
                match=r"strategy\.task_inputs\.plugin_actions\.synthetic_active\.action",
            ),
        ):
            config.load_config()

    def test_typed_task_inputs_reject_non_string_scopes(self, tmp_path):
        import config

        path = tmp_path / "invalid-typed-inputs.yaml"
        path.write_text(
            "strategy:\n  task_inputs:\n    filesystem_scopes: [123]\n",
            encoding="utf-8",
        )

        with (
            patch("config._find_config", return_value=str(path)),
            pytest.raises(
                config.ConfigValidationError,
                match=r"strategy\.task_inputs\.filesystem_scopes must be list",
            ),
        ):
            config.load_config()

    def test_typed_task_inputs_reject_unknown_cloud_provider(self, tmp_path):
        import config

        path = tmp_path / "invalid-cloud-provider.yaml"
        path.write_text(
            "strategy:\n  task_inputs:\n    cloud_providers: [example.test]\n",
            encoding="utf-8",
        )

        with (
            patch("config._find_config", return_value=str(path)),
            pytest.raises(
                config.ConfigValidationError,
                match=r"strategy\.task_inputs\.cloud_providers\[0\] must be a supported cloud provider",
            ),
        ):
            config.load_config()

    def test_plugin_task_inputs_require_parameter_mappings(self, tmp_path):
        import config

        path = tmp_path / "invalid-plugin-inputs.yaml"
        path.write_text(
            "strategy:\n  task_inputs:\n    plugin_actions:\n      payload_keying: invalid\n",
            encoding="utf-8",
        )

        with (
            patch("config._find_config", return_value=str(path)),
            pytest.raises(
                config.ConfigValidationError,
                match=r"strategy\.task_inputs\.plugin_actions\.payload_keying must be a mapping",
            ),
        ):
            config.load_config()

    def test_negative_plan_enrichment_limit_fails_closed(self, tmp_path):
        import config

        path = tmp_path / "negative-enrichment.yaml"
        path.write_text(
            "strategy:\n  plan_enrichment_limit: -1\n",
            encoding="utf-8",
        )
        with (
            patch("config._find_config", return_value=str(path)),
            pytest.raises(
                config.ConfigValidationError,
                match=r"strategy\.plan_enrichment_limit must be >= 0",
            ),
        ):
            config.load_config()

    def test_non_finite_numeric_values_fail_closed(self, tmp_path):
        import config

        path = tmp_path / "non-finite.yaml"
        path.write_text("ollama:\n  top_p: .nan\n", encoding="utf-8")
        with (
            patch("config._find_config", return_value=str(path)),
            pytest.raises(
                config.ConfigValidationError,
                match=r"ollama\.top_p must be finite",
            ),
        ):
            config.load_config()

    def test_malformed_explicit_yaml_never_falls_back_to_defaults(
        self,
        monkeypatch,
        tmp_path,
    ):
        import config

        path = tmp_path / "explicit.yaml"
        path.write_text("killchain: [not, a, mapping]\n", encoding="utf-8")
        monkeypatch.setenv("OCTOPUS_CONFIG", str(path))

        with pytest.raises(
            config.ConfigValidationError,
            match=r"killchain must be a mapping",
        ):
            config.load_config()

    def test_checked_in_config_has_exact_killchain_stage_contract(self):
        from pathlib import Path

        import yaml

        import config

        checked_in = yaml.safe_load(Path(config.__file__).with_name("config.yaml").read_text(encoding="utf-8"))
        assert tuple(checked_in["killchain"]["stages"]) == config.KILLCHAIN_STAGE_KEYS
        config._deep_merge(config.DEFAULTS, checked_in)

    def test_dead_sensitive_killchain_keys_are_not_public_configuration(self):
        from pathlib import Path

        import yaml

        import config

        checked_in = yaml.safe_load(Path(config.__file__).with_name("config.yaml").read_text(encoding="utf-8"))
        retired = {"exfil_dir", "auto_crack_after_privesc", "backdoor_password"}
        assert retired.isdisjoint(config.DEFAULTS["killchain"])
        assert retired.isdisjoint(checked_in["killchain"])


class TestConfigPrecedence:
    def test_explicit_then_user_then_system_then_bundled(self, monkeypatch):
        import config

        explicit = "/virtual/explicit.yaml"
        user = "/virtual/user.yaml"
        system = "/virtual/system.yaml"
        bundled = "/virtual/bundled.yaml"
        existing = {explicit, user, system, bundled}
        monkeypatch.setattr(config, "_USER_CONFIG_PATH", user)
        monkeypatch.setattr(config, "_SYSTEM_CONFIG_PATH", system)
        monkeypatch.setattr(config, "_BUNDLED_CONFIG_PATH", bundled)
        monkeypatch.setattr(config.os.path, "isfile", lambda path: path in existing)
        monkeypatch.setenv("OCTOPUS_CONFIG", explicit)

        assert config._find_config() == explicit

        monkeypatch.delenv("OCTOPUS_CONFIG")
        assert config._find_config() == user

        existing.remove(user)
        assert config._find_config() == system

        existing.remove(system)
        assert config._find_config() == bundled

    def test_missing_explicit_path_does_not_fall_through(self, monkeypatch):
        import config

        monkeypatch.setenv("OCTOPUS_CONFIG", "/virtual/missing.yaml")
        monkeypatch.setattr(config.os.path, "isfile", lambda _path: False)

        with pytest.raises(
            config.ConfigValidationError,
            match="OCTOPUS_CONFIG does not reference a readable file",
        ):
            config._find_config()


class TestEnvVarOverrides:
    """Test that environment variables override config.yaml values."""

    @patch.dict(
        os.environ,
        {
            "OCTOPUS_DB_HOST": "env_host",
            "OCTOPUS_DB_USER": "env_user",
            "OCTOPUS_DB_PASS": "env_pass",
            "OCTOPUS_DB_NAME": "env_db",
        },
    )
    def test_db_env_overrides(self):
        from config import load_config

        cfg = load_config()
        assert cfg["db"]["host"] == "env_host"
        assert cfg["db"]["user"] == "env_user"
        assert cfg["db"]["password"] == "env_pass"
        assert cfg["db"]["database"] == "env_db"

    @patch.dict(os.environ, {"OCTOPUS_OLLAMA_MODEL": "custom-model"})
    def test_ollama_env_override(self):
        from config import load_config

        cfg = load_config()
        assert cfg["ollama"]["model"] == "custom-model"

    @patch.dict(os.environ, {"OCTOBENCH_OLLAMA_CONTEXT_LENGTH": "65536"})
    def test_benchmark_ollama_context_override(self):
        from config import load_config

        cfg = load_config()
        assert cfg["ollama"]["num_ctx"] == 65536

    @patch.dict(os.environ, {"OCTOBENCH_OLLAMA_CONTEXT_LENGTH": "not-an-int"})
    def test_malformed_benchmark_context_override_fails_closed(self):
        from config import ConfigValidationError, load_config

        with pytest.raises(
            ConfigValidationError,
            match=r"OCTOBENCH_OLLAMA_CONTEXT_LENGTH must be an integer",
        ):
            load_config()

    @patch.dict(os.environ, {}, clear=False)
    def test_no_env_uses_yaml_defaults(self):
        """When no env vars are set, config.yaml / DEFAULTS are used."""
        # Remove our test env vars if present
        for key in ["OCTOPUS_DB_HOST", "OCTOPUS_DB_USER", "OCTOPUS_DB_PASS", "OCTOPUS_DB_NAME"]:
            os.environ.pop(key, None)
        from config import load_config

        cfg = load_config()
        # Should have some value (from yaml or defaults)
        assert cfg["db"]["host"]
        assert cfg["db"]["user"]


class TestGetSecret:
    """Test the get_secret() helper."""

    def test_get_secret_with_default(self):
        from config import get_secret

        result = get_secret("NONEXISTENT_KEY_12345", default="fallback")
        assert result == "fallback"

    @patch.dict(os.environ, {"TEST_SECRET_KEY": "secret_value"})
    def test_get_secret_from_env(self):
        from config import get_secret

        result = get_secret("TEST_SECRET_KEY", default="fallback")
        assert result == "secret_value"


class TestFindWordlist:
    """Test wordlist discovery."""

    def test_find_wordlist_returns_string(self):
        from config import find_wordlist

        result = find_wordlist("passwords")
        assert isinstance(result, str)

    def test_find_all_wordlists_returns_list(self):
        from config import find_all_wordlists

        result = find_all_wordlists("passwords")
        assert isinstance(result, list)

    def test_helpers_tolerate_malformed_custom_config(self):
        from config import find_all_wordlists, find_wordlist, get_tool_config

        assert find_wordlist("passwords", {"wordlists": None}) == ""
        assert find_all_wordlists("passwords", {"wordlists": "bad"}) == []
        assert get_tool_config("nmap", {"tools": None}) == {}
