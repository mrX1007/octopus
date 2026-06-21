#!/usr/bin/env python3
"""Tests for config.py — configuration loading, merging, env overrides."""

import os
import pytest
from unittest.mock import patch


class TestLoadDefaults:
    """Test that default config values are correct."""

    def test_defaults_have_db_section(self):
        from config import DEFAULTS
        assert "db" in DEFAULTS
        assert "host" in DEFAULTS["db"]
        assert "user" in DEFAULTS["db"]
        assert "password" in DEFAULTS["db"]
        assert "database" in DEFAULTS["db"]

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

    def test_merge_adds_new_keys(self):
        from config import _deep_merge
        base = {"a": 1}
        override = {"b": 2}
        result = _deep_merge(base, override)
        assert result["a"] == 1
        assert result["b"] == 2

    def test_merge_does_not_mutate_base(self):
        from config import _deep_merge
        base = {"a": {"x": 1}}
        override = {"a": {"y": 2}}
        _deep_merge(base, override)
        # Base should not be mutated
        assert "y" not in base["a"]


class TestEnvVarOverrides:
    """Test that environment variables override config.yaml values."""

    @patch.dict(os.environ, {
        "OCTOPUS_DB_HOST": "env_host",
        "OCTOPUS_DB_USER": "env_user",
        "OCTOPUS_DB_PASS": "env_pass",
        "OCTOPUS_DB_NAME": "env_db",
    })
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
