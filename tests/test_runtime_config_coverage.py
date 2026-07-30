"""Complete hermetic coverage for shared runtime limit helpers."""

from __future__ import annotations

import sys
from types import ModuleType

import pytest

from core import runtime_config

pytestmark = pytest.mark.unit


def test_positive_int_and_runtime_limit_normalization() -> None:
    assert runtime_config._positive_int(True) is None
    assert runtime_config._positive_int(object()) is None
    assert runtime_config._positive_int(0) is None
    assert runtime_config._positive_int("3") == 3

    assert runtime_config.effective_runtime_limit() is None
    assert runtime_config.effective_runtime_limit(8, 3) == 3
    assert runtime_config.effective_runtime_limit("bad", 4) == 4


def test_parallel_workers_uses_smallest_explicit_nested_limit() -> None:
    assert (
        runtime_config.effective_parallel_workers(
            5,
            config={
                "ollama": {"concurrent_tools": "3"},
                "strategy": {"parallel_tools": 4},
            },
        )
        == 3
    )
    assert (
        runtime_config.effective_parallel_workers(
            "2",
            config={"ollama": "invalid", "strategy": []},
        )
        == 2
    )
    assert runtime_config.effective_parallel_workers(None, config=object()) == 1


def test_parallel_workers_imports_cfg_and_falls_back_when_cfg_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = ModuleType("config")
    configured.CFG = {  # type: ignore[attr-defined]
        "ollama": {"concurrent_tools": 6},
        "strategy": {"parallel_tools": 2},
    }
    monkeypatch.setitem(sys.modules, "config", configured)
    assert runtime_config.effective_parallel_workers() == 2

    missing_cfg = ModuleType("config")
    monkeypatch.setitem(sys.modules, "config", missing_cfg)
    assert runtime_config.effective_parallel_workers() == 1
