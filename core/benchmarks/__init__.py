"""Versioned benchmark scenarios and replay-first harness.

The public names remain import-compatible, but they are resolved lazily.  In
particular, importing :mod:`core.benchmarks.v3` for the standalone fixture must
not initialize the application pipeline or require optional runtime profiles.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORTS = {
    "BENCHMARK_SCHEMA_VERSION": (".schema", "BENCHMARK_SCHEMA_VERSION"),
    "REQUIRED_SCENARIO_CATEGORIES": (".schema", "REQUIRED_SCENARIO_CATEGORIES"),
    "TASK_EFFICIENCY_SCENARIO_VERSION": (
        ".task_efficiency",
        "TASK_EFFICIENCY_SCENARIO_VERSION",
    ),
    "TASK_EFFICIENCY_SCHEMA_VERSION": (
        ".task_efficiency",
        "TASK_EFFICIENCY_SCHEMA_VERSION",
    ),
    "BenchmarkAggregate": (".schema", "BenchmarkAggregate"),
    "BenchmarkHarness": (".harness", "BenchmarkHarness"),
    "BenchmarkRun": (".schema", "BenchmarkRun"),
    "BenchmarkRunner": (".harness", "BenchmarkRunner"),
    "BenchmarkScenario": (".schema", "BenchmarkScenario"),
    "BenchmarkSchemaError": (".schema", "BenchmarkSchemaError"),
    "load_scenario": (".schema", "load_scenario"),
    "load_scenarios": (".schema", "load_scenarios"),
    "run_task_efficiency_comparison": (
        ".task_efficiency",
        "run_task_efficiency_comparison",
    ),
    "write_task_efficiency_comparison": (
        ".task_efficiency",
        "write_task_efficiency_comparison",
    ),
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    try:
        module_name, attribute = _EXPORTS[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    value = getattr(import_module(module_name, __name__), attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *__all__})
