"""Side-effect-free, lazy public facade for OCTOPUS CLI primitives."""

from __future__ import annotations

from importlib import import_module
from typing import Any

_PRESENTATION_EXPORTS = (
    "RICH_AVAILABLE",
    "banner",
    "confirm",
    "console",
    "divider",
    "error",
    "info",
    "print_reporting_sections",
    "print_results_table",
    "print_rich_table",
    "prompt",
    "run_with_spinner",
    "success",
    "warn",
)
_EXPORTS = {
    **{name: (".presentation", name) for name in _PRESENTATION_EXPORTS},
    "setup_readline": (".history", "setup_readline"),
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
