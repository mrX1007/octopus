#!/usr/bin/env python3
"""Deprecated compatibility facade and executable entry point.

New code should import :mod:`core.cli` primitives or
:mod:`core.cli.main`. Existing ``import octopus`` callers retain an isolated
legacy namespace so dependency stubs and monkeypatches behave as they did when
this file contained the implementation.
"""

from __future__ import annotations

import sys
from types import FunctionType

from core.cli import application as _application_module
from core.cli.main import create_app as _create_app
from core.cli.main import create_parser as create_parser
from core.cli.main import main as _main


def _bind_legacy_namespace() -> tuple[str, ...]:
    """Bind workflow aliases while preserving module-local monkeypatch state."""

    implementation = {
        name: value
        for name, value in vars(_application_module).items()
        if not (name.startswith("__") and name != "__version__")
    }
    for name, value in implementation.items():
        if isinstance(value, FunctionType) and value.__module__ == _application_module.__name__:
            rebound = FunctionType(
                value.__code__,
                globals(),
                value.__name__,
                value.__defaults__,
                value.__closure__,
            )
            rebound.__annotations__ = dict(value.__annotations__)
            rebound.__dict__.update(value.__dict__)
            rebound.__doc__ = value.__doc__
            rebound.__kwdefaults__ = value.__kwdefaults__
            rebound.__qualname__ = value.__qualname__
            globals()[name] = rebound
        else:
            globals()[name] = value

    # A removed/re-imported legacy module historically rebound whatever DB,
    # export, or tool stubs were active at that moment. Keep that test/plugin
    # seam without reloading or mutating the canonical workflow module.
    for provider_name in ("db", "export", "tools"):
        provider = sys.modules.get(provider_name)
        if provider is None:
            continue
        for name in implementation:
            if hasattr(provider, name):
                globals()[name] = getattr(provider, name)
    return tuple(implementation)


_FORWARDED_NAMES = _bind_legacy_namespace()


def create_app(workflows=None):
    """Compose the canonical lifecycle around this compatibility namespace."""

    return _create_app(workflows or sys.modules[__name__])


def main(argv=None, *, app=None) -> int:
    """Run the explicit CLI dispatcher with legacy monkeypatch compatibility."""

    return _main(argv, app=app or create_app())


__all__ = sorted(
    {
        *(name for name in _FORWARDED_NAMES if not name.startswith("_")),
        "create_app",
        "create_parser",
        "main",
    }
)


if __name__ == "__main__":
    raise SystemExit(main())
