#!/usr/bin/env python3
"""Deprecated import facade for code that still imports top-level ``tools``.

New application code should import ``dispatch_registered_tool`` from
``core.tools``.  Historical names remain available for compatibility and their
migration metadata is exposed as ``__deprecated_exports__``.
"""

from core import tools as _core_tools
from core.tools import *  # noqa: F403

__all__ = tuple(_core_tools.__all__)
__deprecated_exports__ = _core_tools.DEPRECATED_TOOL_EXPORTS
