#!/usr/bin/env python3
"""Legacy facade for code that still imports top-level ``tools``."""

from core.tools import *  # noqa: F401,F403
from core.tools import __all__  # re-export the same public contract
