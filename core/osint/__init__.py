#!/usr/bin/env python3

import contextlib

with contextlib.suppress(ImportError):
    from .shardbrowser import ShardBrowser, ShardBrowserNotInstalled
