"""Closed C2 deployment profile vocabulary.

This module is the sole owner of the deployment profile, method, operating
system, and architecture enums used by V2 action inputs. Keeping these values
out of adapters prevents callers from selecting arbitrary deployment backends.
"""

from __future__ import annotations

from enum import Enum


class C2DeploymentProfileId(str, Enum):
    GO_AGENT = "deployment://go-agent"
    PYTHON_AGENT = "deployment://python-agent"
    POWERSHELL_STAGER = "deployment://powershell-stager"


class C2DeploymentMethod(str, Enum):
    SSH_SESSION = "ssh-session"


class C2TargetOS(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    DARWIN = "darwin"


class C2TargetArch(str, Enum):
    AMD64 = "amd64"
    ARM64 = "arm64"


__all__ = [
    "C2DeploymentMethod",
    "C2DeploymentProfileId",
    "C2TargetArch",
    "C2TargetOS",
]
