"""Test fakes package."""

from tests.fakes.c2_fake_providers import (
    InMemoryC2CleanupProvider,
    InMemoryC2DeployProvider,
    InMemoryC2EnrollProvider,
    InMemoryC2TaskProvider,
)

__all__ = [
    "InMemoryC2CleanupProvider",
    "InMemoryC2DeployProvider",
    "InMemoryC2EnrollProvider",
    "InMemoryC2TaskProvider",
]
