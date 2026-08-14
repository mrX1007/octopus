"""Test fakes and in-memory providers for C2 lifecycle tests."""

from __future__ import annotations

import time
import uuid
from typing import Any


class InMemoryC2EnrollProvider:
    """In-memory test fake for agent enrollment operations."""

    def __init__(self, authenticator: Any = None) -> None:
        self.authenticator = authenticator

    def validate_input(self, params: dict[str, Any]) -> bool:
        if not isinstance(params, dict):
            return False
        return "mission_id" in params and "agent_ref" in params

    def check_readiness(self) -> bool:
        return True

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        if not self.validate_input(params):
            raise ValueError("Invalid enrollment parameters: mission_id and agent_ref required")

        enrollment_id = f"enr_{uuid.uuid4().hex[:8]}"
        return {
            "status": "enrolled",
            "enrollment_id": enrollment_id,
            "mission_id": params["mission_id"],
            "agent_ref": params["agent_ref"],
            "enrolled_at": time.time(),
        }


class InMemoryC2DeployProvider:
    """In-memory test fake for component deployment operations."""

    def __init__(self, authenticator: Any = None) -> None:
        self.authenticator = authenticator

    def validate_input(self, params: dict[str, Any]) -> bool:
        if not isinstance(params, dict):
            return False
        return "target_host" in params and "component" in params

    def check_readiness(self) -> bool:
        return True

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        if not self.validate_input(params):
            raise ValueError("Invalid deploy parameters: target_host and component required")

        deploy_id = f"dep_{uuid.uuid4().hex[:8]}"
        return {
            "status": "deployed",
            "deployment_id": deploy_id,
            "target_host": params["target_host"],
            "component": params["component"],
            "deployed_at": time.time(),
        }


class InMemoryC2TaskProvider:
    """In-memory test fake for C2 agent tasking operations."""

    def __init__(self, authenticator: Any = None) -> None:
        self.authenticator = authenticator

    def validate_input(self, params: dict[str, Any]) -> bool:
        if not isinstance(params, dict):
            return False
        return "agent_id" in params and "command" in params

    def check_readiness(self) -> bool:
        return True

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        if not self.validate_input(params):
            raise ValueError("Invalid task parameters: agent_id and command required")

        task_id = f"task_{uuid.uuid4().hex[:8]}"
        return {
            "status": "queued",
            "task_id": task_id,
            "agent_id": params["agent_id"],
            "command": params["command"],
            "queued_at": time.time(),
        }


class InMemoryC2CleanupProvider:
    """In-memory test fake for daemon and resource cleanup operations."""

    def __init__(self, authenticator: Any = None) -> None:
        self.authenticator = authenticator

    def validate_input(self, params: dict[str, Any]) -> bool:
        if not isinstance(params, dict):
            return False
        return "resource_id" in params

    def check_readiness(self) -> bool:
        return True

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        if not self.validate_input(params):
            raise ValueError("Invalid cleanup parameters: resource_id required")

        cleanup_id = f"clean_{uuid.uuid4().hex[:8]}"
        return {
            "status": "cleaned",
            "cleanup_id": cleanup_id,
            "resource_id": params["resource_id"],
            "cleaned_at": time.time(),
        }


__all__ = [
    "InMemoryC2CleanupProvider",
    "InMemoryC2DeployProvider",
    "InMemoryC2EnrollProvider",
    "InMemoryC2TaskProvider",
]
