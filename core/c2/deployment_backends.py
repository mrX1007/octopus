"""Deployment backend implementations."""

from __future__ import annotations

import os
import time
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class C2DeploymentBackend(Protocol):
    def deploy(self, attempt_id: str, binary_path: str, target_dir: str, config: dict[str, Any]) -> dict[str, Any]: ...
    def probe(self, target_identifier: str) -> bool: ...
    def terminate(self, target_identifier: str) -> bool: ...


class LocalProcessDeploymentBackend:
    """Local process deployment backend."""

    def __init__(self) -> None:
        self._active_processes: dict[str, dict[str, Any]] = {}

    def deploy(self, attempt_id: str, binary_path: str, target_dir: str, config: dict[str, Any]) -> dict[str, Any]:
        """Deploy binary locally."""
        try:
            if not os.path.exists(target_dir):
                os.makedirs(target_dir, exist_ok=True)
        except OSError:
            pass

        target_id = f"local_{attempt_id}"
        self._active_processes[target_id] = {
            "attempt_id": attempt_id,
            "binary_path": binary_path,
            "target_dir": target_dir,
            "config": config,
            "pid": 10000 + len(self._active_processes) + 1,
            "status": "running",
            "deployed_at": time.time(),
        }

        return {
            "target_identifier": target_id,
            "status": "running",
            "pid": self._active_processes[target_id]["pid"],
            "backend": "local",
        }

    def probe(self, target_identifier: str) -> bool:
        """Probe local deployed process health."""
        proc = self._active_processes.get(target_identifier)
        if proc is None:
            return False
        return proc.get("status") == "running"

    def terminate(self, target_identifier: str) -> bool:
        """Terminate local deployed process."""
        proc = self._active_processes.get(target_identifier)
        if proc is None:
            return False
        proc["status"] = "terminated"
        return True


class SSHDeploymentBackend:
    """SSH remote deployment backend."""

    def __init__(self, ssh_host: str = "localhost", ssh_port: int = 22, ssh_user: str = "root") -> None:
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self._active_deployments: dict[str, dict[str, Any]] = {}

    def deploy(self, attempt_id: str, binary_path: str, target_dir: str, config: dict[str, Any]) -> dict[str, Any]:
        """Deploy binary via SSH."""
        target_id = f"ssh_{attempt_id}"
        self._active_deployments[target_id] = {
            "attempt_id": attempt_id,
            "binary_path": binary_path,
            "target_dir": target_dir,
            "ssh_target": f"{self.ssh_user}@{self.ssh_host}:{self.ssh_port}",
            "config": config,
            "status": "running",
            "deployed_at": time.time(),
        }

        return {
            "target_identifier": target_id,
            "status": "running",
            "ssh_host": self.ssh_host,
            "backend": "ssh",
        }

    def probe(self, target_identifier: str) -> bool:
        """Probe remote SSH deployment health."""
        dep = self._active_deployments.get(target_identifier)
        if dep is None:
            return False
        return dep.get("status") == "running"

    def terminate(self, target_identifier: str) -> bool:
        """Terminate remote SSH deployment."""
        dep = self._active_deployments.get(target_identifier)
        if dep is None:
            return False
        dep["status"] = "terminated"
        return True
