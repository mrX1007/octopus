"""Deployment orchestration."""

from __future__ import annotations

import time
from typing import Any

from core.c2.deployment_backends import (
    C2DeploymentBackend,
    LocalProcessDeploymentBackend,
    SSHDeploymentBackend,
)


class C2DeploymentService:
    """Orchestrates agent deployments using backend drivers."""

    def __init__(self) -> None:
        self._backends: dict[str, C2DeploymentBackend] = {
            "local": LocalProcessDeploymentBackend(),
            "ssh": SSHDeploymentBackend(),
        }
        self._active_deployments: dict[str, dict[str, Any]] = {}

    def register_backend(self, name: str, backend: C2DeploymentBackend) -> None:
        """Register a new deployment backend."""
        self._backends[name] = backend

    def get_backend(self, name: str) -> C2DeploymentBackend:
        """Retrieve backend by name."""
        backend = self._backends.get(name)
        if backend is None:
            raise KeyError(f"Deployment backend '{name}' not registered")
        return backend

    def deploy(
        self,
        attempt_id: str,
        backend_name: str,
        binary_path: str,
        target_dir: str,
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Deploy agent using specified backend."""
        backend = self.get_backend(backend_name)
        cfg = config or {}
        result = backend.deploy(
            attempt_id=attempt_id,
            binary_path=binary_path,
            target_dir=target_dir,
            config=cfg,
        )
        self._active_deployments[attempt_id] = {
            "backend_name": backend_name,
            "target_identifier": result.get("target_identifier"),
            "result": result,
            "deployed_at": time.time(),
        }
        return result

    def probe(self, attempt_id: str) -> bool:
        """Probe deployment status for an attempt."""
        dep = self._active_deployments.get(attempt_id)
        if dep is None:
            return False
        backend = self.get_backend(dep["backend_name"])
        return backend.probe(dep["target_identifier"])

    def terminate(self, attempt_id: str) -> bool:
        """Terminate a deployment."""
        dep = self._active_deployments.get(attempt_id)
        if dep is None:
            return False
        backend = self.get_backend(dep["backend_name"])
        success = backend.terminate(dep["target_identifier"])
        if success:
            del self._active_deployments[attempt_id]
        return success
