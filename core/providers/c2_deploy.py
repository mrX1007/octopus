"""C2 deploy provider adapter."""

from __future__ import annotations

import time
import uuid
from typing import Any

from core.c2.deployment import C2DeploymentService


class C2DeployProvider:
    """Provider for deploying agent binaries to target hosts."""

    def __init__(self, deployment_service: C2DeploymentService | None = None) -> None:
        self.deployment_service = deployment_service or C2DeploymentService()

    def validate_input(self, params: dict[str, Any]) -> bool:
        """Validate deployment request parameters."""
        if not isinstance(params, dict):
            return False
        return "target_os" in params and "backend_name" in params

    def check_readiness(self) -> bool:
        """Check provider readiness."""
        return True

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        """Execute agent deployment."""
        if not self.validate_input(params):
            raise ValueError("Invalid deploy parameters: target_os and backend_name required")

        attempt_id = f"att_{uuid.uuid4().hex[:8]}"
        res = self.deployment_service.deploy(
            attempt_id=attempt_id,
            backend_name=params.get("backend_name", "local"),
            binary_path=params.get("binary_path", "/tmp/agent"),
            target_dir=params.get("target_dir", "/tmp/target"),
            config=params.get("config"),
        )
        return {
            "status": "deployed",
            "attempt_id": attempt_id,
            "deployment_result": res,
            "deployed_at": time.time(),
        }
