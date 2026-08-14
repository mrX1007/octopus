"""C2 enrollment provider adapter."""

from __future__ import annotations

import time
import uuid
from typing import Any


class C2EnrollProvider:
    """Provider for agent enrollment operations."""

    def __init__(self, authenticator: Any = None) -> None:
        self.authenticator = authenticator

    def validate_input(self, params: dict[str, Any]) -> bool:
        """Validate enrollment request input parameters."""
        if not isinstance(params, dict):
            return False
        return "mission_id" in params and "agent_ref" in params

    def check_readiness(self) -> bool:
        """Check if provider is ready to enroll agents."""
        return True

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        """Execute agent enrollment."""
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
