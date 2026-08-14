"""C2 task provider adapter."""
from __future__ import annotations

import time
import uuid
from typing import Dict, Any


class C2TaskProvider:
    """Provider for agent task dispatch operations."""

    def __init__(self, task_catalog: Any = None) -> None:
        self.task_catalog = task_catalog

    def validate_input(self, params: Dict[str, Any]) -> bool:
        """Validate task dispatch input parameters."""
        if not isinstance(params, dict):
            return False
        return "agent_ref" in params and "operation_id" in params

    def check_readiness(self) -> bool:
        """Check provider readiness."""
        return True

    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch task to agent."""
        if not self.validate_input(params):
            raise ValueError("Invalid task parameters: agent_ref and operation_id required")

        task_id = f"task_{uuid.uuid4().hex[:8]}"
        return {
            "status": "dispatched",
            "task_id": task_id,
            "agent_ref": params["agent_ref"],
            "operation_id": params["operation_id"],
            "dispatched_at": time.time(),
        }

