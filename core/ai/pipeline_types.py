"""Typing seam shared by the stateless pipeline mixins.

The concrete :class:`core.ai.pipeline.AIPipeline` supplies the collaborators
and mutable scan state at composition time.  ``__getattr__`` models that
intentional dynamic composition for static analysis; at runtime a missing
attribute still fails normally instead of being synthesized.
"""

from typing import Any, Optional


class PipelineMixinBase:
    _active_retry_command_keys: set[str]
    _active_task_attempt_id: Optional[str]
    _active_task_id: Optional[str]
    _last_decision_state: str
    _state_replan_count: int
    _state_replan_signatures: set[str]
    consecutive_llm_failures: int
    executed_fact_action_commands: set[str]
    service_intelligence_evidence_seen: set[str]
    tools_run_count: int

    def __getattr__(self, name: str) -> Any:
        raise AttributeError(name)


__all__ = ["PipelineMixinBase"]
