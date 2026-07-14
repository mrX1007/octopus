"""Execution boundary shared by the AI scheduler and tool runner."""

from core.execution.models import (
    CAP_ACTIVE_TOOL,
    CAP_DESTRUCTIVE_SHELL,
    CAP_DIRECT_BINARY,
    CAP_MANAGED_SHELL,
    CAP_PYTHON_REPL,
    CAP_REGISTERED_TOOL,
    ExecutionContext,
    ExecutionDecision,
    ToolInvocation,
    bind_execution_context,
    current_execution_context,
    redact_sensitive_command,
)
from core.execution.policy import ExecutionPolicy, validate_target
from core.execution.results import (
    DispatchResult,
    ExecutionResult,
    ExecutionStatus,
    adapt_execution_result,
)

__all__ = [
    "CAP_ACTIVE_TOOL",
    "CAP_DESTRUCTIVE_SHELL",
    "CAP_DIRECT_BINARY",
    "CAP_MANAGED_SHELL",
    "CAP_PYTHON_REPL",
    "CAP_REGISTERED_TOOL",
    "DispatchResult",
    "ExecutionContext",
    "ExecutionDecision",
    "ExecutionPolicy",
    "ExecutionResult",
    "ExecutionStatus",
    "ToolInvocation",
    "adapt_execution_result",
    "bind_execution_context",
    "current_execution_context",
    "redact_sensitive_command",
    "validate_target",
]
