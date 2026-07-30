"""Policy-bound public entry point for registered tool execution.

Provider functions and process helpers remain available from :mod:`core.tools`
for import compatibility.  New application code should enter through
``dispatch_registered_tool`` so that an explicit execution context and the
registered-tool policy boundary are always present.
"""

from __future__ import annotations

from core.execution import ExecutionContext
from core.tools.runner import run_tool_by_command


def dispatch_registered_tool(
    command: str,
    execution_context: ExecutionContext,
) -> str:
    """Dispatch one registered command through the canonical policy boundary.

    Unlike the legacy ``run_arbitrary_cmd`` compatibility name, this facade
    cannot select managed shell execution, a Python REPL, or an unregistered
    executable.  ``run_tool_by_command`` reparses and authorizes the command
    immediately before invoking the registered provider.
    """

    if not isinstance(execution_context, ExecutionContext):
        raise TypeError("execution_context must be an ExecutionContext")
    return run_tool_by_command(command, execution_context)


__all__ = ["dispatch_registered_tool"]
