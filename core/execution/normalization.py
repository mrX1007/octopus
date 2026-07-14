"""Pure compatibility normalization used by the execution pipeline."""

from __future__ import annotations

from typing import Any

from core.execution.results import ExecutionResult, ExecutionStatus


def output_text(output: Any) -> str:
    """Project an execution value to the pipeline's legacy combined text."""
    stdout = getattr(output, "stdout", None)
    stderr = getattr(output, "stderr", "")
    if stdout is not None:
        parts = [str(stdout)]
        if stderr:
            parts.append(str(stderr))
        return "\n".join(part for part in parts if part)
    return str(output)


def command_tool_name(cmd: str) -> str:
    """Return the lower-case first command token or the legacy fallback."""
    return (
        (cmd or "").strip().split(None, 1)[0].lower()
        if (cmd or "").strip()
        else "tool"
    )


def normalized_check_status(cmd: str, status: str, output_str: str = "") -> str:
    """Normalize legacy check output markers without changing status strings."""
    text = (output_str or "").lower()
    if command_tool_name(cmd) == "msf_check" and (
        "success:" in text
        or "appears to be vulnerable" in text
        or "is vulnerable" in text
    ):
        return "completed"
    if "msf login check skipped" in text:
        return "skipped"
    if "[timeout]" in text or "killed after" in text or "timed out after" in text:
        return "timeout"
    if "[partial output" in text and status == "completed_empty":
        return "partial"
    return status


def command_check_status(
    cmd: str,
    output_str: str,
    failed: bool,
    parsed_output_facts: int,
    execution_result: ExecutionResult | None = None,
) -> str:
    """Project canonical execution status onto the legacy check-status contract."""
    if execution_result is not None:
        status_map = {
            ExecutionStatus.FAILED: "failed",
            ExecutionStatus.TIMEOUT: "timeout",
            ExecutionStatus.BLOCKED: "blocked",
            ExecutionStatus.PARTIAL: "partial",
            ExecutionStatus.UNAVAILABLE: "unavailable",
            ExecutionStatus.CANCELLED: "cancelled",
        }
        if execution_result.status in status_map:
            return status_map[execution_result.status]
    return normalized_check_status(
        cmd,
        "failed" if failed else ("completed" if parsed_output_facts else "completed_empty"),
        output_str,
    )


def command_failed(output: Any, output_str: str) -> bool:
    """Classify canonical and legacy command failures with existing precedence."""
    exit_code = getattr(output, "exit_code", 0)
    if isinstance(exit_code, int) and exit_code != 0:
        return True
    if isinstance(output, ExecutionResult):
        if output.status in {
            ExecutionStatus.FAILED,
            ExecutionStatus.TIMEOUT,
            ExecutionStatus.UNAVAILABLE,
            ExecutionStatus.CANCELLED,
        }:
            return True
        if output.status is ExecutionStatus.BLOCKED:
            return False

    text = (output_str or "").lower()
    success_markers = (
        "[+]",
        "open",
        "connected",
        "login_success",
        "uid=0",
        "root access",
        "confirmed",
        "cve-",
        "vulnerable",
        "exfil",
        "persistence",
        "cleanup",
    )
    if any(marker in text for marker in success_markers):
        return False

    failure_markers = (
        "[!] tool not found",
        "[!] error",
        "traceback",
        "timed out",
        "returned no output",
        "requires credentials",
        "connection failed",
        "permission denied",
        "unknown tool",
        "missing dependency",
        "no such file or directory",
        "psych/syntax_error",
        "bundler/errors.rb",
        "rubygems/errors.rb",
    )
    return any(marker in text for marker in failure_markers)


__all__ = [
    "command_check_status",
    "command_failed",
    "command_tool_name",
    "normalized_check_status",
    "output_text",
]
