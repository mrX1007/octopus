"""Typed execution request, context, and audit decision models."""

import hashlib
import hmac
import os
import re
import shlex
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Optional
from uuid import uuid4

from core.execution.cancellation import CancellationContext

CAP_REGISTERED_TOOL = "registered_tool"
CAP_DIRECT_BINARY = "direct_binary"
CAP_ACTIVE_TOOL = "active_tool"
CAP_MANAGED_SHELL = "managed_shell"
CAP_DESTRUCTIVE_SHELL = "destructive_shell"
CAP_PYTHON_REPL = "python_repl"

_AUDIT_HASH_KEY = os.urandom(32)
_POSITIONAL_SECRET_TOOLS = {
    "ad_enum", "adcs_review", "asrep_roast", "bloodhound_ingest",
    "dcsync", "gpo_review", "kerberoast", "killchain_cleanup",
    "killchain_exfil", "killchain_full", "killchain_lateral",
    "killchain_persist", "killchain_privesc", "pass_the_hash",
    "psexec", "ssh_exec", "ssh_inventory", "ssh_session", "wmiexec",
}

_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?ix)(?:^|[\s;&|])"
    r"(?:[A-Z][A-Z0-9_-]*_)?"
    r"(?:PASSWORD|PASSWD|PASS|PWD|TOKEN|SECRET|PSK|API[_-]?KEY|"
    r"AUTHORIZATION|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|PRIVATE_KEY)\s*="
)
_CREDENTIAL_FLAG_RE = re.compile(
    r"(?ix)(?:^|\s)--(?:password|passwd|pass|token|secret|api-key|"
    r"authorization|private-key)(?:-stdin)?(?:=|\s|$)"
)
_AUTHORIZATION_VALUE_RE = re.compile(
    r"(?i)\b(?:proxy-)?authorization\s*:\s*(?:basic|bearer)\s+\S+"
)
_URL_CREDENTIAL_RE = re.compile(
    r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@"
)
_SHELL_CREDENTIAL_CONSUMER_RE = re.compile(
    r"(?ix)(?:^|[\s;&|])(?:[^\s;&|]*/)?(?:sshpass|chpasswd)(?:\s|$)|"
    r"(?:^|[\s;&|])(?:[^\s;&|]*/)?sudo\s+-S(?:\s|$)|"
    r"(?:^|[\s;&|])(?:[^\s;&|]*/)?passwd\s+--stdin(?:\s|$)"
)
_OPAQUE_SECRET_REFERENCE_RE = re.compile(
    r"(?i)(?:credential|secret|credential-auth)://[A-Za-z0-9._~-]+"
)


def redact_sensitive_command(command: str) -> str:
    """Remove common named and positional secrets from audit metadata."""
    redacted = re.sub(
        r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key)=([^\s]+)",
        r"\1=[REDACTED]",
        command or "",
    )
    redacted = re.sub(
        r"(?i)(--(?:password|passwd|token|secret|api-key)\s+)([^\s]+)",
        r"\1[REDACTED]",
        redacted,
    )
    redacted = re.sub(
        r'''(?ix)(["']?(?:password|passwd|pwd|token|secret|api[_-]?key)["']?\s*:\s*["'])([^"']+)(["'])''',
        r"\1[REDACTED]\3",
        redacted,
    )
    try:
        parts = shlex.split(redacted, posix=True)
    except ValueError:
        return redacted
    if parts and parts[0].lower() in _POSITIONAL_SECRET_TOOLS and len(parts) >= 4:
        parts[3] = "[REDACTED]"
        return shlex.join(parts)
    return redacted


def contains_sensitive_command_material(
    command: str,
    *,
    argv: Optional[tuple[str, ...]] = None,
) -> bool:
    """Return whether free-form command text carries credential material.

    The managed-shell boundary accepts shell language, not typed provider
    inputs. Consequently it rejects plaintext credential forms and opaque
    secret handles alike. Credentials may only be revealed inside a
    provider-specific execution context.
    """

    raw = str(command or "")
    if not raw:
        return False
    if any(
        pattern.search(raw)
        for pattern in (
            _CREDENTIAL_ASSIGNMENT_RE,
            _CREDENTIAL_FLAG_RE,
            _AUTHORIZATION_VALUE_RE,
            _URL_CREDENTIAL_RE,
            _SHELL_CREDENTIAL_CONSUMER_RE,
            _OPAQUE_SECRET_REFERENCE_RE,
        )
    ):
        return True
    if "-----BEGIN" in raw.upper() and "PRIVATE KEY-----" in raw.upper():
        return True

    if argv is None:
        try:
            parts = shlex.split(raw, posix=True)
        except ValueError:
            return False
    else:
        parts = list(argv)
    lowered = [part.casefold() for part in parts]
    basenames = [part.rsplit("/", 1)[-1] for part in lowered]
    if "sshpass" in basenames:
        return True
    if basenames and basenames[0] in _POSITIONAL_SECRET_TOOLS and len(parts) >= 4:
        return True
    if basenames and basenames[0] == "curl":
        return any(part in {"-u", "--user"} or part.startswith("--user=") for part in lowered[1:])
    if basenames and basenames[0] == "docker" and len(lowered) > 1 and lowered[1] == "login":
        return any(
            part in {"-p", "--password", "--password-stdin"} or part.startswith("--password=")
            for part in lowered[2:]
        )
    if basenames and basenames[0] in {"mysql", "mariadb"}:
        return any(part == "-p" or (part.startswith("-p") and len(part) > 2) for part in lowered[1:])
    if basenames and basenames[0] in {"ssh", "scp", "sftp"}:
        return any(
            part in {"-i", "-oidentityfile"} or part.startswith("-oidentityfile=")
            for part in lowered[1:]
        )
    credential_flags = {
        "ldapsearch": {"-w", "-y"},
        "redis-cli": {"-a", "--pass"},
        "rpcclient": {"-u", "--user"},
        "smbclient": {"-u", "--user"},
        "sqlcmd": {"-p"},
    }
    if basenames and basenames[0] in credential_flags:
        return any(part in credential_flags[basenames[0]] for part in lowered[1:])
    return False


def _request_id() -> str:
    return uuid4().hex


@dataclass(frozen=True)
class ExecutionContext:
    """Authority and resource limits attached to one execution request.

    ``target_scope`` contains exact hosts/URLs, explicit wildcard domains, or
    CIDRs. An empty scope preserves legacy registered-tool calls while still
    enforcing typed dispatch and syntactic target validation. Pipeline calls
    always provide their current target and therefore enforce scope matching.
    """

    actor: str
    origin: str
    target_scope: tuple[str, ...] = ()
    capabilities: frozenset[str] = field(
        default_factory=lambda: frozenset({CAP_REGISTERED_TOOL, CAP_DIRECT_BINARY})
    )
    approved: bool = False
    approval_id: str = ""
    request_id: str = field(default_factory=_request_id)
    max_runtime_seconds: int = 300
    max_output_bytes: int = 1_000_000
    cancellation: CancellationContext = field(
        default_factory=CancellationContext,
        repr=False,
        compare=False,
    )

    @classmethod
    def automatic(
        cls,
        target_scope: tuple[str, ...] = (),
        *,
        actor: str = "ai",
        origin: str = "automation",
        max_runtime_seconds: int = 300,
        max_output_bytes: int = 1_000_000,
        cancellation: Optional[CancellationContext] = None,
    ) -> "ExecutionContext":
        return cls(
            actor=actor,
            origin=origin,
            target_scope=tuple(target_scope),
            capabilities=frozenset({CAP_REGISTERED_TOOL, CAP_DIRECT_BINARY}),
            max_runtime_seconds=max_runtime_seconds,
            max_output_bytes=max_output_bytes,
            cancellation=cancellation or CancellationContext(),
        )

    @classmethod
    def operator(
        cls,
        *,
        actor: str,
        approval_id: str,
        target_scope: tuple[str, ...] = (),
        allow_active_tools: bool = False,
        allow_shell: bool = False,
        allow_destructive_shell: bool = False,
        allow_python_repl: bool = False,
        max_runtime_seconds: int = 300,
        max_output_bytes: int = 1_000_000,
        cancellation: Optional[CancellationContext] = None,
    ) -> "ExecutionContext":
        capabilities = {CAP_REGISTERED_TOOL, CAP_DIRECT_BINARY}
        if allow_active_tools:
            capabilities.add(CAP_ACTIVE_TOOL)
        if allow_shell:
            capabilities.add(CAP_MANAGED_SHELL)
        if allow_destructive_shell:
            capabilities.add(CAP_DESTRUCTIVE_SHELL)
        if allow_python_repl:
            capabilities.add(CAP_PYTHON_REPL)
        return cls(
            actor=actor,
            origin="operator",
            target_scope=tuple(target_scope),
            capabilities=frozenset(capabilities),
            approved=bool(approval_id),
            approval_id=approval_id,
            max_runtime_seconds=max_runtime_seconds,
            max_output_bytes=max_output_bytes,
            cancellation=cancellation or CancellationContext(),
        )

    def has(self, capability: str) -> bool:
        return capability in self.capabilities


@dataclass(frozen=True)
class ToolInvocation:
    """A parsed command that can be authorized without executing it."""

    executable: str
    argv: tuple[str, ...]
    raw_command: str = field(repr=False, default="")
    registered_name: str = ""
    targets: tuple[str, ...] = ()
    uses_shell: bool = False

    def audit_dict(self) -> dict[str, Any]:
        """Return non-secret invocation metadata suitable for persistent logs."""
        return {
            "executable": self.executable,
            "registered_name": self.registered_name,
            "argument_count": max(0, len(self.argv) - 1),
            "targets": list(self.targets),
            "uses_shell": self.uses_shell,
            "command_audit_hmac": hmac.new(
                _AUDIT_HASH_KEY,
                self.raw_command.encode("utf-8", "replace"),
                hashlib.sha256,
            ).hexdigest(),
        }


@dataclass(frozen=True)
class ExecutionDecision:
    """An audit-friendly allow/deny result produced before every execution."""

    allowed: bool
    reason: str
    context: ExecutionContext
    invocation: Optional[ToolInvocation] = None

    @property
    def action(self) -> str:
        return "execute" if self.allowed else "deny"

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reason": self.reason,
            "request_id": self.context.request_id,
            "actor": self.context.actor,
            "origin": self.context.origin,
            "approval_id": self.context.approval_id,
            "target_scope": list(self.context.target_scope),
            "capabilities": sorted(self.context.capabilities),
            "limits": {
                "runtime_seconds": self.context.max_runtime_seconds,
                "output_bytes": self.context.max_output_bytes,
            },
            "invocation": self.invocation.audit_dict() if self.invocation else None,
        }


_CURRENT_EXECUTION_CONTEXT: ContextVar[Optional[ExecutionContext]] = ContextVar(
    "octopus_execution_context", default=None
)


def current_execution_context() -> ExecutionContext:
    context = _CURRENT_EXECUTION_CONTEXT.get()
    if context is not None:
        return context
    return ExecutionContext.automatic(actor="legacy_ai", origin="legacy_automation")


@contextmanager
def bind_execution_context(context: ExecutionContext) -> Iterator[ExecutionContext]:
    token = _CURRENT_EXECUTION_CONTEXT.set(context)
    try:
        yield context
    finally:
        _CURRENT_EXECUTION_CONTEXT.reset(token)
