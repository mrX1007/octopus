"""Fail-closed execution policy used at scheduling and dispatch boundaries."""

import ipaddress
import logging
import re
import shlex
from collections.abc import Iterable, Sequence
from typing import Optional
from urllib.parse import urlparse

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
)

logger = logging.getLogger("octopus.execution")

_ALLOWED_URL_SCHEMES = {"http", "https", "ssh", "ftp", "smb", "tcp", "tls"}
_HOST_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)
_SHELL_OPERATOR_RE = re.compile(r"(?:^|\s)(?:\|\||&&|[|;<>]|\d+>)(?:\s|$)")
_COMMAND_SUBSTITUTION_RE = re.compile(r"\$\(|`")
_DESTRUCTIVE_SHELL_RE = re.compile(
    r"(?:^|[;&|()\s])(?:sudo\s+)?(?:[^\s;&|()]+/)?"
    r"(?:dd|init|mkfs(?:\.[a-z0-9]+)?|mv|poweroff|reboot|rm|shutdown)"
    r"(?=$|[;&|()\s])",
    re.IGNORECASE,
)

# Automatic execution has one direct binary compatibility exception. All
# normal tools must be represented by the decorator registry.
_AUTOMATIC_DIRECT_BINARIES = {"rustscan"}

_MANUAL_APPROVAL_TOOLS = {
    "asrep_roast",
    "bruteforce",
    "build_go_implant",
    "build_ps_stager",
    "build_python_implant",
    "dcsync",
    "deploy_c2_beacon",
    "dns_c2_listener",
    "jmx2rce_cleanup",
    "jmx2rce_rce",
    "jmx2rce_read",
    "kerberoast",
    "killchain_cleanup",
    "killchain_exfil",
    "killchain_exploit",
    "killchain_full",
    "killchain_lateral",
    "killchain_persist",
    "killchain_privesc",
    "msf_run",
    "pass_the_hash",
    "port_forward",
    "psexec",
    "socks_proxy",
    "ssh_exec",
    "ssh_session",
    "web_login_brute",
    "wmiexec",
}

_NON_NETWORK_TARGET_TOOLS = {
    "burp_import",
    "checkov_scan",
    "gitleaks_scan",
    "jwt_analyze",
    "prowler_scan",
    "scoutsuite_scan",
    "semgrep_scan",
    "session_profile_import",
    "trivy_scan",
    "trufflehog_scan",
    "zap_import",
}

class InvalidInvocation(ValueError):
    """Raised when a command cannot be represented as a typed invocation."""


def _clean_host(host: str) -> str:
    try:
        return host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("invalid_idn") from exc


def _split_target(value: str) -> tuple[str, str, Optional[int]]:
    """Return target kind, normalized host/network, and optional port."""
    raw = (value or "").strip().strip("'\"")
    if not raw or len(raw) > 2048 or any(ord(char) < 32 for char in raw):
        raise ValueError("empty_or_control_character")
    if any(char.isspace() for char in raw):
        raise ValueError("embedded_whitespace")

    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
            return "network", str(network), None
        except ValueError:
            pass

    try:
        address = ipaddress.ip_address(raw.strip("[]"))
        return "host", str(address), None
    except ValueError:
        pass

    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    if parsed.scheme and parsed.scheme.lower() not in _ALLOWED_URL_SCHEMES:
        raise ValueError("unsupported_scheme")
    if parsed.username or parsed.password:
        raise ValueError("userinfo_not_allowed")
    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid_port") from exc
    if not host:
        raise ValueError("missing_host")
    host = _clean_host(host)
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        if host != "localhost" and not _HOST_RE.fullmatch(host):
            raise ValueError("invalid_hostname") from None
    return "host", host, port


def validate_target(value: str) -> bool:
    """Return whether a network target is syntactically safe and unambiguous."""
    try:
        _split_target(value)
        return True
    except ValueError:
        return False


def _scope_matches(target: str, scope: str) -> bool:
    target_kind, target_value, target_port = _split_target(target)
    raw_scope = (scope or "").strip()
    if not raw_scope:
        return False

    wildcard = raw_scope.startswith("*.")
    if wildcard:
        suffix = _clean_host(raw_scope[2:])
        return (
            target_kind == "host"
            and target_value.endswith(f".{suffix}")
            and target_value != suffix
        )

    scope_kind, scope_value, scope_port = _split_target(raw_scope)
    if scope_kind == "network":
        if target_kind != "host":
            return target_value == scope_value
        try:
            return ipaddress.ip_address(target_value) in ipaddress.ip_network(scope_value)
        except ValueError:
            return False
    if target_kind == "network":
        return False
    if target_value != scope_value:
        return False
    return scope_port is None or target_port == scope_port


def _looks_like_network_target(token: str) -> bool:
    value = (token or "").strip().strip("'\"")
    if not value or value.startswith("-"):
        return False
    if "://" in value or value == "localhost":
        return True
    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False
    host_part = value
    if value.count(":") == 1:
        host_part = value.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(host_part.strip("[]"))
        return True
    except ValueError:
        pass
    return "." in host_part and bool(re.search(r"[a-z]", host_part, re.IGNORECASE))


def extract_network_targets(argv: Iterable[str]) -> tuple[str, ...]:
    targets: list[str] = []
    for token in argv:
        candidate = str(token).rstrip(",)")
        if not _looks_like_network_target(candidate):
            continue
        if validate_target(candidate) and candidate not in targets:
            targets.append(candidate)
    return tuple(targets)


def _has_shell_syntax(command: str) -> bool:
    return bool(
        "\n" in command
        or "\r" in command
        or _SHELL_OPERATOR_RE.search(command)
        or _COMMAND_SUBSTITUTION_RE.search(command)
    )


def parse_invocation(command: str, *, allow_executable_path: bool = False) -> ToolInvocation:
    raw = (command or "").strip()
    if not raw:
        raise InvalidInvocation("empty_command")
    if len(raw) > 65_536:
        raise InvalidInvocation("command_too_long")
    if "\x00" in raw:
        raise InvalidInvocation("nul_byte")
    try:
        argv = tuple(shlex.split(raw, posix=True))
    except ValueError as exc:
        raise InvalidInvocation("invalid_quoting") from exc
    if not argv:
        raise InvalidInvocation("empty_command")
    executable = argv[0].lower()
    if ("/" in executable and not allow_executable_path) or executable in {".", ".."}:
        raise InvalidInvocation("executable_path_not_allowed")
    return ToolInvocation(
        executable=executable,
        argv=argv,
        raw_command=raw,
        targets=extract_network_targets(argv[1:]),
        uses_shell=_has_shell_syntax(raw),
    )


class ExecutionPolicy:
    """Authorize a typed invocation against capability and target scope."""

    def _decision(
        self,
        allowed: bool,
        reason: str,
        context: ExecutionContext,
        invocation: Optional[ToolInvocation] = None,
    ) -> ExecutionDecision:
        decision = ExecutionDecision(allowed, reason, context, invocation)
        logger.info("execution_decision=%s", decision.to_dict())
        return decision

    def _limits_valid(self, context: ExecutionContext) -> bool:
        return (
            1 <= int(context.max_runtime_seconds) <= 86_400
            and 1_024 <= int(context.max_output_bytes) <= 100_000_000
        )

    def _targets_allowed(
        self,
        targets: Sequence[str],
        context: ExecutionContext,
    ) -> tuple[bool, str]:
        for target in targets:
            if not validate_target(target):
                return False, f"invalid_target:{target[:120]}"
            scope_match = False
            for scope in context.target_scope:
                try:
                    if _scope_matches(target, scope):
                        scope_match = True
                        break
                except ValueError:
                    continue
            if context.target_scope and not scope_match:
                return False, f"target_out_of_scope:{target[:120]}"
        return True, "target_authorized"

    def authorize_registered(
        self,
        invocation: ToolInvocation,
        context: ExecutionContext,
    ) -> ExecutionDecision:
        if context.cancellation.cancelled:
            return self._decision(False, "execution_cancelled", context, invocation)
        if not self._limits_valid(context):
            return self._decision(False, "invalid_resource_limits", context, invocation)
        if not context.has(CAP_REGISTERED_TOOL):
            return self._decision(False, "missing_capability:registered_tool", context, invocation)

        name = invocation.registered_name or invocation.executable
        requires_approval = name in _MANUAL_APPROVAL_TOOLS
        if name == "cpanel_exploit":
            action = invocation.argv[2].lower() if len(invocation.argv) > 2 else "cmd"
            requires_approval = action not in {"scan", "check"}
        if name == "plugin":
            action = invocation.argv[3].lower() if len(invocation.argv) > 3 else "scan"
            requires_approval = action not in {"list", "ls", "scan", "check", "summary"}
        if requires_approval and (
            not context.has(CAP_ACTIVE_TOOL)
            or not context.approved
            or not context.approval_id
        ):
            return self._decision(False, "active_tool_requires_approval", context, invocation)

        targets = () if name in _NON_NETWORK_TARGET_TOOLS else invocation.targets
        allowed, reason = self._targets_allowed(targets, context)
        if not allowed:
            return self._decision(False, reason, context, invocation)
        return self._decision(True, "registered_tool_authorized", context, invocation)

    def authorize_direct(
        self,
        invocation: ToolInvocation,
        context: ExecutionContext,
    ) -> ExecutionDecision:
        if context.cancellation.cancelled:
            return self._decision(False, "execution_cancelled", context, invocation)
        if not self._limits_valid(context):
            return self._decision(False, "invalid_resource_limits", context, invocation)
        if not context.has(CAP_DIRECT_BINARY):
            return self._decision(False, "missing_capability:direct_binary", context, invocation)
        if invocation.executable not in _AUTOMATIC_DIRECT_BINARIES:
            return self._decision(False, f"unknown_tool:{invocation.executable}", context, invocation)
        allowed, reason = self._targets_allowed(invocation.targets, context)
        if not allowed:
            return self._decision(False, reason, context, invocation)
        return self._decision(True, "allowlisted_binary_authorized", context, invocation)

    def authorize_shell(
        self,
        command: str,
        context: ExecutionContext,
    ) -> ExecutionDecision:
        try:
            invocation = parse_invocation(command, allow_executable_path=True)
        except InvalidInvocation as exc:
            return self._decision(False, str(exc), context)
        try:
            lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
            lexer.whitespace_split = True
            lexer.commenters = ""
            shell_targets = extract_network_targets(list(lexer))
        except ValueError:
            shell_targets = invocation.targets
        invocation = ToolInvocation(
            executable=invocation.executable,
            argv=invocation.argv,
            raw_command=invocation.raw_command,
            targets=shell_targets,
            uses_shell=True,
        )
        if context.cancellation.cancelled:
            return self._decision(False, "execution_cancelled", context, invocation)
        if not self._limits_valid(context):
            return self._decision(False, "invalid_resource_limits", context, invocation)
        if context.origin not in {"operator", "interactive_cli"}:
            return self._decision(False, "shell_origin_not_interactive", context, invocation)
        if not context.has(CAP_MANAGED_SHELL):
            return self._decision(False, "missing_capability:managed_shell", context, invocation)
        if not context.approved or not context.approval_id:
            return self._decision(False, "shell_requires_approval", context, invocation)
        if _DESTRUCTIVE_SHELL_RE.search(command) and not context.has(CAP_DESTRUCTIVE_SHELL):
            return self._decision(False, "destructive_shell_requires_capability", context, invocation)
        allowed, reason = self._targets_allowed(invocation.targets, context)
        if not allowed:
            return self._decision(False, reason, context, invocation)
        return self._decision(True, "managed_shell_authorized", context, invocation)

    def authorize_python_repl(
        self,
        code: str,
        context: ExecutionContext,
    ) -> ExecutionDecision:
        invocation = ToolInvocation(
            executable="python",
            argv=("python", "-I", "-c", code),
            raw_command=code,
        )
        if context.cancellation.cancelled:
            return self._decision(False, "execution_cancelled", context, invocation)
        if not self._limits_valid(context):
            return self._decision(False, "invalid_resource_limits", context, invocation)
        if context.origin not in {"operator", "interactive_cli"}:
            return self._decision(False, "python_repl_origin_not_interactive", context, invocation)
        if not context.has(CAP_PYTHON_REPL):
            return self._decision(False, "missing_capability:python_repl", context, invocation)
        if not context.approved or not context.approval_id:
            return self._decision(False, "python_repl_requires_approval", context, invocation)
        return self._decision(True, "python_repl_authorized", context, invocation)

    def authorize_command(
        self,
        command: str,
        context: ExecutionContext,
    ) -> ExecutionDecision:
        if context.cancellation.cancelled:
            return self._decision(False, "execution_cancelled", context)
        try:
            invocation = parse_invocation(command)
        except InvalidInvocation as exc:
            return self._decision(False, str(exc), context)

        # Importing the package registers all built-in @tool functions. Keep it
        # lazy to avoid an execution-policy -> runner import cycle.
        try:
            import core.tools  # noqa: F401
            from core.tools.registry import get_tool

            alias_tokens = 1
            tool_def = get_tool(invocation.executable)
            if not tool_def and len(invocation.argv) >= 2:
                tool_def = get_tool(f"{invocation.argv[0]} {invocation.argv[1]}")
                if tool_def:
                    alias_tokens = 2
            if tool_def:
                candidates = extract_network_targets(invocation.argv[alias_tokens:])
                # The first network-like argument is the declared target for
                # registered commands; later values can be evidence/context.
                targets = candidates[:1]
                registered = ToolInvocation(
                    executable=invocation.executable,
                    argv=invocation.argv,
                    raw_command=invocation.raw_command,
                    registered_name=tool_def.name,
                    targets=targets,
                )
                return self.authorize_registered(registered, context)
        except ImportError:
            pass

        # Shell-looking text carried as an argument to a registered function is
        # inert because the dispatcher never sends it to a shell. Only unknown
        # commands reach the managed-shell authorization branch.
        if invocation.uses_shell:
            return self.authorize_shell(command, context)

        return self.authorize_direct(invocation, context)
