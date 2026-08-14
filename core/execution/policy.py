"""Fail-closed execution policy used at scheduling and dispatch boundaries."""

from __future__ import annotations

import inspect
import ipaddress
import logging
import re
import shlex
from collections.abc import Iterable, Sequence
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
    contains_sensitive_command_material,
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
_SHELL_VARIABLE_RE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^}\r\n]+\})")
_DESTRUCTIVE_SHELL_RE = re.compile(
    r"(?:^|[;&|()\s])(?:sudo\s+)?(?:[^\s;&|()]+/)?"
    r"(?:dd|init|mkfs(?:\.[a-z0-9]+)?|mv|poweroff|reboot|rm|shutdown)"
    r"(?=$|[;&|()\s])",
    re.IGNORECASE,
)

_MANUAL_APPROVAL_TOOLS = {
    "ad_dcom_exec",
    "ad_dump_lsass",
    "ad_pass_the_ticket",
    "ad_remote_execution",
    "ad_sam_dump",
    "ad_smbexec",
    "ad_winrm_exec",
    "asrep_roast",
    "bruteforce",
    "build_go_implant",
    "build_ps_stager",
    "build_python_implant",
    "crack_hashes",
    "dcsync",
    "deploy_c2_beacon",
    "c2_channel_create",
    "c2_cleanup",
    "c2_deploy",
    "c2_enroll",
    "c2_task",
    "dns_c2_channel",
    "dns_c2_listener",
    "jmx2rce_cleanup",
    "jmx2rce_rce",
    "jmx2rce_read",
    "kerberoast",
    "kerberos_crack_tickets",
    "kerberos_extract_tickets",
    "killchain_cleanup",
    "killchain_exfil",
    "killchain_exploit",
    "killchain_full",
    "killchain_lateral",
    "killchain_persist",
    "killchain_privesc",
    "msf_run",
    "pass_the_hash",
    "payload_keying",
    "port_forward",
    "pivot_proxy_scan",
    "pivot_remote_forward",
    "pivot_ssh_chain",
    "psexec",
    "socks_proxy",
    "ssh_exec",
    "ssh_session",
    "sqlmap",
    "web_login_brute",
    "wmiexec",
}

_NON_NETWORK_TARGET_TOOLS = {
    "burp_import",
    "checkov_scan",
    "gitleaks_scan",
    "jwt_analyze",
    "openapi_import",
    "prowler_scan",
    "scoutsuite_scan",
    "semgrep_scan",
    "session_profile_import",
    "trivy_scan",
    "trufflehog_scan",
    "zap_import",
}

_NETWORK_PARAMETER_NAMES = frozenset({"callback_host", "target", "target_ip", "host", "url", "remote_host"})

# Registered callables whose network endpoint is intentionally named after the
# produced/query artifact rather than ``target``.  This is a closed, code-owned
# extension: an inspectable callable is never allowed to infer a new endpoint
# parameter from arbitrary command text.
_TOOL_NETWORK_PARAMETER_NAMES = {
    "build_go_implant": frozenset({"c2_url"}),
    "build_ps_stager": frozenset({"c2_url"}),
    "build_python_implant": frozenset({"c2_url"}),
    "shodan": frozenset({"query"}),
}
_OPTIONAL_NETWORK_TARGET_TOOLS = frozenset(
    {
        "build_go_implant",
        "build_ps_stager",
        "build_python_implant",
        # These manual-gated identities can operate on local opaque artifacts,
        # but an explicitly supplied target remains bound to operator scope.
        "c2_enroll",
        "kerberos_crack_tickets",
        "payload_keying",
        # This provider accepts either a local artifact (no network scope) or
        # an HTTP(S) artifact URL (normal target-scope enforcement).
        "openapi_import",
    }
)

_NMAP_INDIRECT_TARGET_FLAGS = frozenset(
    {
        "-b",
        "-D",
        "-iL",
        "-iR",
        "-S",
        "--dns-servers",
        "--proxies",
        "--resume",
        "--script-args-file",
    }
)
_MSF_UNBOUND_ENDPOINT_OPTIONS = frozenset(
    {
        "CHOST",
        "LHOST",
        "PROXIES",
        "SESSION",
        "SRVHOST",
        "VHOST",
    }
)
_REMOTE_COMMAND_ARGUMENT = {
    "jmx2rce_rce": 1,
    "psexec": 4,
    "ssh_exec": 3,
    "wmiexec": 4,
}
_REMOTE_SAFE_COMMANDS = {
    "psexec": frozenset({"whoami", "hostname", "ipconfig", "whoami && hostname && ipconfig"}),
    "wmiexec": frozenset({"whoami", "hostname", "ipconfig", "whoami && hostname && ipconfig"}),
    "ssh_exec": frozenset(
        {
            "hostname",
            "id",
            "ip -o addr show",
            "ip -o addr show || ip addr show",
            "ip addr",
            "ip addr show",
            "netstat -tulpen",
            "ss -tulpen",
            "ss -tulpen || netstat -tulpen",
            "sudo -n -l",
            "uname",
            "uname -a",
            "uname -r",
            "whoami",
        }
    ),
}
_NETWORK_CLIENT_COMMANDS = frozenset(
    {
        "curl",
        "dig",
        "ftp",
        "nc",
        "ncat",
        "netcat",
        "nslookup",
        "ping",
        "scp",
        "sftp",
        "ssh",
        "telnet",
        "wget",
    }
)


def _normalize_remote_command(command: str) -> str:
    normalized = re.sub(r"\s+", " ", str(command or "").strip())
    normalized = re.sub(r"\s+2>/dev/null", "", normalized)
    normalized = re.sub(r"\s+\|\|\s+true$", "", normalized)
    return normalized.strip()


def remote_command_is_code_owned(tool_name: str, command: str) -> bool:
    """Return whether one remote-execution payload is an exact safe operation."""

    name = str(tool_name or "").strip().casefold()
    normalized = _normalize_remote_command(command)
    if name == "jmx2rce_rce":
        return not normalized
    return normalized in _REMOTE_SAFE_COMMANDS.get(name, frozenset())


def _network_parameter_names(tool_def: object) -> frozenset[str]:
    name = str(getattr(tool_def, "name", "") or "").strip().casefold()
    return _NETWORK_PARAMETER_NAMES | _TOOL_NETWORK_PARAMETER_NAMES.get(
        name,
        frozenset(),
    )


def _network_parameter_positions(tool_def: object) -> tuple[int, ...]:
    """Return positional indexes explicitly declared as network parameters.

    This deliberately uses the registered callable contract instead of guessing
    that every hostname-looking command token is a target.  For example,
    ``bruteforce ssh intranet`` binds ``ssh`` to ``service`` and ``intranet`` to
    ``target`` even though both are syntactically valid single-label hostnames.
    """

    func = getattr(tool_def, "func", None)
    if not callable(func):
        return ()
    try:
        parameters = inspect.signature(func).parameters.values()
    except (TypeError, ValueError):
        return ()

    network_names = _network_parameter_names(tool_def)
    positions: list[int] = []
    positional_index = 0
    for parameter in parameters:
        if parameter.kind not in {
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        }:
            continue
        if parameter.name in network_names:
            positions.append(positional_index)
        positional_index += 1
    return tuple(positions)


def _registered_tool_uses_network_scope(tool_def: object) -> bool:
    """Return whether a ToolDef requires an explicitly scoped network target."""

    name = str(getattr(tool_def, "name", "") or "").strip().casefold()
    if not bool(getattr(tool_def, "needs_target", True)) or name in _NON_NETWORK_TARGET_TOOLS:
        return False
    positions = _network_parameter_positions(tool_def)
    if positions:
        return True
    # An uninspectable target-requiring provider is ambiguous and therefore
    # network-scoped by default.  Inspectable query/file providers without one
    # of the typed network parameter names remain outside network scope.
    func = getattr(tool_def, "func", None)
    if not callable(func):
        return True
    try:
        inspect.signature(func)
    except (TypeError, ValueError):
        return True
    return False


def registered_tool_uses_network_scope(name: str) -> bool:
    """Resolve whether a registered identity consumes a network scope target.

    Unknown identities return ``True`` so callers that are preparing a final
    authorization cannot turn registry ambiguity into a scope bypass.
    """

    try:
        import core.tools  # noqa: F401
        from core.tools.registry import get_tool
    except ImportError:
        return True
    tool_def = get_tool(name)
    return True if tool_def is None else _registered_tool_uses_network_scope(tool_def)


def registered_tool_network_parameter_names(name: str) -> frozenset[str]:
    """Return the explicit network-bearing parameters for one tool identity."""

    try:
        import core.tools  # noqa: F401
        from core.tools.registry import get_tool
    except ImportError:
        return frozenset()
    tool_def = get_tool(name)
    if tool_def is None:
        return frozenset()
    canonical = str(getattr(tool_def, "name", "") or "").strip().casefold()
    if not _registered_tool_uses_network_scope(tool_def) and canonical not in _OPTIONAL_NETWORK_TARGET_TOOLS:
        return frozenset()
    return _network_parameter_names(tool_def)


def _declared_network_targets(
    tool_def: object,
    argv: Sequence[str],
    alias_tokens: int,
) -> tuple[str, ...]:
    """Bind single-label targets through the callable's positional contract."""

    name = str(getattr(tool_def, "name", "") or "").strip().casefold()
    if not _registered_tool_uses_network_scope(tool_def) and name not in _OPTIONAL_NETWORK_TARGET_TOOLS:
        return ()
    arguments = tuple(str(item) for item in argv[alias_tokens:])
    special = _special_registered_targets(
        name,
        arguments,
    )
    if special is not None:
        return tuple(dict.fromkeys(candidate for candidate in special if validate_target(candidate)))
    targets: list[str] = []
    for position in _network_parameter_positions(tool_def):
        if position >= len(arguments):
            continue
        candidate = arguments[position].strip()
        if validate_target(candidate) and candidate not in targets:
            targets.append(candidate)
    return tuple(targets)


def _special_registered_targets(
    name: str,
    arguments: Sequence[str],
) -> tuple[str, ...] | None:
    """Mirror flag-aware target binding performed by the registered runner."""

    args = tuple(str(item) for item in arguments)
    if name == "nmap":
        for index, argument in enumerate(args):
            option = argument.split("=", 1)[0]
            if option in _NMAP_INDIRECT_TARGET_FLAGS or any(
                argument.startswith(prefix)
                for prefix in (
                    "-D",
                    "-S",
                    "-b",
                    "-iL",
                    "-iR",
                    "--dns-servers=",
                    "--proxies=",
                    "--resume=",
                    "--script-args-file=",
                )
            ):
                raise InvalidInvocation(f"unsupported_nmap_indirect_target:{option}")
            if argument == "--script-args" and index + 1 < len(args) and "newtargets" in args[index + 1].casefold():
                raise InvalidInvocation("unsupported_nmap_newtargets")
            if argument.startswith("--script-args=") and "newtargets" in argument.casefold():
                raise InvalidInvocation("unsupported_nmap_newtargets")
            if option in {"--datadir", "--script-args", "--script-args-file"}:
                raise InvalidInvocation("unsupported_nmap_script_args")
            if option == "--script":
                script_value = (
                    argument.split("=", 1)[1] if "=" in argument else (args[index + 1] if index + 1 < len(args) else "")
                )
                if script_value.strip().casefold() != "vuln":
                    raise InvalidInvocation("unsupported_nmap_script_source")
        value_flags = {
            "-e",
            "-g",
            "-p",
            "--data-length",
            "--exclude",
            "--excludefile",
            "--host-timeout",
            "--initial-rtt-timeout",
            "--max-hostgroup",
            "--max-parallelism",
            "--max-rate",
            "--max-retries",
            "--max-rtt-timeout",
            "--max-scan-delay",
            "--min-hostgroup",
            "--min-parallelism",
            "--min-rate",
            "--min-rtt-timeout",
            "--mtu",
            "--scan-delay",
            "--script",
            "--script-args",
            "--source-port",
            "--spoof-mac",
            "--stylesheet",
            "--top-ports",
            "--ttl",
            "--version-intensity",
        }
        clean: list[str] = []
        skip_next = False
        for argument in args:
            if skip_next:
                skip_next = False
                continue
            if argument in {
                "-oX",
                "-oN",
                "-oG",
                "-oA",
                "-o",
                *value_flags,
            } or argument.startswith("--output"):
                skip_next = True
                continue
            if argument.startswith(("--ports", "-p=", "--top-ports=")):
                continue
            clean.append(argument)
        positional = tuple(argument for argument in clean if not argument.startswith("-"))
        invalid = next((argument for argument in positional if not validate_target(argument)), "")
        if invalid:
            raise InvalidInvocation(f"invalid_nmap_target:{invalid[:120]}")
        candidates = tuple(dict.fromkeys(positional))
        if not candidates:
            return ()
        # The runner binds the last remaining positional value to ``target``
        # and forwards earlier values as flags.  Keep that primary endpoint
        # first for action/request target matching, while still authorizing
        # every earlier network-shaped value that the provider will receive.
        return (candidates[-1], *candidates[:-1])

    if name == "rustscan":
        separator = args.index("--") if "--" in args else len(args)
        rustscan_args = args[:separator]
        for argument in rustscan_args:
            option = argument.split("=", 1)[0]
            if option in {"-c", "--config-path", "--resolver", "--scripts"} or (
                argument.startswith("-c") and argument != "-c"
            ):
                raise InvalidInvocation(f"unsupported_rustscan_indirection:{option}")
        target = ""
        flags: list[str] = []
        index = 0
        while index < len(args):
            argument = args[index]
            if argument in {"-a", "--addresses"} and index + 1 < len(args):
                if not target:
                    target = args[index + 1]
                index += 2
                continue
            if argument.startswith("--addresses="):
                if not target:
                    target = argument.split("=", 1)[1]
                index += 1
                continue
            flags.append(argument)
            index += 1
        if not target:
            target = next(
                (argument for argument in reversed(flags) if not argument.startswith("-")),
                "",
            )
        targets: list[str] = []
        if target and validate_target(target):
            targets.append(target)
        # Arguments forwarded after ``--`` are interpreted by Nmap.  Treat
        # every network-shaped value there as an additional dispatched target.
        if "--" in flags:
            separator = flags.index("--")
            forwarded = _special_registered_targets("nmap", flags[separator + 1 :]) or ()
            targets.extend(item for item in forwarded if item not in targets)
        return tuple(targets)

    if name in {"msf_check", "msf_run"}:
        msf_targets: list[str] = []
        if args and validate_target(args[0]):
            msf_targets.append(args[0])
        try:
            flattened = list(validate_msf_options(" ".join(args[2:])))
        except ValueError as exc:
            raise InvalidInvocation(str(exc)) from exc
        for index, argument in enumerate(flattened):
            option_name = argument.split("=", 1)[0].upper()
            if option_name in _MSF_UNBOUND_ENDPOINT_OPTIONS:
                raise InvalidInvocation(f"unbound_msf_option:{option_name}")
            match = re.match(r"(?i)^(?:RHOSTS?|VHOST)=(.+)$", argument)
            candidate = match.group(1).strip() if match else ""
            if not candidate and argument.upper() in {"RHOST", "RHOSTS", "VHOST"} and index + 1 < len(flattened):
                candidate = flattened[index + 1].strip()
            for item in re.split(r"[,\s]+", candidate):
                if item and validate_target(item) and item not in msf_targets:
                    msf_targets.append(item)
        return tuple(msf_targets)

    if name in {"deploy_c2_beacon", "killchain_full", "killchain_persist"}:
        callback_targets = [args[0]] if args and validate_target(args[0]) else []
        callback_host = args[3].strip() if len(args) > 3 else ""
        if not callback_host or not validate_host(callback_host):
            raise InvalidInvocation("missing_explicit_callback_target")
        if callback_host not in callback_targets:
            callback_targets.append(callback_host)
        return tuple(callback_targets)

    if name in {"build_go_implant", "build_ps_stager", "build_python_implant"}:
        c2_url = args[0].strip() if args else ""
        if not c2_url:
            return ()
        if any(character in c2_url for character in (",", ";", "\r", "\n")):
            raise InvalidInvocation("multiple_c2_targets_not_supported")
        if not re.match(r"^https?://", c2_url, re.IGNORECASE) or not validate_target(c2_url):
            raise InvalidInvocation("invalid_c2_target")
        return (c2_url,)

    if name == "browser_surface_analysis":
        target = args[0].strip() if args else ""
        proto = args[1].strip().casefold() if len(args) > 1 else "https"
        port_text = args[2].strip() if len(args) > 2 else ""
        if proto not in {"http", "https"}:
            raise InvalidInvocation("invalid_browser_protocol")
        if port_text:
            try:
                port = int(port_text)
            except ValueError as exc:
                raise InvalidInvocation("invalid_browser_port") from exc
            if not 1 <= port <= 65_535:
                raise InvalidInvocation("invalid_browser_port")
        if target.startswith(("http://", "https://")):
            url = target
        else:
            url = f"{proto}://{target}" + (f":{port_text}" if port_text else "")
        if not validate_target(url):
            raise InvalidInvocation("invalid_browser_target")
        return (url,)

    command_index = _REMOTE_COMMAND_ARGUMENT.get(name)
    if command_index is not None:
        remote_targets: list[str] = []
        if args and validate_target(args[0]):
            remote_targets.append(args[0])
        if command_index < len(args):
            payload = " ".join(args[command_index:])
            if not remote_command_is_code_owned(name, payload):
                raise InvalidInvocation(f"unapproved_remote_command:{name}")
        return tuple(remote_targets)

    if name == "curl_headers":
        for argument in args:
            option = argument.split("=", 1)[0]
            if (
                option
                in {
                    "-L",
                    "-K",
                    "-x",
                    "--abstract-unix-socket",
                    "--alt-svc",
                    "--config",
                    "--connect-to",
                    "--dns-servers",
                    "--doh-url",
                    "--location",
                    "--location-trusted",
                    "--next",
                    "--preproxy",
                    "--proxy",
                    "--resolve",
                    "--unix-socket",
                    "--url",
                }
                or option.startswith(("--proxy-", "--socks"))
                or (
                    argument.startswith("-")
                    and not argument.startswith("--")
                    and any(flag in argument[1:] for flag in "KLx")
                )
            ):
                raise InvalidInvocation(f"unsupported_curl_indirection:{option}")
        value_flags = {
            "-A",
            "--user-agent",
            "-H",
            "--header",
            "--max-time",
            "--connect-timeout",
        }
        target = ""
        skip_next = False
        for argument in args:
            if skip_next:
                skip_next = False
                continue
            if argument in value_flags:
                skip_next = True
                continue
            if argument.startswith(("http://", "https://")):
                target = argument
                break
            if not argument.startswith("-"):
                target = argument
        return (target,) if target else ()

    if name == "enum4linux":
        target = next(
            (argument for argument in reversed(args) if not argument.startswith("-")),
            args[-1] if args else "",
        )
        return (target,) if target else ()

    if name == "nuclei_safe":
        value_flags = {
            "-severity",
            "-exclude-tags",
            "-tags",
            "-t",
            "-templates",
            "-timeout",
            "-retries",
            "-rl",
            "-rate-limit",
            "-c",
            "-bs",
            "-headless-bulk-size",
            "-page-timeout",
            "-proxy",
        }
        target_flags = {"-u", "-url", "-target"}
        target = ""
        skip_next = False
        for index, argument in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            if any(argument.startswith(flag + "=") for flag in target_flags):
                target = argument.split("=", 1)[1]
                break
            if argument in target_flags and index + 1 < len(args):
                target = args[index + 1]
                break
            if argument in value_flags:
                skip_next = True
                continue
            if argument.startswith("-"):
                continue
            if re.match(r"^https?://", argument, re.IGNORECASE):
                target = argument
                break
        if not target:
            target = next((argument for argument in args if not argument.startswith("-")), "")
        return (target,) if target else ()

    flag_contracts = {
        "nikto": (
            {"-h", "-host", "--host"},
            {"-output", "-Format", "-Tuning", "-Display", "-Plugins", "-useragent"},
            ("-h=", "-host=", "--host="),
        ),
        "sqlmap": (
            {"-u", "--url"},
            {"-r", "-l", "-m", "-c", "--proxy", "--data", "--cookie", "--headers"},
            ("--url=",),
        ),
        "wpscan": (
            {"--url"},
            {"--api-token", "--proxy", "--cookie-string", "--user-agent", "--passwords", "--usernames"},
            ("--url=",),
        ),
    }
    contract = flag_contracts.get(name)
    if contract is not None:
        target_flags, value_flags, assignment_prefixes = contract
        target = ""
        skip_next = False
        for index, argument in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            if argument in target_flags and index + 1 < len(args):
                target = args[index + 1]
                break
            if argument.startswith(assignment_prefixes):
                target = argument.split("=", 1)[1]
                break
            if argument in value_flags:
                skip_next = True
                continue
            if not argument.startswith("-"):
                target = argument
                break
        return (target,) if target else ()

    return None


def validate_registered_arguments(
    name: str,
    arguments: Sequence[str],
) -> tuple[str, ...]:
    """Validate one provider's final argument grammar without granting scope."""

    targets = _special_registered_targets(
        str(name or "").strip().casefold(),
        arguments,
    )
    return tuple(targets or ())


def registered_tool_requires_approval(
    name: str,
    argv: Sequence[str] = (),
) -> bool:
    """Classify whether one registered invocation is active/manual-gated.

    This is deliberately the same pure classification used by
    :meth:`ExecutionPolicy.authorize_registered`.  Action/provider ranking can
    therefore account for active risk without maintaining a second, drifting
    list of sensitive tools.  The helper grants no authority and performs no
    dispatch.
    """

    normalized = str(name or "").strip().casefold()
    arguments = tuple(str(item) for item in argv)
    requires_approval = normalized in _MANUAL_APPROVAL_TOOLS
    if normalized == "plugin":
        gateway = arguments[1].casefold() if len(arguments) > 1 else ""
        if gateway in {"list", "ls", "summary"}:
            requires_approval = False
        elif len(arguments) <= 3:
            # A concrete plugin request without an explicit verb must never
            # inherit the passive ``scan`` classification.
            requires_approval = True
        else:
            fourth = arguments[3].casefold()
            action = "scan" if "=" in fourth else fourth
            requires_approval = action not in {"list", "ls", "scan", "check", "summary"}
    return requires_approval


class InvalidInvocation(ValueError):
    """Raised when a command cannot be represented as a typed invocation."""


def _clean_host(host: str) -> str:
    try:
        return host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("invalid_idn") from exc


def _split_target(value: str) -> tuple[str, str, int | None]:
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


def normalize_host(value: str) -> str:
    """Normalize a host-only endpoint with no URL, port, path, or userinfo."""

    raw = str(value or "").strip().strip("'\"")
    if not raw or len(raw) > 253 or any(character.isspace() for character in raw):
        raise ValueError("invalid_host")
    if any(character in raw for character in ("/", "?", "#", "@", "\\", "\x00", "\r", "\n")):
        raise ValueError("invalid_host")
    try:
        return str(ipaddress.ip_address(raw.strip("[]")))
    except ValueError:
        if ":" in raw:
            raise ValueError("host_port_not_allowed") from None
    host = _clean_host(raw)
    if host != "localhost" and not _HOST_RE.fullmatch(host):
        raise ValueError("invalid_hostname")
    return host


def validate_host(value: str) -> bool:
    """Return whether a value is one exact host without endpoint syntax."""

    try:
        normalize_host(value)
        return True
    except ValueError:
        return False


def targets_equivalent(left: str, right: str) -> bool:
    """Compare target spellings by normalized host/network and optional port."""

    try:
        return _split_target(left) == _split_target(right)
    except ValueError:
        return False


def validate_msf_options(options: str) -> tuple[str, ...]:
    """Parse the closed MSF option envelope and reject opaque endpoint/command inputs."""

    raw = str(options or "")
    if any(character in raw for character in ("\x00", "\r", "\n", ";")):
        raise ValueError("unsafe_msf_option_syntax")
    try:
        tokens = tuple(shlex.split(raw, posix=True))
    except ValueError as exc:
        raise ValueError("invalid_msf_options_quoting") from exc
    for token in tokens:
        key, separator, value = token.partition("=")
        normalized = key.strip().upper()
        if not normalized:
            continue
        if (
            normalized
            in {
                "AUTORUNSCRIPT",
                "CMD",
                "COMMAND",
                "COMMANDS",
                "HTTPPROXYHOST",
                "INITIALAUTORUNSCRIPT",
                "PROXIES",
                "REVERSELISTENERBINDADDRESS",
                "RHOSTS_FILE",
            }
            or normalized.startswith("SESSION")
            or (normalized.endswith(("HOST", "HOSTS")) and normalized not in {"RHOST", "RHOSTS"})
        ):
            raise ValueError(f"unbound_msf_option:{normalized}")
        if normalized == "PAYLOAD" and separator and "reverse" in value.casefold():
            raise ValueError("unbound_msf_reverse_payload")
    return tokens


def bind_msf_target_options(options: str, target: str) -> str:
    """Remove caller-selected remote hosts and bind MSF to one action target."""

    if not validate_target(target):
        raise ValueError("invalid_msf_target")
    tokens = list(validate_msf_options(options))

    retained: list[str] = []
    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        upper = token.upper()
        if upper in {"RHOST", "RHOSTS"}:
            skip_next = True
            continue
        if re.match(r"(?i)^RHOSTS?=", token):
            continue
        retained.append(token)
    return shlex.join((f"RHOSTS={target}", *retained))


def _scope_matches(target: str, scope: str) -> bool:
    target_kind, target_value, target_port = _split_target(target)
    raw_scope = (scope or "").strip()
    if not raw_scope:
        return False

    wildcard = raw_scope.startswith("*.")
    if wildcard:
        suffix = _clean_host(raw_scope[2:])
        return target_kind == "host" and target_value.endswith(f".{suffix}") and target_value != suffix

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


def _command_text_network_targets(command: str) -> tuple[str, ...]:
    """Extract endpoints used by a shell/remote-command network client.

    Free-form command text is an opaque execution language.  This parser owns
    a deliberately small grammar for common network clients and rejects
    variable/indirect endpoints instead of pretending they are target-free.
    """

    raw = str(command or "")
    if _SHELL_VARIABLE_RE.search(raw):
        raise InvalidInvocation("unresolved_network_variable")
    try:
        lexer = shlex.shlex(raw, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError as exc:
        raise InvalidInvocation("invalid_remote_command_quoting") from exc

    # Bind endpoints to the network-client segment that consumes them.  A
    # global pre-scan both over-scoped inert text and made a later segment look
    # unresolved when its target had already been inserted.
    targets: list[str] = []
    segment: list[str] = []

    def add(candidate: str) -> None:
        value = str(candidate or "").strip().strip("'\"")
        if "@" in value and "://" not in value:
            value = value.rsplit("@", 1)[-1]
        if validate_target(value) and value not in targets:
            targets.append(value)

    def inspect_segment(items: Sequence[str]) -> None:
        if not items:
            return
        command_index = next(
            (
                index
                for index, item in enumerate(items)
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", item)
                and item not in {"sudo", "env", "command", "nohup"}
            ),
            None,
        )
        if command_index is None:
            return
        executable = items[command_index].rsplit("/", 1)[-1].casefold()
        if executable not in _NETWORK_CLIENT_COMMANDS:
            return
        starting_target_count = len(targets)
        arguments = list(items[command_index + 1 :])
        value_flags = {
            "-A",
            "-H",
            "-P",
            "-S",
            "-b",
            "-c",
            "-i",
            "-p",
            "-s",
            "-w",
            "--connect-timeout",
            "--header",
            "--interface",
            "--max-time",
            "--output",
            "--user-agent",
        }
        positional: list[str] = []
        skip_next = False
        proxy_next = False
        for argument in arguments:
            if skip_next:
                if proxy_next:
                    add(argument)
                    proxy_next = False
                skip_next = False
                continue
            if argument in value_flags:
                skip_next = True
                continue
            if argument.startswith(("--proxy=", "-x=")):
                add(argument.split("=", 1)[1])
                continue
            if argument in {"--proxy", "-x"}:
                skip_next = True
                proxy_next = True
                continue
            if argument.startswith("-"):
                continue
            positional.append(argument)

        for argument in positional:
            if validate_target(argument) or "@" in argument:
                add(argument)
                if executable in {
                    "ping",
                    "nc",
                    "ncat",
                    "netcat",
                    "ssh",
                    "scp",
                    "sftp",
                    "ftp",
                    "telnet",
                    "dig",
                    "nslookup",
                }:
                    break
        if len(targets) == starting_target_count:
            raise InvalidInvocation(f"unresolved_network_target:{executable}")

    for token in tokens:
        if token and all(char in ";&|<>" for char in token):
            inspect_segment(segment)
            segment = []
        else:
            segment.append(token)
    inspect_segment(segment)
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
        invocation: ToolInvocation | None = None,
    ) -> ExecutionDecision:
        decision = ExecutionDecision(allowed, reason, context, invocation)
        logger.info("execution_decision=%s", decision.to_dict())
        return decision

    def _limits_valid(self, context: ExecutionContext) -> bool:
        return 1 <= int(context.max_runtime_seconds) <= 86_400 and 1_024 <= int(context.max_output_bytes) <= 100_000_000

    def _targets_allowed(
        self,
        targets: Sequence[str],
        context: ExecutionContext,
    ) -> tuple[bool, str]:
        for target in targets:
            if not validate_target(target):
                return False, f"invalid_target:{target[:120]}"
        if targets and not context.target_scope:
            return False, "missing_target_scope"
        for target in targets:
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
        policy_names = tuple(
            dict.fromkeys(candidate for candidate in (invocation.registered_name, invocation.executable) if candidate)
        )
        canonical_killchain_name = None
        from core.killchain.policy import (
            canonical_killchain_tool,
            registered_tool_gate_reason,
        )

        for policy_name in policy_names:
            configured_denial = registered_tool_gate_reason(policy_name)
            if configured_denial:
                return self._decision(
                    False,
                    configured_denial,
                    context,
                    invocation,
                )
            canonical_killchain_name = canonical_killchain_name or canonical_killchain_tool(policy_name)

        # ``registered_name`` is caller-supplied metadata at this boundary. It
        # must resolve to the same canonical ToolDef as the executable/alias in
        # argv before it can influence approval or dispatch classification.
        try:
            import core.tools  # noqa: F401
            from core.tools.registry import get_tool
        except ImportError:
            return self._decision(
                False,
                "registered_tool_registry_unavailable",
                context,
                invocation,
            )

        registered_tool = get_tool(name)
        if registered_tool is None:
            return self._decision(
                False,
                f"unknown_registered_tool:{str(name)[:120]}",
                context,
                invocation,
            )
        alias_tokens = 1
        command_tool = get_tool(invocation.executable)
        if command_tool is None and len(invocation.argv) >= 2:
            command_tool = get_tool(f"{invocation.argv[0]} {invocation.argv[1]}")
            if command_tool is not None:
                alias_tokens = 2
        if command_tool is None or command_tool.name != registered_tool.name:
            return self._decision(
                False,
                "registered_tool_mismatch",
                context,
                invocation,
            )
        name = registered_tool.name
        registered_arguments = tuple(str(item) for item in invocation.argv[alias_tokens:])
        plugin_inventory_gateway = bool(
            name == "plugin"
            and registered_arguments
            and registered_arguments[0].strip().casefold() in {"list", "ls", "summary"}
        )
        declared_targets: tuple[str, ...]
        if plugin_inventory_gateway:
            declared_targets = ()
        else:
            try:
                declared_targets = _declared_network_targets(
                    registered_tool,
                    invocation.argv,
                    alias_tokens,
                )
            except InvalidInvocation as exc:
                return self._decision(False, str(exc), context, invocation)
        uses_network_scope = (
            _registered_tool_uses_network_scope(registered_tool)
            or (name in _OPTIONAL_NETWORK_TARGET_TOOLS and bool(declared_targets))
        ) and not plugin_inventory_gateway
        effective_targets = tuple(dict.fromkeys((*declared_targets, *invocation.targets)))
        if effective_targets != invocation.targets:
            invocation = ToolInvocation(
                executable=invocation.executable,
                argv=invocation.argv,
                raw_command=invocation.raw_command,
                registered_name=invocation.registered_name,
                targets=effective_targets,
                uses_shell=invocation.uses_shell,
            )
        if uses_network_scope and not effective_targets:
            return self._decision(
                False,
                "missing_explicit_target",
                context,
                invocation,
            )

        targets = effective_targets if uses_network_scope else ()
        allowed, reason = self._targets_allowed(targets, context)
        if not allowed:
            return self._decision(False, reason, context, invocation)

        requires_approval = registered_tool_requires_approval(
            canonical_killchain_name or name,
            invocation.argv,
        )
        if requires_approval and (not context.has(CAP_ACTIVE_TOOL) or not context.approved or not context.approval_id):
            return self._decision(False, "active_tool_requires_approval", context, invocation)
        if not bool(getattr(registered_tool, "enabled", True)):
            reason = str(getattr(registered_tool, "disabled_reason", "") or "provider_disabled")
            return self._decision(False, reason, context, invocation)
        return self._decision(True, "registered_tool_authorized", context, invocation)

    def authorize_coarse(
        self,
        action_id: str,
        context: ExecutionContext,
    ) -> ExecutionDecision:
        if not context.actor:
            return self._decision(False, "missing_actor", context, None)
        return self._decision(True, "coarse_authorization_granted", context, None)

    def authorize_deep(
        self,
        action_id: str,
        context: ExecutionContext,
        target_scope: tuple[str, ...],
    ) -> ExecutionDecision:
        allowed, reason = self._targets_allowed(target_scope, context)
        if not allowed:
            return self._decision(False, reason, context, None)
        return self._decision(True, "deep_authorization_granted", context, None)

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
        return self._decision(
            False,
            f"unknown_tool:{invocation.executable}",
            context,
            invocation,
        )

    def authorize_shell(
        self,
        command: str,
        context: ExecutionContext,
    ) -> ExecutionDecision:
        try:
            invocation = parse_invocation(command, allow_executable_path=True)
        except InvalidInvocation as exc:
            return self._decision(False, str(exc), context)
        if contains_sensitive_command_material(command, argv=invocation.argv):
            return self._decision(
                False,
                "credential_material_forbidden_in_managed_shell",
                context,
                invocation,
            )
        try:
            shell_targets = _command_text_network_targets(command)
        except InvalidInvocation as exc:
            return self._decision(False, str(exc), context, invocation)
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
                parameter_positions = _network_parameter_positions(tool_def)
                if not _registered_tool_uses_network_scope(tool_def) and bool(getattr(tool_def, "needs_target", True)):
                    action_arguments = invocation.argv[alias_tokens:]
                    candidates = action_arguments[:1]
                elif parameter_positions:
                    try:
                        candidates = _declared_network_targets(
                            tool_def,
                            invocation.argv,
                            alias_tokens,
                        )
                    except InvalidInvocation as exc:
                        return self._decision(False, str(exc), context, invocation)
                else:
                    candidates = extract_network_targets(invocation.argv[alias_tokens:])
                # The callable's typed target position is authoritative.  The
                # generic network-token fallback is used only for legacy
                # callables without a typed position, so an earlier URL/IP
                # argument cannot shadow the endpoint the provider will use.
                targets = candidates
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

    # --- unified runtime policy gates (phase-1.3) ---

    def check_capability_permission(
        self,
        capability_class: str,
        context: ExecutionContext,
    ) -> ExecutionDecision:
        """Verify that *capability_class* is permitted under *context*.

        The default implementation allows all capabilities when the context
        carries ``CAP_REGISTERED_TOOL``; subclasses or future configuration
        may restrict specific classes.
        """
        if not capability_class:
            return self._decision(True, "no_capability_restriction", context)
        allowed = context.has(CAP_REGISTERED_TOOL)
        reason = "capability_permitted" if allowed else f"capability_denied:{capability_class}"
        return self._decision(allowed, reason, context)

    def check_killchain_stage(
        self,
        stage: str | None,
        context: ExecutionContext,
    ) -> ExecutionDecision:
        """Verify that *stage* is reachable under current policy."""
        if stage is None:
            return self._decision(True, "no_stage_restriction", context)
        allowed = context.has(CAP_REGISTERED_TOOL)
        reason = "stage_permitted" if allowed else f"stage_denied:{stage}"
        return self._decision(allowed, reason, context)

    def check_preconditions(
        self,
        required_fact_types: tuple[str, ...],
        available_fact_types: frozenset[str],
    ) -> tuple[bool, str]:
        """Check whether all required precondition fact-types exist.

        Returns ``(True, 'ok')`` when satisfied or
        ``(False, 'blocked_by_input:<missing>')`` with the first missing
        type name.

        This is a pure predicate — it does **not** read mutable FactStore.
        Evidence belongs to FactStore/snapshot; this method receives only
        the already-evaluated immutable set.
        """
        for ft in required_fact_types:
            if ft not in available_fact_types:
                return False, f"blocked_by_input:{ft}"
        return True, "ok"

    def check_credential_authorization(
        self,
        credential_ref: str,
        context: ExecutionContext,
    ) -> ExecutionDecision:
        """Verify that *context* is authorized to resolve *credential_ref*.

        The default gate requires ``CAP_REGISTERED_TOOL`` and a non-empty
        credential reference.  Stricter checks (e.g. per-credential ACL)
        can be added by subclass.
        """
        normalized_ref = str(credential_ref or "").strip()
        if not normalized_ref:
            return self._decision(False, "empty_credential_ref", context)
        if not normalized_ref.startswith("credential://") or any(
            character.isspace() or ord(character) < 32 for character in normalized_ref
        ):
            return self._decision(False, "invalid_credential_ref", context)
        allowed = context.has(CAP_REGISTERED_TOOL)
        reason = "credential_authorized" if allowed else "credential_denied"
        return self._decision(allowed, reason, context)


def authorize_final_registered_arguments(
    name: str,
    arguments: Sequence[str],
    context: ExecutionContext,
) -> ExecutionDecision:
    """Re-authorize the exact provider-expanded argv immediately before a sink."""

    command = shlex.join((str(name), *(str(item) for item in arguments)))
    return ExecutionPolicy().authorize_command(command, context)
