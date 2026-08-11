"""Menu Bridge for legacy CLI numeric choice mapping and canonical dispatch."""

from __future__ import annotations

import logging
import shlex
from typing import Any

from core.actions.catalog import ActionCatalog
from core.actions.executor import ActionExecutor
from core.actions.models import ActionExecutionReport, ActionRequest, OutcomeStatus
from core.execution import ExecutionContext

logger = logging.getLogger("octopus.cli.menu_bridge")

MENU_CANONICAL_MAP: dict[str, str] = {
    "1": "tool:nmap",
    "2": "tool:whois",
    "3": "tool:whatweb",
    "4": "tool:curl_headers",
    "5": "tool:dig",
    "6": "tool:sslscan",
    "7": "tool:ffuf",
    "8": "tool:enum4linux",
    "9": "tool:smbclient",
    "10": "tool:wpscan",
    "11": "tool:sqlmap",
    "12": "tool:nikto",
    "13": "tool:scrapling",
    "15": "tool:ssh_user_enum",
    "16": "tool:bruteforce",
    "17": "tool:web_login_brute",
    "18": "tool:ssh_session",
    "19": "killchain:killchain_vuln_assess",
    "20": "killchain:killchain_exploit",
    "21": "killchain:killchain_privesc",
    "22": "killchain:killchain_persist",
    "23": "killchain:killchain_lateral",
    "24": "killchain:killchain_exfil",
    "25": "killchain:killchain_full",
    "26": "tool:waf_detect",
    "27": "killchain:killchain_cleanup",
    "28": "tool:shodan",
    "29": "tool:shodan",
    "30": "tool:shodan",
    "31": "tool:crack_hashes",
    "32": "tool:shodan",
    "35": "tool:ad_enum",
    "36": "tool:asrep_roast",
    "37": "tool:kerberoast",
    "38": "tool:dcsync",
    "39": "killchain:pass_the_hash",
    "40": "tool:psexec",
    "41": "tool:wmiexec",
    "42": "tool:socks_proxy",
    "43": "tool:port_forward",
    "44": "tool:network_recon",
    "45": "tool:build_go_implant",
    "46": "tool:build_python_implant",
    "47": "tool:build_ps_stager",
    "49": "tool:ftp_anonymous_check",
    "50": "tool:smtp_probe",
}

_EXPLICIT_INPUT_CHOICES = frozenset(
    {
        "18",
        "20",
        "21",
        "22",
        "23",
        "24",
        "25",
        "27",
        "31",
        "36",
        "37",
        "38",
        "39",
        "40",
        "41",
        "42",
        "43",
        "44",
        "45",
        "46",
        "47",
    }
)
_UNMAPPED_SHODAN_SUBACTION_CHOICES = frozenset({"29", "30", "32"})


def build_menu_action_request(
    choice: str,
    target: str,
    *,
    context: ExecutionContext | None = None,
    parameters: dict[str, Any] | None = None,
    arguments: tuple[str, ...] = (),
    typed_input: object | None = None,
    facts: tuple[dict[str, Any], ...] = (),
    precondition_refs: tuple[str, ...] = (),
) -> tuple[str | None, ActionRequest | None]:
    """Construct a canonical ActionRequest for a legacy menu numeric choice.

    Fails closed cleanly (returning (None, None)) if choice or target is invalid.
    """
    normalized_choice = str(choice).strip()
    canonical_id = MENU_CANONICAL_MAP.get(normalized_choice)
    if not canonical_id:
        logger.error("No canonical action mapped for menu choice '%s'", choice)
        return None, None

    normalized_target = str(target or "").strip()
    if not normalized_target:
        logger.error("Cannot build typed ActionRequest for choice '%s': target is empty", choice)
        return None, None

    if not isinstance(context, ExecutionContext):
        logger.error("Menu dispatch requires an explicit ExecutionContext")
        return None, None
    exec_context = context

    if normalized_choice in _UNMAPPED_SHODAN_SUBACTION_CHOICES:
        logger.error("Menu choice '%s' has no distinct canonical Shodan subaction", choice)
        return None, None
    if normalized_choice in _EXPLICIT_INPUT_CHOICES:
        has_consumable_input = typed_input is not None if normalized_choice == "39" else bool(arguments)
        if not has_consumable_input:
            logger.error("Menu choice '%s' requires input consumed by its canonical adapter", choice)
            return None, None

    command = ""
    if normalized_choice == "13":
        url = (
            normalized_target
            if normalized_target.startswith(("http://", "https://"))
            else f"http://{normalized_target}"
        )
        command = shlex.join(("scrapling", url))
    elif normalized_choice == "16":
        command = shlex.join(("bruteforce", "ssh", normalized_target))

    request = ActionRequest(
        target=normalized_target,
        execution_context=exec_context,
        arguments=arguments,
        parameters=parameters or {},
        command=command,
        typed_input=typed_input,
        facts=facts,
        precondition_refs=precondition_refs,
    )
    return canonical_id, request


def dispatch_menu_choice(
    choice: str,
    target: str,
    catalog: ActionCatalog,
    executor: ActionExecutor,
    *,
    context: ExecutionContext | None = None,
    parameters: dict[str, Any] | None = None,
    arguments: tuple[str, ...] = (),
    typed_input: object | None = None,
    facts: tuple[dict[str, Any], ...] = (),
    precondition_refs: tuple[str, ...] = (),
) -> tuple[bool, ActionExecutionReport | str]:
    """Dispatch a legacy menu choice through ActionCatalog and ActionExecutor.

    Returns (success_flag, report_or_error_message). Fails closed if request
    or resolution fails.
    """
    canonical_id, request = build_menu_action_request(
        choice,
        target,
        context=context,
        parameters=parameters,
        arguments=arguments,
        typed_input=typed_input,
        facts=facts,
        precondition_refs=precondition_refs,
    )
    if canonical_id is None or request is None:
        err_msg = f"[!] Failed closed: cannot construct typed ActionRequest for menu choice '{choice}'."
        logger.error(err_msg)
        return False, err_msg

    resolved = catalog.resolve(canonical_id)
    if resolved is None:
        err_msg = f"[!] Failed closed: action '{canonical_id}' (choice '{choice}') not resolved in catalog."
        logger.error(err_msg)
        return False, err_msg

    try:
        report = executor.run(resolved.canonical_id, request)
        successful = report.lifecycle.outcome in {
            OutcomeStatus.SUCCEEDED,
            OutcomeStatus.PARTIAL,
        }
        return successful, report
    except Exception as exc:
        err_msg = f"[!] Failed closed executing action '{canonical_id}': {exc}"
        logger.exception("Error executing menu action %s", canonical_id)
        return False, err_msg
