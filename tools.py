#!/usr/bin/env python3
"""
"""

# Base utilities
from core.tools.base import (
    run_tool, is_tool_available, _fmt_elapsed, get_tool_config, ToolResult,
)

# Credential cache
from core.tools.exploit_tools import (
    register_credential, get_known_creds,
    get_best_creds_for_target, get_all_known_creds_for_target,
    _merge_wordlists, _is_internal_ip,
    run_bruteforce, run_web_login_bruteforce,
    run_jmx2rce_scan, run_jmx2rce_rce,
    run_jmx2rce_read, run_jmx2rce_cleanup,
)

# Recon tools
from core.tools.recon_tools import (
    run_nmap, run_whois, run_whatweb, run_curl_headers,
    run_dig, run_sslscan, run_ffuf, run_enum4linux,
    run_smbclient, run_wpscan, run_sqlmap, run_nikto,
    run_scrapling_fetch, run_scrapling_crawl,
    run_ssh_user_enum, run_ftp_anonymous_check, run_smtp_probe,
)

# Post-exploitation + recon pipeline
from core.tools.post_tools import (
    _run_ssh_session_interactive, _run_killchain_stage,
    _run_killchain_interactive, _run_waf_detect,
    _run_shodan_interactive, _run_shodan_host,
    _run_shodan_vulns, _run_shodan_range,
    _run_crack_hashes, run_default_recon,
)

# Dispatchers
from core.tools.runner import (
    TOOLS_MENU,
    run_single_tool, format_recon_for_llm,
    run_python_repl, run_tool_by_command,
    interactive_tool_run, run_arbitrary_cmd,
)
