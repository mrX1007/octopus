#!/usr/bin/env python3

import shutil
from typing import List, Dict, Set

class ToolRegistry:
    def __init__(self):
        # LLMs and plugins often describe the same work with slightly different
        # names. Keep that vocabulary normalized at the registry boundary so the
        # rest of the pipeline can track completed work reliably.
        self.task_aliases = {
            "port_scan": "service_discovery",
            "scan_ports": "service_discovery",
            "service_scan": "service_discovery",
            "service_enumeration": "service_discovery",
            "enumerate_services": "service_discovery",
            "recon": "service_discovery",
            "initial_recon": "service_discovery",

            "vuln_scan": "vulnerability_assessment",
            "vulnerability_scan": "vulnerability_assessment",
            "vuln_assess": "vulnerability_assessment",
            "exploit_selection": "exploit_selection",
            "select_exploits": "exploit_selection",
            "exploit_select": "exploit_selection",
            "payload_plan": "exploit_selection",
            "payload_planning": "exploit_selection",
            "metasploit": "metasploit_verification",
            "msf": "metasploit_verification",
            "msf_check": "metasploit_verification",
            "metasploit_check": "metasploit_verification",
            "web_scan": "vulnerability_assessment",
            "web_vuln_scan": "web_vulnerability_testing",
            "web_vulnerability_scan": "web_vulnerability_testing",
            "web_vulnerability_testing": "web_vulnerability_testing",
            "wordpress_scan": "web_vulnerability_testing",
            "wpscan": "web_vulnerability_testing",
            "sqlmap": "web_vulnerability_testing",
            "sql_injection": "web_vulnerability_testing",
            "sqli": "web_vulnerability_testing",
            "jmx": "web_vulnerability_testing",
            "jmx2rce": "web_vulnerability_testing",
            "web_enum": "web_application_mapping",
            "web_enumeration": "web_application_mapping",
            "web_recon": "web_application_mapping",
            "web_fingerprinting": "web_application_mapping",
            "http_fingerprint": "web_application_mapping",
            "browser_analyze": "browser_surface_analysis",
            "browser_analysis": "browser_surface_analysis",
            "browser_surface": "browser_surface_analysis",
            "shardbrowser_browse": "browser_surface_analysis",
            "directory_bruteforce": "web_content_discovery",
            "dir_bruteforce": "web_content_discovery",
            "dirb_fuzz": "web_content_discovery",
            "content_discovery": "web_content_discovery",
            "directory_discovery": "web_content_discovery",
            "crawl": "web_content_discovery",
            "tls_scan": "transport_security_assessment",
            "ssl_scan": "transport_security_assessment",
            "ssl_assessment": "transport_security_assessment",
            "ftp": "ftp_assessment",
            "ftp_anon": "ftp_assessment",
            "ftp_anonymous": "ftp_assessment",
            "ftp_anonymous_check": "ftp_assessment",
            "smtp": "mail_service_assessment",
            "smtp_probe": "mail_service_assessment",
            "smtp_banner": "mail_service_assessment",
            "mail_enum": "mail_service_assessment",
            "mail_service_assessment": "mail_service_assessment",
            "database_inventory": "database_inventory",
            "db_inventory": "database_inventory",
            "db_enum": "database_inventory",
            "waf_detection": "firewall_detection",
            "detect_waf": "firewall_detection",
            "firewall_detection": "firewall_detection",
            "osint": "external_intelligence",
            "external_recon": "external_intelligence",
            "external_intelligence": "external_intelligence",
            "browser_osint": "browser_osint",
            "shardbrowser": "browser_osint",
            "shard_osint": "browser_osint",
            "ssh_enumeration": "ssh_user_enumeration",
            "enumerate_ssh_users": "ssh_user_enumeration",
            "identify_cves": "analyze_vulnerabilities",
            "analyze_services": "analyze_vulnerabilities",
            "analysis": "analyze_vulnerabilities",

            "credential_discovery": "credential_harvesting",
            "credential_scan": "credential_harvesting",
            "web_credentials": "web_credential_testing",
            "web_credential_testing": "web_credential_testing",
            "web_login_brute": "web_credential_testing",
            "web_brute": "web_credential_testing",
            "ad": "active_directory_enumeration",
            "active_directory": "active_directory_enumeration",
            "ad_enum": "active_directory_enumeration",
            "ad_enumerate": "active_directory_enumeration",
            "domain_enum": "active_directory_enumeration",
            "domain_enumeration": "active_directory_enumeration",
            "asrep": "kerberos_assessment",
            "asrep_roast": "kerberos_assessment",
            "kerberoast": "kerberos_assessment",
            "kerberoasting": "kerberos_assessment",
            "kerberos": "kerberos_assessment",
            "dcsync": "domain_credential_extraction",
            "dc_sync": "domain_credential_extraction",
            "domain_hash_dump": "domain_credential_extraction",
            "domain_credential_dump": "domain_credential_extraction",
            "pass_the_hash": "ad_remote_execution",
            "pth": "ad_remote_execution",
            "psexec": "ad_remote_execution",
            "wmiexec": "ad_remote_execution",
            "wmi_exec": "ad_remote_execution",
            "ad_lateral": "ad_remote_execution",
            "hash_crack": "hash_cracking",
            "hash_cracking": "hash_cracking",
            "crack_hashes": "hash_cracking",
            "smb_enum": "windows_enumeration",
            "enumerate_smb": "windows_enumeration",
            "windows_enum": "windows_enumeration",
            "windows_enumeration": "windows_enumeration",
            "bruteforce": "test_credentials",
            "bruteforce_ssh": "test_credentials",
            "verify_credentials": "test_credentials",

            "privesc": "find_privesc_vectors",
            "privilege_escalation_scan": "find_privesc_vectors",
            "find_privilege_escalation": "find_privesc_vectors",
            "verify_exploit": "vulnerability_assessment",

            "persist": "establish_persistence",
            "persistence": "establish_persistence",
            "plugin": "plugin_assessment",
            "run_plugin": "plugin_assessment",
            "plugin_assessment": "plugin_assessment",
            "cpanel": "cpanel_assessment",
            "cpanel_exploit": "cpanel_assessment",
            "cpanel_auth_bypass": "cpanel_assessment",
            "payload_generation": "payload_generation",
            "payload_build": "payload_generation",
            "build_payload": "payload_generation",
            "build_python_implant": "payload_generation",
            "build_ps_stager": "payload_generation",
            "pivot_setup": "pivot_setup",
            "socks_proxy": "pivot_setup",
            "port_forward": "pivot_setup",
            "internal_recon": "internal_network_recon",
            "internal_network_recon": "internal_network_recon",
            "internal_network_reconnaissance": "internal_network_recon",
            "pivot_recon": "internal_network_recon",
            "network_recon": "internal_network_recon",
            "lateral": "lateral_movement",
            "lateral_move": "lateral_movement",
            "lateral_movement": "lateral_movement",
            "exfil": "exfiltrate_data",
            "data_exfil": "exfiltrate_data",
            "cleanup": "stealth_cleanup",
            "killchain_vuln_assess": "vulnerability_assessment",
            "killchain_vuln": "vulnerability_assessment",
            "vuln_assess": "vulnerability_assessment",
            "killchain_exploit": "exploit_selection",
            "auto_exploit": "exploit_selection",
            "ssh_inventory": "post_access_inventory",
            "controlled_ssh_inventory": "post_access_inventory",
            "post_access_inventory": "post_access_inventory",
        }

        # Execution profiles make registry coverage explicit without silently
        # scheduling invasive actions. Auto tasks are normal pipeline commands,
        # follow-up tasks are only run when emitted as verification facts, and
        # manual/gated tasks remain callable from the CLI with explicit intent.
        self.tool_execution_profiles = {
            "msf_check": "followup",
            "plugin": "auto",
            "searchsploit": "auto",
            "msf_run": "manual_gated",
            "deploy_c2_beacon": "manual_gated",
            "ssh_session": "manual_gated",
            "ssh_exec": "manual_gated",
            "ssh_inventory": "followup",
            "jmx2rce_rce": "manual_gated",
            "jmx2rce_read": "manual_gated",
            "jmx2rce_cleanup": "manual_gated",
            "killchain_vuln_assess": "legacy_wrapper",
            "killchain_exploit": "legacy_wrapper",
            "killchain_full": "legacy_wrapper",
            "stealth_brute": "alias_wrapper",
        }

        # Map high-level tasks to a list of potential CLI commands
        # Each entry is (command_template, binary_name_to_check)
        self.task_map = {
            "service_discovery": [
                ("nmap -Pn -sV --top-ports 1000 {target}", "nmap"),
                ("nmap -Pn -sV -p 2082,2083,2086,2087,2095,2096,8443,8080,3000,3030,9000,5432,465,587,993,995,110,143,21 {target}", "nmap"),
                ("rustscan -a {target} -- -sV", "rustscan"),
            ],
            "vulnerability_assessment": [
                ("nmap -Pn -sV -sC --script=vuln {target}", "nmap"),
                ("nikto -h {target}", "nikto"),
                ("exploit_select {target}", "exploit_select"),
                ("web_vulnerability_testing {target}", "web_vulnerability_testing"),
            ],
            "exploit_selection": [
                ("exploit_select {target}", "exploit_select"),
                ("searchsploit {target}", "searchsploit"),
            ],
            "metasploit_verification": [
                # Concrete module/options are emitted by exploit_select and can
                # be run directly as msf_check TARGET MODULE RPORT=PORT.
                ("exploit_select {target}", "exploit_select"),
            ],
            "web_vulnerability_testing": [
                ("wpscan {target}", "wpscan"),
                ("sqlmap {target}", "sqlmap"),
                ("jmx2rce_scan {target}", "jmx2rce_scan"),
            ],
            "web_application_mapping": [
                ("whatweb {target}", "whatweb"),
                ("curl_headers {target}", "curl_headers"),
                ("scrapling {target}", "scrapling"),
                ("browser_surface_analysis {target}", "browser_surface_analysis"),
            ],
            "browser_surface_analysis": [
                ("browser_surface_analysis {target}", "browser_surface_analysis"),
            ],
            "web_content_discovery": [
                ("ffuf {target}", "ffuf"),
                ("scrapling_crawl {target}", "scrapling_crawl"),
            ],
            "transport_security_assessment": [
                ("sslscan {target}", "sslscan"),
            ],
            "ftp_assessment": [
                ("ftp_anonymous_check {target}", "ftp_anonymous_check"),
            ],
            "mail_service_assessment": [
                ("smtp_probe {target}", "smtp_probe"),
            ],
            "database_inventory": [
                ("db_inventory {target}", "db_inventory"),
            ],
            "firewall_detection": [
                ("waf_detect {target}", "waf_detect"),
            ],
            "external_intelligence": [
                ("whois {target}", "whois"),
                ("dig {target}", "dig"),
                ("shodan {target}", "shodan"),
            ],
            "browser_osint": [
                ("shardbrowser_osint {target}", "shardbrowser_osint"),
            ],
            "ssh_user_enumeration": [
                ("ssh_user_enum {target}", "ssh_user_enum"),
            ],
            "windows_enumeration": [
                ("enum4linux -a {target}", "enum4linux"),
                ("smbclient {target}", "smbclient"),
            ],
            "credential_harvesting": [
                ("enum4linux -a {target}", "enum4linux"),
                ("web_login_brute {target}", "web_login_brute"),
            ],
            "web_credential_testing": [
                ("web_login_brute {target}", "web_login_brute"),
            ],
            "active_directory_enumeration": [
                ("ad_enum {target}", "ad_enum"),
            ],
            "kerberos_assessment": [
                ("asrep_roast {target}", "asrep_roast"),
                ("kerberoast {target}", "kerberoast"),
            ],
            "domain_credential_extraction": [
                ("dcsync {target}", "dcsync"),
            ],
            "ad_remote_execution": [
                ("pass_the_hash {target}", "pass_the_hash"),
                ("psexec {target}", "psexec"),
                ("wmiexec {target}", "wmiexec"),
            ],
            "hash_cracking": [
                ("crack_hashes {target}", "crack_hashes"),
            ],
            "test_credentials": [
                ("bruteforce ssh {target}", "bruteforce"),
            ],
            "find_privesc_vectors": [
                ("ssh_inventory {target}", "ssh_inventory"),
            ],
            "post_access_inventory": [
                ("ssh_inventory {target}", "ssh_inventory"),
            ],
            "exploit_privesc": [
                ("killchain_privesc {target}", "killchain_privesc"),
            ],
            "establish_persistence": [
                ("killchain_persist {target}", "killchain_persist"),
            ],
            "payload_generation": [
                ("build_go_implant", "build_go_implant"),
                ("build_python_implant", "build_python_implant"),
                ("build_ps_stager", "build_ps_stager"),
            ],
            "internal_network_recon": [
                ("network_recon {target}", "network_recon"),
            ],
            "pivot_setup": [
                ("socks_proxy {target}", "socks_proxy"),
                ("port_forward {target}", "port_forward"),
            ],
            "lateral_movement": [
                ("killchain_lateral {target}", "killchain_lateral"),
            ],
            "exfiltrate_data": [
                ("killchain_exfil {target}", "killchain_exfil"),
            ],
            "stealth_cleanup": [
                ("killchain_cleanup {target}", "killchain_cleanup"),
            ],
            "cpanel_assessment": [
                ("plugin cpanel_auth_bypass {target} scan", "plugin"),
                ("cpanel_exploit {target} scan", "cpanel_exploit"),
            ],
            "plugin_assessment": [
                ("plugin list", "plugin"),
            ],
            "analyze_vulnerabilities": [
                # AnalysisAgent doesn't run CLI tools — this is handled by the agent itself
            ],
        }

        # Cache of available tools (checked once)
        self._available_cache = {}
        self._plugin_summary_cache = None

    def canonical_task(self, task: str) -> str:
        """Return the canonical registry task for a planner/agent task name."""
        key = (task or "").strip().lower().replace("-", "_").replace(" ", "_")
        return self.task_aliases.get(key, key)

    def _is_tool_available(self, binary_name: str) -> bool:
        """Check if a CLI tool is installed and available in PATH or internally."""
        if binary_name in self._available_cache:
            return self._available_cache[binary_name]

        try:
            from core.tools.registry import get_tool
            tool_def = get_tool(binary_name)
            if tool_def is not None:
                # If it's a registered tool, check its internal availability (which checks 'requires')
                available = tool_def.is_available()
                self._available_cache[binary_name] = available
                return available
        except ImportError:
            pass

        if binary_name in self.task_map:
            child_binaries = [
                entry_binary
                for _cmd_template, entry_binary in self.task_map[binary_name]
                if entry_binary != binary_name
            ]
            available = bool(child_binaries) and any(self._is_tool_available(entry_binary) for entry_binary in child_binaries)
            self._available_cache[binary_name] = available
            return available

        available = shutil.which(binary_name) is not None
        self._available_cache[binary_name] = available
        return available

    def _tool_names_for_task(self, task: str, seen: Set[str] = None) -> List[str]:
        """Expand a task into concrete tool names, including nested tasks."""
        task = self.canonical_task(task)
        seen = seen or set()
        if task in seen:
            return []
        seen.add(task)

        names = []
        for _cmd_template, binary_name in self.task_map.get(task, []):
            if binary_name in self.task_map and binary_name != task:
                names.extend(self._tool_names_for_task(binary_name, seen))
            else:
                names.append(binary_name)
        return list(dict.fromkeys(names))

    def get_commands_for_task(self, task: str, target: str, user: str = "root",
                              password: str = "", _seen: Set[str] = None) -> List[str]:
        """
        Translate a conceptual task into concrete CLI commands.
        Only returns commands whose binary is actually installed.
        """
        task = self.canonical_task(task)
        _seen = _seen or set()
        if task in _seen:
            return []
        _seen.add(task)
        entries = self.task_map.get(task, [])
        formatted_cmds = []
        skipped = []
        
        for cmd_template, binary_name in entries:
            if binary_name in self.task_map and binary_name != task:
                nested_cmds = self.get_commands_for_task(
                    binary_name, target, user=user, password=password, _seen=_seen
                )
                formatted_cmds.extend(nested_cmds)
                if not nested_cmds:
                    skipped.append(binary_name)
                continue
            if self._is_tool_available(binary_name):
                formatted_cmds.append(cmd_template.format(
                    target=target,
                    user=user,
                    password=password
                ))
            else:
                skipped.append(binary_name)
        
        if skipped:
            print(f"     [!] Skipped unavailable tools: {', '.join(skipped)}")
        
        if not formatted_cmds and entries:
            print(f"     [!] WARNING: No tools available for task '{task}'")
            
        return formatted_cmds
    
    def has_task(self, task: str) -> bool:
        """Check if a task is registered."""
        return self.canonical_task(task) in self.task_map
    
    def get_available_tools_summary(self) -> Dict[str, List[str]]:
        """Return a summary of which tools are available for which tasks."""
        summary = {}
        for task, entries in self.task_map.items():
            summary[task] = self.get_available_tools_for_task(task)
        return summary

    def get_available_tools_for_task(self, task: str) -> List[str]:
        """Return available tool names for one canonical task."""
        task = self.canonical_task(task)
        available = []
        for binary_name in self._tool_names_for_task(task):
            if self._is_tool_available(binary_name):
                available.append(binary_name)
        return available

    def task_has_available_tools(self, task: str) -> bool:
        """True when at least one command can run for the task."""
        return bool(self.get_available_tools_for_task(task))

    def get_unavailable_tools_summary(self) -> Dict[str, List[str]]:
        """Return unavailable tools per task for startup diagnostics."""
        summary = {}
        for task, entries in self.task_map.items():
            unavailable = []
            for binary_name in self._tool_names_for_task(task):
                if not self._is_tool_available(binary_name):
                    unavailable.append(binary_name)
            summary[task] = unavailable
        return summary

    def tool_execution_profile(self, tool_name: str) -> str:
        """Return how a registered tool is allowed to participate in pipeline flow."""
        return self.tool_execution_profiles.get(tool_name, "auto")

    def get_coverage_report(self, registered_tools: List[str] = None) -> Dict[str, object]:
        """Classify registry coverage without treating gated/manual tools as bugs."""
        if registered_tools is None:
            try:
                import tools  # noqa: F401 - loads @tool decorators
                from core.tools.registry import list_tools
                registered_tools = [tool_def.name for tool_def in list_tools()]
            except Exception:
                registered_tools = []

        registered = set(registered_tools)
        auto_tools = set()
        for task in self.task_map:
            auto_tools.update(self._tool_names_for_task(task))
        auto_tools &= registered

        followup_tools = {
            name for name in registered
            if self.tool_execution_profile(name) == "followup"
        }
        manual_gated = {
            name for name in registered
            if self.tool_execution_profile(name) == "manual_gated"
        }
        legacy_wrappers = {
            name for name in registered
            if self.tool_execution_profile(name) in {"legacy_wrapper", "alias_wrapper"}
        }
        covered = auto_tools | followup_tools | manual_gated | legacy_wrappers

        return {
            "registered": len(registered),
            "covered": len(covered),
            "auto": sorted(auto_tools),
            "followup": sorted(followup_tools),
            "manual_gated": sorted(manual_gated),
            "legacy_wrappers": sorted(legacy_wrappers),
            "unknown": sorted(registered - covered),
        }

    def get_discovered_plugins_summary(self) -> List[Dict[str, str]]:
        """Return metadata for class-based plugins discovered under modules/."""
        if self._plugin_summary_cache is not None:
            return self._plugin_summary_cache

        try:
            from core.plugins.loader import PluginManager
            manager = PluginManager("modules/")
            self._plugin_summary_cache = manager.list_plugins()
        except Exception:
            self._plugin_summary_cache = []

        return self._plugin_summary_cache
