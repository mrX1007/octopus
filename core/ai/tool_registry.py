#!/usr/bin/env python3

import shutil
from typing import List, Dict

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
            "web_scan": "vulnerability_assessment",
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
        }

        # Map high-level tasks to a list of potential CLI commands
        # Each entry is (command_template, binary_name_to_check)
        self.task_map = {
            "service_discovery": [
                ("nmap -Pn -sV --top-ports 1000 {target}", "nmap"),
                ("rustscan -a {target} -- -sV", "rustscan"),
            ],
            "vulnerability_assessment": [
                ("nmap -Pn -sV -sC --script=vuln {target}", "nmap"),
                ("nikto -h {target}", "nikto"),
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
            "firewall_detection": [
                ("waf_detect {target}", "waf_detect"),
            ],
            "external_intelligence": [
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
            ],
            "test_credentials": [
                ("bruteforce ssh {target}", "bruteforce"),
            ],
            "find_privesc_vectors": [
                ("ssh_session {target}", "ssh_session"),
            ],
            "exploit_privesc": [
                ("killchain_privesc {target} {user} {password}", "killchain_privesc"),
            ],
            "establish_persistence": [
                ("killchain_persist {target} {user} {password}", "killchain_persist"),
            ],
            "internal_network_recon": [
                ("network_recon {target}", "network_recon"),
            ],
            "lateral_movement": [
                ("killchain_lateral {target} {user} {password}", "killchain_lateral"),
            ],
            "exfiltrate_data": [
                ("killchain_exfil {target} {user} {password}", "killchain_exfil"),
            ],
            "stealth_cleanup": [
                ("killchain_cleanup {target} {user} {password}", "killchain_cleanup"),
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
            
        available = shutil.which(binary_name) is not None
        self._available_cache[binary_name] = available
        return available

    def get_commands_for_task(self, task: str, target: str, user: str = "root", password: str = "") -> List[str]:
        """
        Translate a conceptual task into concrete CLI commands.
        Only returns commands whose binary is actually installed.
        """
        task = self.canonical_task(task)
        entries = self.task_map.get(task, [])
        formatted_cmds = []
        skipped = []
        
        for cmd_template, binary_name in entries:
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
        for _, binary_name in self.task_map.get(task, []):
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
            for _, binary_name in entries:
                if not self._is_tool_available(binary_name):
                    unavailable.append(binary_name)
            summary[task] = unavailable
        return summary

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
