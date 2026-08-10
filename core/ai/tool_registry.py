#!/usr/bin/env python3

from __future__ import annotations

import os
import re
import shlex
import shutil
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from core.ai.evaluated_facts import fact_is_decision_usable

# The planner prompt and registry task map intentionally share this public
# inventory.  A contract test makes drift fail closed: adding a task without
# deciding whether the Planner may name it is no longer reported as autonomous
# reachability merely because its providers happen to be registered.
PLANNER_TASKS = (
    "service_discovery",
    "vulnerability_assessment",
    "exploit_selection",
    "metasploit_verification",
    "web_vulnerability_testing",
    "web_app_deep_testing",
    "web_application_mapping",
    "browser_surface_analysis",
    "web_content_discovery",
    "transport_security_assessment",
    "ftp_assessment",
    "mail_service_assessment",
    "database_inventory",
    "firewall_detection",
    "external_intelligence",
    "asm_discovery",
    "asm_http_probe",
    "asm_dns_resolution",
    "asm_port_discovery",
    "asm_url_discovery",
    "template_verification",
    "api_security_testing",
    "secrets_scanning",
    "code_security_assessment",
    "cloud_security_assessment",
    "ssh_user_enumeration",
    "windows_enumeration",
    "credential_harvesting",
    "web_credential_testing",
    "active_directory_enumeration",
    "ad_security_review",
    "bloodhound_ingest",
    "password_policy_review",
    "delegation_analysis",
    "gpo_review",
    "adcs_review",
    "local_admin_paths",
    "acl_review",
    "kerberos_assessment",
    "domain_credential_extraction",
    "ad_remote_execution",
    "hash_cracking",
    "test_credentials",
    "find_privesc_vectors",
    "post_access_inventory",
    "exploit_privesc",
    "establish_persistence",
    "payload_generation",
    "internal_network_recon",
    "internal_service_discovery",
    "pivot_setup",
    "lateral_movement",
    "exfiltrate_data",
    "stealth_cleanup",
    "plugin_assessment",
    "analyze_vulnerabilities",
)

SCAN_TARGET_INPUT = "scan_target"
NO_INPUT = "none"


@dataclass(frozen=True)
class ProviderInputContract:
    """The semantic input consumed by one concrete provider command.

    Values are resolved from trusted facts or explicit operator configuration
    before command formatting.  The contract deliberately describes semantic
    kinds, not Python keyword arguments, so it cannot become a raw-kwargs bypass
    around the action catalog or execution policy.
    """

    kind: str = SCAN_TARGET_INPUT
    sources: tuple[str, ...] = ("scan_target",)


_PROVIDER_INPUT_CONTRACTS = {
    "session_profile_import": ProviderInputContract("session_profile", ("fact", "configuration")),
    "jwt_analyze": ProviderInputContract("jwt_artifact", ("fact", "configuration")),
    "burp_import": ProviderInputContract("burp_export", ("fact", "configuration")),
    "zap_import": ProviderInputContract("zap_export", ("fact", "configuration")),
    "openapi_import": ProviderInputContract("openapi_spec", ("fact", "configuration")),
    "gitleaks_scan": ProviderInputContract("filesystem_scope", ("configuration",)),
    "trufflehog_scan": ProviderInputContract("filesystem_scope", ("configuration",)),
    "semgrep_scan": ProviderInputContract("filesystem_scope", ("configuration",)),
    "trivy_scan": ProviderInputContract("filesystem_scope", ("configuration",)),
    "checkov_scan": ProviderInputContract("filesystem_scope", ("configuration",)),
    "prowler_scan": ProviderInputContract("cloud_provider", ("fact", "configuration")),
    "scoutsuite_scan": ProviderInputContract("cloud_provider", ("fact", "configuration")),
    "build_go_implant": ProviderInputContract(NO_INPUT, ("tool_default",)),
    "build_python_implant": ProviderInputContract(NO_INPUT, ("tool_default",)),
    "build_ps_stager": ProviderInputContract(NO_INPUT, ("tool_default",)),
    "plugin_inventory": ProviderInputContract(NO_INPUT, ("plugin_discovery",)),
}

_CONFIGURED_INPUT_KEYS = {
    "session_profiles": "session_profile",
    "jwt_artifacts": "jwt_artifact",
    "burp_exports": "burp_export",
    "zap_exports": "zap_export",
    "openapi_specs": "openapi_spec",
    "cloud_providers": "cloud_provider",
    "filesystem_scopes": "filesystem_scope",
}

_FACT_INPUT_KINDS = {
    "session_profile": "session_profile",
    "session_profile_path": "session_profile",
    "jwt_artifact": "jwt_artifact",
    "burp_export": "burp_export",
    "zap_export": "zap_export",
    "openapi_spec": "openapi_spec",
    "openapi_spec_path": "openapi_spec",
    "openapi_spec_url": "openapi_spec",
    "cloud_provider": "cloud_provider",
}

_PATH_INPUT_KINDS = frozenset(
    {
        "session_profile",
        "jwt_artifact",
        "burp_export",
        "zap_export",
        "filesystem_scope",
    }
)
_CLOUD_PROVIDERS = frozenset({"aws", "azure", "gcp", "kubernetes", "m365"})
_OPENAPI_URL_RE = re.compile(r"(?i)(?:openapi|swagger|api-docs)(?:\.(?:json|ya?ml))?(?:[/?#]|$)")


class ToolRegistry:
    def __init__(self, plugin_manager_provider: Callable[[], Any] | None = None):
        self._plugin_manager_provider = plugin_manager_provider
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
            "internal_vulnerability_assessment": "vulnerability_assessment",
            "execute_vulnerability_checks": "vulnerability_assessment",
            "run_vulnerability_checks": "vulnerability_assessment",
            "prioritize_high_value_targets": "analyze_vulnerabilities",
            "validate_findings": "metasploit_verification",
            "map_attack_paths": "exploit_selection",
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
            "web_app_deep_testing": "web_app_deep_testing",
            "web_security_review": "web_app_deep_testing",
            "security_headers": "web_app_deep_testing",
            "cors": "web_app_deep_testing",
            "csrf": "web_app_deep_testing",
            "jwt": "web_app_deep_testing",
            "session_import": "web_app_deep_testing",
            "session_profile_import": "web_app_deep_testing",
            "authenticated_crawl": "web_app_deep_testing",
            "auth_crawl": "web_app_deep_testing",
            "burp": "web_app_deep_testing",
            "burp_import": "web_app_deep_testing",
            "zap": "web_app_deep_testing",
            "zap_import": "web_app_deep_testing",
            "js_route_extraction": "web_app_deep_testing",
            "js_route_extract": "web_app_deep_testing",
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
            "asm": "asm_discovery",
            "asm_discovery": "asm_discovery",
            "asset_inventory": "asm_discovery",
            "attack_surface_management": "asm_discovery",
            "subdomain_discovery": "asm_discovery",
            "subfinder": "asm_discovery",
            "amass": "asm_discovery",
            "httpx": "asm_http_probe",
            "http_probe": "asm_http_probe",
            "dnsx": "asm_dns_resolution",
            "dns_resolution": "asm_dns_resolution",
            "naabu": "asm_port_discovery",
            "passive_url_discovery": "asm_url_discovery",
            "wayback": "asm_url_discovery",
            "gau": "asm_url_discovery",
            "nuclei": "template_verification",
            "nuclei_safe": "template_verification",
            "template_verification": "template_verification",
            "api_security": "api_security_testing",
            "api_security_testing": "api_security_testing",
            "openapi": "api_security_testing",
            "swagger": "api_security_testing",
            "graphql": "api_security_testing",
            "api_auth_check": "api_security_testing",
            "missing_auth_check": "api_security_testing",
            "secrets": "secrets_scanning",
            "secret_scan": "secrets_scanning",
            "secrets_scanning": "secrets_scanning",
            "gitleaks": "secrets_scanning",
            "trufflehog": "secrets_scanning",
            "code_security": "code_security_assessment",
            "sca": "code_security_assessment",
            "dependency_scan": "code_security_assessment",
            "semgrep": "code_security_assessment",
            "trivy": "code_security_assessment",
            "checkov": "code_security_assessment",
            "cloud_security": "cloud_security_assessment",
            "cloud_security_assessment": "cloud_security_assessment",
            "prowler": "cloud_security_assessment",
            "scoutsuite": "cloud_security_assessment",
            "ssh_enumeration": "ssh_user_enumeration",
            "enumerate_ssh_users": "ssh_user_enumeration",
            "ssh_inventory": "post_access_inventory",
            "ssh_inventory_deep_dive": "post_access_inventory",
            "deep_dive_ssh_inventory": "post_access_inventory",
            "map_internal_ports": "internal_service_discovery",
            "internal_services": "internal_service_discovery",
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
            "ad_security": "ad_security_review",
            "ad_security_review": "ad_security_review",
            "ad_review": "ad_security_review",
            "bloodhound": "bloodhound_ingest",
            "bloodhound_ingest": "bloodhound_ingest",
            "sharphound": "bloodhound_ingest",
            "sharphound_ingest": "bloodhound_ingest",
            "ldap_enumeration": "active_directory_enumeration",
            "ldap_review": "active_directory_enumeration",
            "password_policy": "password_policy_review",
            "password_policy_review": "password_policy_review",
            "delegation": "delegation_analysis",
            "delegation_analysis": "delegation_analysis",
            "gpo": "gpo_review",
            "gpo_review": "gpo_review",
            "adcs": "adcs_review",
            "adcs_review": "adcs_review",
            "local_admin_paths": "local_admin_paths",
            "acl_review": "acl_review",
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
            "internal_service_discovery": "internal_service_discovery",
            "internal_service_probe": "internal_service_discovery",
            "lateral": "lateral_movement",
            "lateral_move": "lateral_movement",
            "lateral_movement": "lateral_movement",
            "exfil": "exfiltrate_data",
            "data_exfil": "exfiltrate_data",
            "cleanup": "stealth_cleanup",
            "killchain_vuln_assess": "vulnerability_assessment",
            "killchain_vuln": "vulnerability_assessment",
            "killchain_exploit": "exploit_selection",
            "auto_exploit": "exploit_selection",
            "controlled_ssh_inventory": "post_access_inventory",
            "post_access_inventory": "post_access_inventory",
        }

        # Execution profiles make registry coverage explicit without silently
        # scheduling invasive actions. Auto tasks are normal pipeline commands,
        # follow-up tasks are only run when emitted as verification facts, and
        # manual/gated tasks remain callable from the CLI with explicit intent.
        self.tool_execution_profiles = {
            "cve_lookup": "followup",
            "msf_check": "followup",
            "plugin": "auto",
            "plugin_inventory": "auto",
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

        self.task_profiles = {
            "service_discovery": {"cost": 2, "time": "medium", "risk": "safe", "preconditions": []},
            "vulnerability_assessment": {"cost": 5, "time": "long", "risk": "active", "preconditions": ["services"]},
            "exploit_selection": {"cost": 1, "time": "short", "risk": "passive", "preconditions": ["services"]},
            "metasploit_verification": {
                "cost": 4,
                "time": "medium",
                "risk": "check_only",
                "preconditions": ["services"],
            },
            "web_application_mapping": {"cost": 1, "time": "short", "risk": "passive", "preconditions": ["web"]},
            "browser_surface_analysis": {"cost": 2, "time": "short", "risk": "passive", "preconditions": ["web"]},
            "web_app_deep_testing": {"cost": 2, "time": "short", "risk": "safe", "preconditions": ["web"]},
            "web_content_discovery": {"cost": 3, "time": "medium", "risk": "safe", "preconditions": ["web"]},
            "template_verification": {"cost": 5, "time": "long", "risk": "safe", "preconditions": ["web"]},
            "web_vulnerability_testing": {"cost": 6, "time": "long", "risk": "active", "preconditions": ["web"]},
            "api_security_testing": {"cost": 3, "time": "medium", "risk": "safe", "preconditions": ["web"]},
            "secrets_scanning": {"cost": 3, "time": "medium", "risk": "safe", "preconditions": []},
            "code_security_assessment": {"cost": 4, "time": "long", "risk": "safe", "preconditions": []},
            "cloud_security_assessment": {"cost": 5, "time": "long", "risk": "post_access_read", "preconditions": []},
            "transport_security_assessment": {"cost": 2, "time": "short", "risk": "passive", "preconditions": ["tls"]},
            "ftp_assessment": {"cost": 2, "time": "short", "risk": "active", "preconditions": ["services"]},
            "mail_service_assessment": {"cost": 1, "time": "short", "risk": "safe", "preconditions": ["services"]},
            "database_inventory": {
                "cost": 3,
                "time": "medium",
                "risk": "post_access_read",
                "preconditions": ["services", "access"],
            },
            "firewall_detection": {"cost": 2, "time": "short", "risk": "safe", "preconditions": ["web"]},
            "external_intelligence": {"cost": 1, "time": "short", "risk": "passive", "preconditions": []},
            "asm_discovery": {"cost": 3, "time": "medium", "risk": "passive", "preconditions": ["domain"]},
            "asm_http_probe": {"cost": 2, "time": "short", "risk": "active", "preconditions": ["domain"]},
            "asm_dns_resolution": {"cost": 1, "time": "short", "risk": "safe", "preconditions": ["domain"]},
            "asm_port_discovery": {"cost": 3, "time": "medium", "risk": "active", "preconditions": ["domain"]},
            "asm_url_discovery": {"cost": 1, "time": "short", "risk": "passive", "preconditions": ["domain"]},
            "active_directory_enumeration": {
                "cost": 3,
                "time": "medium",
                "risk": "safe",
                "preconditions": ["ad_surface"],
            },
            "ad_security_review": {"cost": 4, "time": "medium", "risk": "safe", "preconditions": ["ad_surface"]},
            "bloodhound_ingest": {
                "cost": 4,
                "time": "long",
                "risk": "post_access_read",
                "preconditions": ["ad_surface", "access"],
            },
            "password_policy_review": {
                "cost": 2,
                "time": "short",
                "risk": "post_access_read",
                "preconditions": ["ad_surface", "access"],
            },
            "delegation_analysis": {
                "cost": 4,
                "time": "long",
                "risk": "post_access_read",
                "preconditions": ["ad_surface", "access"],
            },
            "gpo_review": {
                "cost": 3,
                "time": "medium",
                "risk": "post_access_read",
                "preconditions": ["ad_surface", "access"],
            },
            "adcs_review": {
                "cost": 3,
                "time": "medium",
                "risk": "post_access_read",
                "preconditions": ["ad_surface", "access"],
            },
            "local_admin_paths": {
                "cost": 4,
                "time": "long",
                "risk": "post_access_read",
                "preconditions": ["ad_surface", "access"],
            },
            "acl_review": {
                "cost": 4,
                "time": "long",
                "risk": "post_access_read",
                "preconditions": ["ad_surface", "access"],
            },
            "windows_enumeration": {"cost": 3, "time": "medium", "risk": "safe", "preconditions": ["smb"]},
            "kerberos_assessment": {"cost": 3, "time": "medium", "risk": "safe", "preconditions": ["ad_surface"]},
            "domain_credential_extraction": {
                "cost": 6,
                "time": "long",
                "risk": "active",
                "preconditions": ["ad_surface", "access", "stage:credentials"],
            },
            "ad_remote_execution": {
                "cost": 6,
                "time": "long",
                "risk": "post_access_change",
                "preconditions": ["ad_surface", "access", "internal_services", "stage:root"],
            },
            "hash_cracking": {"cost": 5, "time": "long", "risk": "active", "preconditions": ["access"]},
            "test_credentials": {"cost": 5, "time": "long", "risk": "active", "preconditions": ["services", "ssh"]},
            "ssh_user_enumeration": {"cost": 2, "time": "short", "risk": "safe", "preconditions": ["ssh"]},
            "credential_harvesting": {"cost": 4, "time": "medium", "risk": "active", "preconditions": ["services"]},
            "web_credential_testing": {"cost": 4, "time": "medium", "risk": "active", "preconditions": ["web"]},
            "post_access_inventory": {
                "cost": 2,
                "time": "short",
                "risk": "post_access_read",
                "preconditions": ["access"],
            },
            "find_privesc_vectors": {
                "cost": 3,
                "time": "medium",
                "risk": "post_access_read",
                "preconditions": ["access"],
            },
            "exploit_privesc": {
                "cost": 6,
                "time": "long",
                "risk": "post_access_change",
                "preconditions": ["access", "stage:credentials", "killchain:privesc"],
            },
            "internal_network_recon": {
                "cost": 2,
                "time": "short",
                "risk": "post_access_read",
                "preconditions": ["access"],
            },
            "internal_service_discovery": {
                "cost": 2,
                "time": "short",
                "risk": "post_access_read",
                "preconditions": ["internal_hosts"],
            },
            "pivot_setup": {"cost": 4, "time": "medium", "risk": "post_access_change", "preconditions": ["access"]},
            "payload_generation": {"cost": 2, "time": "short", "risk": "local_build", "preconditions": []},
            "establish_persistence": {
                "cost": 6,
                "time": "medium",
                "risk": "post_access_change",
                "preconditions": ["access"],
            },
            "lateral_movement": {"cost": 6, "time": "long", "risk": "active", "preconditions": ["internal_services"]},
            "exfiltrate_data": {"cost": 6, "time": "long", "risk": "post_access_read", "preconditions": ["access"]},
            "stealth_cleanup": {"cost": 5, "time": "medium", "risk": "post_access_change", "preconditions": ["access"]},
            "plugin_assessment": {"cost": 1, "time": "short", "risk": "passive", "preconditions": []},
            "analyze_vulnerabilities": {"cost": 1, "time": "short", "risk": "passive", "preconditions": ["services"]},
        }

        # Map high-level tasks to a list of potential CLI commands
        # Each entry is (command_template, binary_name_to_check)
        self.task_map = {
            "service_discovery": [
                ("nmap -Pn -sV --top-ports 1000 {target}", "nmap"),
                (
                    "nmap -Pn -sV -p 8443,8080,3000,3030,9000,5432,465,587,993,995,110,143,21 {target}",
                    "nmap",
                ),
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
            "web_app_deep_testing": [
                ("session_profile_import {session_profile}", "session_profile_import"),
                ("security_headers_check {target}", "security_headers_check"),
                ("cors_check {target}", "cors_check"),
                ("jwt_analyze {jwt_artifact}", "jwt_analyze"),
                ("js_route_extract {target}", "js_route_extract"),
                ("authenticated_crawl {target}", "authenticated_crawl"),
                ("burp_import {burp_export}", "burp_import"),
                ("zap_import {zap_export}", "zap_import"),
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
                ("gobuster {target}", "gobuster"),
                ("dirb {target}", "dirb"),
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
                ("web_search {target}", "web_search"),
            ],
            "asm_discovery": [
                ("subfinder {target}", "subfinder"),
                ("amass_enum {target}", "amass_enum"),
                ("dnsx {target}", "dnsx"),
                ("httpx_probe {target}", "httpx_probe"),
                ("naabu {target}", "naabu"),
                ("tlsx {target}", "tlsx"),
                ("wayback_urls {target}", "wayback_urls"),
                ("gau_urls {target}", "gau_urls"),
            ],
            "asm_http_probe": [
                ("httpx_probe {target}", "httpx_probe"),
            ],
            "asm_dns_resolution": [
                ("dnsx {target}", "dnsx"),
            ],
            "asm_port_discovery": [
                ("naabu {target}", "naabu"),
            ],
            "asm_url_discovery": [
                ("wayback_urls {target}", "wayback_urls"),
                ("gau_urls {target}", "gau_urls"),
            ],
            "template_verification": [
                ("nuclei_safe {target}", "nuclei_safe"),
            ],
            "api_security_testing": [
                ("openapi_import {openapi_spec}", "openapi_import"),
                ("graphql_check {target}", "graphql_check"),
                ("api_auth_check {target}", "api_auth_check"),
                ("katana_crawl {target}", "katana_crawl"),
            ],
            "secrets_scanning": [
                ("gitleaks_scan {filesystem_scope}", "gitleaks_scan"),
                ("trufflehog_scan {filesystem_scope}", "trufflehog_scan"),
            ],
            "code_security_assessment": [
                ("semgrep_scan {filesystem_scope}", "semgrep_scan"),
                ("trivy_scan {filesystem_scope}", "trivy_scan"),
                ("checkov_scan {filesystem_scope}", "checkov_scan"),
            ],
            "cloud_security_assessment": [
                ("prowler_scan {cloud_provider}", "prowler_scan"),
                ("scoutsuite_scan {cloud_provider}", "scoutsuite_scan"),
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
            "ad_security_review": [
                ("ad_enum {target}", "ad_enum"),
                ("bloodhound_ingest {target}", "bloodhound_ingest"),
                ("gpo_review {target}", "gpo_review"),
            ],
            "bloodhound_ingest": [
                ("bloodhound_ingest {target}", "bloodhound_ingest"),
            ],
            "password_policy_review": [
                ("ad_enum {target}", "ad_enum"),
            ],
            "delegation_analysis": [
                ("ad_enum {target}", "ad_enum"),
                ("bloodhound_ingest {target}", "bloodhound_ingest"),
            ],
            "gpo_review": [
                ("gpo_review {target}", "gpo_review"),
            ],
            "adcs_review": [
                ("adcs_review {target}", "adcs_review"),
            ],
            "local_admin_paths": [
                ("bloodhound_ingest {target}", "bloodhound_ingest"),
            ],
            "acl_review": [
                ("bloodhound_ingest {target}", "bloodhound_ingest"),
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
            "internal_service_discovery": [
                ("internal_service_probe {target}", "internal_service_probe"),
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
            "plugin_assessment": [
                ("plugin_inventory", "plugin_inventory"),
            ],
            "analyze_vulnerabilities": [
                # AnalysisAgent doesn't run CLI tools — this is handled by the agent itself
            ],
        }

        # Cache of available tools (checked once)
        self._available_cache: dict[str, bool] = {}
        self._plugin_summary_cache: list[dict[str, Any]] | None = None

    def provider_input_contract(self, provider: str) -> ProviderInputContract:
        """Return the declared semantic input for one canonical provider."""

        return _PROVIDER_INPUT_CONTRACTS.get(str(provider or "").strip(), ProviderInputContract())

    @staticmethod
    def _configured_input_values(value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            candidates: Iterable[Any] = (value,)
        elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
            candidates = value
        else:
            return ()
        result: list[str] = []
        for candidate in candidates:
            if not isinstance(candidate, str):
                continue
            normalized = candidate.strip()
            if normalized and normalized not in result:
                result.append(normalized)
        return tuple(result)

    @staticmethod
    def _resolved_directory(path: str) -> str:
        try:
            resolved = Path(path).expanduser().resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            return ""
        return str(resolved) if resolved.is_dir() else ""

    @staticmethod
    def _resolved_file(path: str) -> str:
        try:
            resolved = Path(path).expanduser().resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            return ""
        return str(resolved) if resolved.is_file() else ""

    @staticmethod
    def _path_is_within(path: str, roots: Sequence[str]) -> bool:
        for root in roots:
            try:
                if os.path.commonpath((path, root)) == root:
                    return True
            except (OSError, ValueError):
                continue
        return False

    @staticmethod
    def _url_in_scope(value: str, target: str) -> bool:
        if not value.startswith(("http://", "https://")):
            return False
        try:
            from core.tools.targeting import endpoint_in_target_scope

            return endpoint_in_target_scope(value, target)
        except (ImportError, TypeError, ValueError):
            return False

    @classmethod
    def _openapi_url_in_scope(cls, value: str, target: str) -> bool:
        return bool(_OPENAPI_URL_RE.search(value)) and cls._url_in_scope(value, target)

    def resolve_task_inputs(
        self,
        target: str,
        facts: Iterable[Mapping[str, Any]] = (),
        configured_inputs: Mapping[str, Any] | None = None,
    ) -> dict[str, tuple[str, ...]]:
        """Resolve typed autonomous inputs without treating the scan target as data.

        Filesystem access is configuration-authorized: a path fact can select an
        artifact only when it resolves beneath one of ``filesystem_scopes``.
        Cloud provider facts/configuration are closed over the providers supported
        by the mounted scanners.  OpenAPI URLs must remain in the network scan
        scope.  Raw JWT values are intentionally not put into command strings;
        ``jwt_artifact`` is the supported autonomous boundary.
        """

        configured = configured_inputs if isinstance(configured_inputs, Mapping) else {}
        resolved: dict[str, list[str]] = {}

        def add(kind: str, value: str) -> None:
            bucket = resolved.setdefault(kind, [])
            if value and value not in bucket:
                bucket.append(value)

        configured_roots = tuple(
            value
            for raw in self._configured_input_values(configured.get("filesystem_scopes"))
            if (value := self._resolved_directory(raw))
        )
        for root in configured_roots:
            add("filesystem_scope", root)

        candidates: list[tuple[str, str]] = []
        for config_key, kind in _CONFIGURED_INPUT_KEYS.items():
            if kind == "filesystem_scope":
                continue
            candidates.extend((kind, value) for value in self._configured_input_values(configured.get(config_key)))

        for fact in facts or ():
            if not isinstance(fact, Mapping) or not fact_is_decision_usable(fact):
                continue
            fact_type = str(fact.get("type") or "").strip().casefold()
            value = str(fact.get("value") or "").strip()
            if not value:
                continue
            fact_kind = _FACT_INPUT_KINDS.get(fact_type)
            if fact_kind:
                candidates.append((fact_kind, value))
            elif fact_type == "web_link" and self._openapi_url_in_scope(value, target):
                candidates.append(("openapi_spec", value))

        for kind, raw_value in candidates:
            value = raw_value.strip()
            if kind == "cloud_provider":
                provider = value.casefold()
                if provider in _CLOUD_PROVIDERS:
                    add(kind, provider)
                continue
            # Values already declared as ``openapi_spec`` are semantic typed
            # inputs and may use an arbitrary filename. Only generic web_link
            # discovery relies on the OpenAPI/Swagger pathname heuristic above.
            if kind == "openapi_spec" and self._url_in_scope(value, target):
                add(kind, value)
                continue
            path = self._resolved_file(value) if kind == "openapi_spec" or kind in _PATH_INPUT_KINDS else ""
            if path and configured_roots and self._path_is_within(path, configured_roots):
                add(kind, path)

        return {kind: tuple(values) for kind, values in sorted(resolved.items())}

    def _input_values_for_provider(
        self,
        provider: str,
        target: str,
        task_inputs: Mapping[str, Sequence[str]],
    ) -> tuple[str, ...]:
        contract = self.provider_input_contract(provider)
        if contract.kind == NO_INPUT:
            return ("",)
        if contract.kind == SCAN_TARGET_INPUT:
            normalized_target = str(target or "").strip()
            return (normalized_target,) if normalized_target else ()
        values = self._configured_input_values(task_inputs.get(contract.kind))
        if provider == "scoutsuite_scan":
            values = tuple(value for value in values if value in {"aws", "azure", "gcp"})
        return values

    def _leaf_provider_entries(
        self,
        task: str,
        seen: set[str] | None = None,
    ) -> list[tuple[str, str]]:
        task = self.canonical_task(task)
        seen = set(seen or ())
        if task in seen:
            return []
        seen.add(task)
        entries: list[tuple[str, str]] = []
        for command_template, provider in self.task_map.get(task, []):
            if provider in self.task_map and provider != task:
                entries.extend(self._leaf_provider_entries(provider, seen))
            else:
                entries.append((command_template, provider))
        return entries

    def get_task_input_readiness(
        self,
        task: str,
        target: str,
        task_inputs: Mapping[str, Sequence[str]] | None = None,
    ) -> dict[str, Any]:
        """Describe input reachability independently from provider availability."""

        task = self.canonical_task(task)
        inputs = task_inputs if isinstance(task_inputs, Mapping) else {}
        providers = []
        ready_count = 0
        missing: list[str] = []
        for _template, provider in self._leaf_provider_entries(task):
            contract = self.provider_input_contract(provider)
            values = self._input_values_for_provider(provider, target, inputs)
            ready = bool(values)
            ready_count += int(ready)
            if not ready and contract.kind not in missing:
                missing.append(contract.kind)
            providers.append(
                {
                    "provider": provider,
                    "input_kind": contract.kind,
                    "input_sources": list(contract.sources),
                    "ready": ready,
                    "resolved_count": len(values) if contract.kind != NO_INPUT else 0,
                }
            )
        if not providers and task == "analyze_vulnerabilities":
            state = "agent_owned"
        elif not providers or ready_count == 0:
            state = "blocked_by_input"
        elif ready_count == len(providers):
            state = "ready"
        else:
            state = "partial"
        return {
            "task": task,
            "state": state,
            "ready_providers": ready_count,
            "provider_count": len(providers),
            "missing_input_kinds": missing,
            "providers": providers,
        }

    def get_discovered_plugin_action_reachability(
        self,
        target: str = "",
        plugin_inputs: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Expose safe plugin action candidates only after typed inputs resolve.

        Discovery metadata supplies the closed ``input_schema``. Operator-owned
        values remain outside this report; only parameter names and validation
        state are returned. Runtime and ``PluginActionAdapter`` still perform the
        authoritative parse/validation immediately before provider invocation.
        """

        from core.plugins.schema import empty_input_schema, normalize_input_schema, validate_input_parameters

        supplied_by_plugin = plugin_inputs if isinstance(plugin_inputs, Mapping) else {}
        active_types = {"evasion", "exploit", "lateral", "persistence", "post"}
        rows: list[dict[str, Any]] = []
        for record in self.get_discovered_plugins_summary():
            if not isinstance(record, Mapping):
                continue
            name = str(record.get("name") or "").strip()
            if not name:
                continue
            try:
                schema = normalize_input_schema(record.get("input_schema", empty_input_schema()))
            except ValueError:
                continue
            raw_parameters = supplied_by_plugin.get(name, {})
            parameters = dict(raw_parameters) if isinstance(raw_parameters, Mapping) else {}
            properties = schema["properties"]
            required = list(schema["required"])
            missing = [parameter for parameter in required if parameter not in parameters]
            undeclared = sorted(set(parameters) - set(properties))
            validation_error = ""
            if not missing and not undeclared:
                try:
                    validate_input_parameters(schema, parameters)
                except ValueError as exc:
                    validation_error = str(exc)
            input_state = "ready"
            if not str(target or "").strip():
                input_state = "blocked_by_target"
            elif missing or undeclared or validation_error:
                input_state = "blocked_by_input"
            plugin_type = str(record.get("type") or "").strip().casefold()
            supports_check = record.get("supports_check") is True
            actions = (["check"] if supports_check else []) + (["run"] if plugin_type in active_types else ["scan"])
            rows.append(
                {
                    "action_id": f"plugin:{name}",
                    "plugin": name,
                    "plugin_type": plugin_type,
                    "actions": actions,
                    "supports_check": supports_check,
                    "input_state": input_state,
                    "planner_visible": input_state == "ready",
                    "required_parameter_names": required,
                    "resolved_parameter_names": sorted(set(parameters).intersection(properties)),
                    "missing_parameter_names": missing,
                    "undeclared_parameter_names": undeclared,
                    "validation_error": validation_error,
                    "input_schema": {
                        parameter: {key: value for key, value in property_schema.items() if key in {"format", "type"}}
                        for parameter, property_schema in properties.items()
                    },
                }
            )
        return rows

    def get_reachability_report(
        self,
        target: str = "",
        task_inputs: Mapping[str, Sequence[str]] | None = None,
        plugin_inputs: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Report planner routing and typed-input readiness without conflating coverage."""

        allowed = frozenset(PLANNER_TASKS)
        task_rows = []
        for task in self.task_map:
            readiness = self.get_task_input_readiness(task, target, task_inputs)
            routes = ["planner_prompt"] if task in allowed else []
            task_rows.append(
                {
                    "task": task,
                    "routes": routes,
                    "planner_allowed": bool(routes),
                    "input_state": readiness["state"],
                    "missing_input_kinds": readiness["missing_input_kinds"],
                    "provider_count": readiness["provider_count"],
                    "ready_providers": readiness["ready_providers"],
                }
            )
        unreachable = [row["task"] for row in task_rows if not row["routes"]]
        blocked = [row["task"] for row in task_rows if row["input_state"] == "blocked_by_input"]
        plugin_actions = (
            self.get_discovered_plugin_action_reachability(target, plugin_inputs) if plugin_inputs is not None else []
        )
        return {
            "task_map_total": len(self.task_map),
            "planner_allowed_total": len(allowed.intersection(self.task_map)),
            "routed_total": len(task_rows) - len(unreachable),
            "unreachable": unreachable,
            "blocked_by_input": blocked,
            "tasks": task_rows,
            "plugin_actions": plugin_actions,
            "planner_visible_plugin_actions": [row["action_id"] for row in plugin_actions if row["planner_visible"]],
        }

    def canonical_task(self, task: str) -> str:
        """Return the canonical registry task for a planner/agent task name."""
        key = (task or "").strip().lower().replace("-", "_").replace(" ", "_")
        return self.task_aliases.get(key, key)

    def task_profile(self, task: str) -> dict[str, Any]:
        """Return scheduling metadata for a canonical task."""
        task = self.canonical_task(task)
        return dict(
            self.task_profiles.get(
                task,
                {"cost": 5, "time": "medium", "risk": "unknown", "preconditions": []},
            )
        )

    def _is_tool_available(self, binary_name: str) -> bool:
        """Check if a CLI tool is installed and available in PATH or internally."""
        if binary_name in self._available_cache:
            return self._available_cache[binary_name]

        try:
            from core.tools.registry import get_tool

            tool_def = get_tool(binary_name)
            if tool_def is not None:
                # If it's a registered tool, check its internal availability (which checks 'requires')
                available = bool(getattr(tool_def, "enabled", True)) and tool_def.is_available()
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
            available = bool(child_binaries) and any(
                self._is_tool_available(entry_binary) for entry_binary in child_binaries
            )
            self._available_cache[binary_name] = available
            return available

        available = shutil.which(binary_name) is not None
        self._available_cache[binary_name] = available
        return available

    def _tool_names_for_task(self, task: str, seen: set[str] | None = None) -> list[str]:
        """Expand a task into enabled concrete tool names, including nested tasks."""
        from core.tools.registry import get_tool

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
                tool_def = get_tool(binary_name)
                if tool_def is not None and not bool(getattr(tool_def, "enabled", True)):
                    continue
                names.append(binary_name)
        return list(dict.fromkeys(names))

    def get_commands_for_task(
        self,
        task: str,
        target: str = "",
        user: str = "",
        password: str = "",
        task_inputs: Mapping[str, Any] | None = None,
        _seen: set[str] | None = None,
    ) -> list[str]:
        """Expand available providers for a task into command strings.

        A network scan target is only formatted into providers declaring
        ``scan_target``.  Artifact, token-file, cloud, and filesystem providers
        are omitted until their own input kind has been resolved.
        """
        if password:
            print("     [!] Credential-bearing command expansion is disabled.")
            return []
        task = self.canonical_task(task)
        if task.startswith("plugin:"):
            plugin_name = task.split(":", 1)[1]
            if self._is_tool_available("plugin"):
                target_str = shlex.quote(str(target or ""))
                cmd_tokens = ["plugin", plugin_name]
                if target_str:
                    cmd_tokens.append(target_str)
                cmd_tokens.append("scan")
                if task_inputs and isinstance(task_inputs, Mapping):
                    p_actions = task_inputs.get("plugin_actions") or []
                    if isinstance(p_actions, Sequence):
                        for item in p_actions:
                            if isinstance(item, Mapping) and item.get("plugin") == plugin_name:
                                for k, v in item.items():
                                    if k not in {"plugin", "target", "action"}:
                                        cmd_tokens.append(f"{k}={shlex.quote(str(v))}")
                return [shlex.join(cmd_tokens)]
            return []
        _seen = _seen or set()
        if task in _seen:
            return []
        _seen.add(task)
        entries = self.task_map.get(task, [])
        formatted_cmds = []
        skipped = []
        skipped_inputs = []
        inputs = task_inputs if isinstance(task_inputs, Mapping) else {}

        for cmd_template, binary_name in entries:
            if binary_name in self.task_map and binary_name != task:
                nested_cmds = self.get_commands_for_task(
                    binary_name,
                    target,
                    user=user,
                    task_inputs=inputs,
                    _seen=_seen,
                )
                formatted_cmds.extend(nested_cmds)
                if not nested_cmds:
                    skipped.append(binary_name)
            else:
                if self._is_tool_available(binary_name):
                    values = self._input_values_for_provider(binary_name, target, inputs)
                    if not values:
                        skipped_inputs.append(f"{binary_name}:{self.provider_input_contract(binary_name).kind}")
                        continue
                    for value in values:
                        format_values = {
                            "target": shlex.quote(str(target or "")),
                            "user": shlex.quote(str(user or "")),
                            self.provider_input_contract(binary_name).kind: shlex.quote(value),
                        }
                        try:
                            command = cmd_template.format_map(format_values).strip()
                        except KeyError:
                            skipped_inputs.append(f"{binary_name}:invalid_input_contract")
                            continue
                        if command and command not in formatted_cmds:
                            formatted_cmds.append(command)
                else:
                    skipped.append(binary_name)

        if skipped:
            print(f"     [!] Skipped unavailable tools: {', '.join(skipped)}")
        if skipped_inputs:
            print(f"     [i] Skipped providers awaiting typed input: {', '.join(skipped_inputs)}")

        if not formatted_cmds and entries:
            print(f"     [!] WARNING: No tools available for task '{task}'")

        return formatted_cmds

    def has_task(self, task: str) -> bool:
        """Check if a task is registered."""
        canon = self.canonical_task(task)
        if canon in self.task_map:
            return True
        if canon.startswith("plugin:"):
            plugin_name = canon.split(":", 1)[1]
            return any(
                isinstance(r, Mapping) and str(r.get("name")) == plugin_name
                for r in self.get_discovered_plugins_summary()
            )
        return False

    def get_available_tools_summary(self) -> dict[str, list[str]]:
        """Return a summary of which tools are available for which tasks."""
        summary = {}
        for task, _entries in self.task_map.items():
            summary[task] = self.get_available_tools_for_task(task)
        return summary

    def get_available_tools_for_task(self, task: str) -> list[str]:
        """Return available tool names for one canonical task."""
        task = self.canonical_task(task)
        if task.startswith("plugin:"):
            return ["plugin"] if self._is_tool_available("plugin") else []
        available = []
        for binary_name in self._tool_names_for_task(task):
            if self._is_tool_available(binary_name):
                available.append(binary_name)
        return available

    def get_provider_statuses_for_task(self, task: str) -> list[dict[str, Any]]:
        """Describe concrete providers for a task without invoking them.

        Nested task aliases are expanded to the same leaf command templates
        used by :meth:`get_commands_for_task`.  Availability is read from the
        existing registry/dependency checks; this method deliberately does not
        format credentials or dispatch a command.
        """
        task = self.canonical_task(task)
        if task.startswith("plugin:"):
            plugin_name = task.split(":", 1)[1]
            return [
                {
                    "task": task,
                    "provider": "plugin",
                    "command_template": f"plugin {plugin_name} {{target}} scan",
                    "available": self._is_tool_available("plugin"),
                }
            ]
        return self._provider_statuses_for_task(task, set(), task)

    def _provider_statuses_for_task(
        self,
        task: str,
        seen: set[str],
        requested_task: str,
    ) -> list[dict[str, Any]]:
        task = self.canonical_task(task)
        if task in seen:
            return []
        seen = set(seen)
        seen.add(task)

        statuses: list[dict[str, Any]] = []
        for command_template, provider in self.task_map.get(task, []):
            if provider in self.task_map and provider != task:
                statuses.extend(self._provider_statuses_for_task(provider, seen, requested_task))
            else:
                statuses.append(
                    {
                        "task": requested_task,
                        "provider": provider,
                        "command_template": command_template,
                        "available": self._is_tool_available(provider),
                    }
                )

        deduplicated: list[dict[str, Any]] = []
        seen_records: set[tuple[str, str, str]] = set()
        for status in statuses:
            key = (
                str(status.get("task", "")),
                str(status.get("provider", "")),
                str(status.get("command_template", "")),
            )
            if key in seen_records:
                continue
            seen_records.add(key)
            deduplicated.append(status)
        return deduplicated

    def task_has_available_tools(self, task: str) -> bool:
        """True when at least one command can run for the task."""
        return bool(self.get_available_tools_for_task(task))

    def get_unavailable_tools_summary(self) -> dict[str, list[str]]:
        """Return unavailable tools per task for startup diagnostics."""
        summary = {}
        for task, _entries in self.task_map.items():
            unavailable = []
            for binary_name in self._tool_names_for_task(task):
                if not self._is_tool_available(binary_name):
                    unavailable.append(binary_name)
            summary[task] = unavailable
        return summary

    def tool_execution_profile(self, tool_name: str) -> str:
        """Return how a registered tool is allowed to participate in pipeline flow."""
        from core.tools.registry import get_tool

        tool_def = get_tool(tool_name)
        if tool_def is None:
            return "unknown"
        if not bool(getattr(tool_def, "enabled", True)):
            return "disabled"
        return self.tool_execution_profiles.get(tool_def.name, "auto")

    def get_coverage_report(self, registered_tools: list[str] | None = None) -> dict[str, Any]:
        """Classify registry coverage without treating gated/manual tools as bugs."""
        if registered_tools is None:
            try:
                from core.tools.registry import list_tools

                # Importing ``core.tools.registry`` initializes the
                # ``core.tools`` package first, whose canonical leaf-module
                # imports register every built-in decorator tool.  The
                # top-level ``tools.py`` compatibility facade is unnecessary
                # here and must not remain a first-party dependency.
                registered_tools = [tool_def.name for tool_def in list_tools()]
            except Exception:
                registered_tools = []

        from core.tools.registry import get_tool

        registered = set(registered_tools)
        canonical_names = {
            name: tool_def.name if (tool_def := get_tool(name)) is not None else name for name in registered
        }
        auto_providers = set()
        for task in self.task_map:
            auto_providers.update(self._tool_names_for_task(task))
        auto_providers.update(name for name, profile in self.tool_execution_profiles.items() if profile == "auto")

        followup_tools = {name for name in registered if self.tool_execution_profile(name) == "followup"}
        manual_gated = {name for name in registered if self.tool_execution_profile(name) == "manual_gated"}
        legacy_wrappers = {
            name for name in registered if self.tool_execution_profile(name) in {"legacy_wrapper", "alias_wrapper"}
        }
        disabled_tools = {name for name in registered if self.tool_execution_profile(name) == "disabled"}
        explicitly_classified = followup_tools | manual_gated | legacy_wrappers | disabled_tools
        auto_tools = {name for name in registered - explicitly_classified if canonical_names[name] in auto_providers}
        covered = auto_tools | followup_tools | manual_gated | legacy_wrappers | disabled_tools

        return {
            "registered": len(registered),
            "covered": len(covered),
            "auto": sorted(auto_tools),
            "followup": sorted(followup_tools),
            "manual_gated": sorted(manual_gated),
            "legacy_wrappers": sorted(legacy_wrappers),
            "disabled": sorted(disabled_tools),
            "unknown": sorted(registered - covered),
        }

    def get_discovered_plugins_summary(self) -> list[dict[str, Any]]:
        """Return metadata for class-based plugins discovered under modules/."""
        if self._plugin_summary_cache is not None:
            return self._plugin_summary_cache

        try:
            if self._plugin_manager_provider is not None:
                manager = self._plugin_manager_provider()
            else:
                from core.plugins.loader import PluginManager, default_modules_dir

                manager = PluginManager(default_modules_dir())
            self._plugin_summary_cache = manager.list_plugins()
        except Exception:
            self._plugin_summary_cache = []

        return self._plugin_summary_cache
