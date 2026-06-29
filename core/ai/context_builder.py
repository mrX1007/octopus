#!/usr/bin/env python3
"""
"""

from typing import Dict, Any, List
from core.ai.fact_store import FactStore
from core.ai.state_resolver import StateResolver

# Map port numbers and service names to canonical service labels
SERVICE_PATTERNS = {
    "ssh":       ["ssh", "22/"],
    "http":      ["http", "80/", "443/", "8080/", "8443/", "3000/", "3030/", "9000/"],
    "https":     ["ssl/http", "443/"],
    "cpanel":    ["cpanel", "whm", "2082/", "2083/", "2086/", "2087/", "2095/", "2096/"],
    "tomcat":    ["tomcat", "ajp13", "8009/"],
    "jmx":       ["jmx"],
    "ftp":       ["ftp", "21/"],
    "smtp":      ["smtp", "25/", "465/", "587/"],
    "pop3":      ["pop3", "110/", "995/"],
    "imap":      ["imap", "143/", "993/"],
    "mysql":     ["mysql", "3306/"],
    "postgres":  ["postgres", "5432/"],
    "rdp":       ["rdp", "3389/"],
    "smb":       ["smb", "445/", "139/"],
    "ldap":      ["ldap", "389/", "636/"],
    "kerberos":  ["kerberos", "88/"],
    "winrm":     ["winrm", "5985/", "5986/"],
    "dns":       ["dns", "53/"],
    "redis":     ["redis", "6379/"],
    "mongodb":   ["mongo", "27017/"],
    "rtsp":      ["rtsp", "554/", "8082/"],
}

class ContextBuilder:
    def __init__(self, fact_store: FactStore, state_resolver: StateResolver):
        self.fact_store = fact_store
        self.state_resolver = state_resolver

    def build_context(self, scan_id: str, host: str) -> Dict[str, Any]:
        """
        Builds a concise summary of the current state, services, and open questions.
        Example output:
        {
          "host": "x.x.x.x",
          "state": "recon_completed",
          "services": ["ssh", "http", "ftp", "smtp", "postgres"],
          "ports_count": 15,
          "open_questions": ["web_vulnerabilities_unknown", "ftp_anonymous_unknown"]
        }
        """
        state = self.state_resolver.resolve_state(scan_id, host)
        facts = self.fact_store.get_facts(scan_id, host)
        
        # Determine highest level conceptual state
        primary_state = "initial_recon"
        if state.get("cleanup_completed"):
            primary_state = "cleanup_completed"
        elif state.get("exfiltration_completed"):
            primary_state = "exfiltration_completed"
        elif state.get("persistence_established"):
            primary_state = "internal_recon_completed" if state.get("internal_recon_completed") else "persistence_established"
        elif state.get("root_access_confirmed"):
            primary_state = "root_access_confirmed"
        elif state.get("credentials_found"):
            primary_state = "credentials_found"
        elif state.get("vulnerabilities_found"):
            primary_state = "vulnerabilities_found"
        elif state.get("recon_completed"):
            primary_state = "recon_completed"

        # Extract services from ALL port facts
        services = set()
        open_ports = state.get("open_ports", [])
        for port_str in open_ports:
            port_lower = port_str.lower()
            for svc_name, patterns in SERVICE_PATTERNS.items():
                if any(p in port_lower for p in patterns):
                    services.add(svc_name)
        
        services = sorted(services)

        # Infer open questions based on current state, services and facts
        open_questions = self._infer_open_questions(state, services, primary_state, facts)
        stage_gates = self._stage_gates(state)

        return {
            "host": host,
            "state": primary_state,
            "services": services,
            "ports_count": len(open_ports),
            "open_questions": open_questions,
            "stage_gates": stage_gates,
            "next_required_capability": self._next_required_capability(primary_state, open_questions),
        }
    
    def _infer_open_questions(self, state: Dict, services: List[str], primary_state: str,
                              facts: List[Dict[str, Any]] = None) -> List[str]:
        """Infer what we still don't know based on services and state."""
        questions = []
        facts = facts or []
        fact_text = " ".join(str(f.get("value", "")).lower() for f in facts)
        has_login_form = (
            "login_form_detected" in fact_text
            or any(f.get("type") == "web_input" and "password:" in str(f.get("value", "")).lower() for f in facts)
        )
        has_cpanel_surface = "cpanel" in services or "whm" in fact_text or "cpanel" in fact_text
        has_jmx_surface = "jmx" in services or "tomcat" in services or "jmx" in fact_text
        has_ssh_access = (
            "ssh_login_success:" in fact_text
            or "ssh_authenticated" in fact_text
            or "ssh_key_available:" in fact_text
        )
        
        if primary_state in ("initial_recon",):
            return ["service_discovery_needed"]

        if primary_state == "root_access_confirmed":
            if not state.get("post_access_inventory_completed"):
                return ["post_access_inventory_needed"]
            return ["persistence_needed"] if not state.get("persistence_established") else []

        if primary_state == "persistence_established":
            if not state.get("post_access_inventory_completed"):
                return ["post_access_inventory_needed"]
            if not state.get("internal_recon_completed"):
                return ["internal_network_recon_pending"]
            return ["data_exfiltration_pending"] if not state.get("exfiltration_completed") else []

        if primary_state == "internal_recon_completed":
            if not state.get("post_access_inventory_completed"):
                return ["post_access_inventory_needed"]
            return ["data_exfiltration_pending"] if not state.get("exfiltration_completed") else []

        if primary_state == "exfiltration_completed":
            return ["cleanup_needed"] if not state.get("cleanup_completed") else []

        if primary_state == "cleanup_completed":
            return []

        if primary_state == "vulnerabilities_found":
            if not state.get("recon_completed"):
                questions.append("service_discovery_needed")
            questions.append("vulnerability_verification_needed")
            if has_cpanel_surface:
                questions.append("cpanel_auth_bypass_unknown")
            if has_jmx_surface:
                questions.append("jmx_exposure_unknown")
            return list(dict.fromkeys(questions))

        if primary_state == "credentials_found":
            if not state.get("recon_completed"):
                questions.append("service_discovery_needed")
            if has_cpanel_surface:
                questions.append("cpanel_authenticated_session_present")
            if has_ssh_access and not state.get("root_access_confirmed"):
                questions.append("privilege_escalation_path_unknown")
            elif not questions:
                questions.append("credential_scope_verification_needed")
            return list(dict.fromkeys(questions))

        if not state.get("vulnerabilities_found"):
            if "http" in services or "https" in services:
                questions.append("web_vulnerabilities_unknown")
            if has_cpanel_surface:
                questions.append("cpanel_auth_bypass_unknown")
            if has_jmx_surface:
                questions.append("jmx_exposure_unknown")
            if "ftp" in services:
                questions.append("ftp_anonymous_access_unknown")
            if "smtp" in services:
                questions.append("smtp_open_relay_unknown")
            if "postgres" in services or "mysql" in services:
                questions.append("database_auth_unknown")
            if "smb" in services:
                questions.append("smb_null_session_unknown")
            if any(svc in services for svc in ("ldap", "kerberos", "winrm", "rdp")):
                questions.append("active_directory_exposure_unknown")
            if not questions:
                questions.append("general_vulnerability_scan_needed")
                
        if not state.get("credentials_found"):
            if "ssh" in services:
                questions.append("ssh_credentials_unknown")
            if "ftp" in services:
                questions.append("ftp_credentials_unknown")
            if has_login_form:
                questions.append("web_credentials_unknown")
                
        if state.get("credentials_found") and has_ssh_access and not state.get("root_access_confirmed"):
            questions.append("privilege_escalation_path_unknown")
            
        return questions

    def _stage_gates(self, state: Dict) -> Dict[str, bool]:
        return {
            "recon": bool(state.get("recon_completed")),
            "credentials": bool(state.get("credentials_found")),
            "root": bool(state.get("root_access_confirmed")),
            "post_access_inventory": bool(state.get("post_access_inventory_completed")),
            "persistence": bool(state.get("persistence_established")),
            "internal_recon": bool(state.get("internal_recon_completed")),
            "exfiltration": bool(state.get("exfiltration_completed")),
            "cleanup": bool(state.get("cleanup_completed")),
        }

    def _next_required_capability(self, primary_state: str, open_questions: List[str]) -> str:
        if "service_discovery_needed" in open_questions:
            return "service_discovery"
        if any("vulnerabilit" in q for q in open_questions):
            return "vulnerability_assessment"
        if any("credential" in q for q in open_questions):
            return "credential_harvesting"
        if "privilege_escalation_path_unknown" in open_questions:
            return "privilege_escalation"
        if "cpanel_authenticated_session_present" in open_questions:
            return "vulnerability_assessment"
        if "post_access_inventory_needed" in open_questions:
            return "post_access_inventory"
        if "persistence_needed" in open_questions:
            return "persistence"
        if "internal_network_recon_pending" in open_questions:
            return "internal_reconnaissance"
        if "data_exfiltration_pending" in open_questions:
            return "data_exfiltration"
        if "cleanup_needed" in open_questions:
            return "cleanup"
        if primary_state == "cleanup_completed":
            return "conclude"
        return "conclude"
