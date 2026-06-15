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
    "ftp":       ["ftp", "21/"],
    "smtp":      ["smtp", "25/", "465/", "587/"],
    "pop3":      ["pop3", "110/", "995/"],
    "imap":      ["imap", "143/", "993/"],
    "mysql":     ["mysql", "3306/"],
    "postgres":  ["postgres", "5432/"],
    "rdp":       ["rdp", "3389/"],
    "smb":       ["smb", "445/", "139/"],
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
        if state.get("root_access_confirmed"):
            primary_state = "root_access_confirmed"
        elif state.get("persistence_established"):
            primary_state = "persistence_established"
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

        # Infer open questions based on current state and services
        open_questions = self._infer_open_questions(state, services, primary_state)

        return {
            "host": host,
            "state": primary_state,
            "services": services,
            "ports_count": len(open_ports),
            "open_questions": open_questions
        }
    
    def _infer_open_questions(self, state: Dict, services: List[str], primary_state: str) -> List[str]:
        """Infer what we still don't know based on services and state."""
        questions = []
        
        if primary_state in ("initial_recon",):
            return ["service_discovery_needed"]
        
        if not state.get("vulnerabilities_found"):
            if "http" in services or "https" in services:
                questions.append("web_vulnerabilities_unknown")
            if "ftp" in services:
                questions.append("ftp_anonymous_access_unknown")
            if "smtp" in services:
                questions.append("smtp_open_relay_unknown")
            if "postgres" in services or "mysql" in services:
                questions.append("database_auth_unknown")
            if "smb" in services:
                questions.append("smb_null_session_unknown")
            if not questions:
                questions.append("general_vulnerability_scan_needed")
                
        if not state.get("credentials_found"):
            if "ssh" in services:
                questions.append("ssh_credentials_unknown")
            if "ftp" in services:
                questions.append("ftp_credentials_unknown")
                
        if state.get("credentials_found") and not state.get("root_access_confirmed"):
            questions.append("privilege_escalation_path_unknown")
            
        return questions
