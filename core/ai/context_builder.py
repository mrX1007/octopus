#!/usr/bin/env python3
"""
"""

import re
import json
from typing import Dict, Any, List
from core.ai.fact_store import FactStore
from core.ai.state_resolver import StateResolver
from core.ai.target_model import TargetModel
from core.ai.asset_graph import AssetGraph
from core.ai.surface_state import SurfaceState

try:
    from config import CFG
except ImportError:
    CFG = {}

# Map service names/banners to canonical service labels. Do not infer services
# from port numbers: custom deployments move protocols to arbitrary ports.
SERVICE_PATTERNS = {
    "ssh":       ["ssh", "openssh"],
    "http":      ["http", "httpd", "web server", "nginx", "apache", "cowboy", "golang net/http", "node.js", "express", "php"],
    "https":     ["ssl/http", "https"],
    "cpanel":    ["cpanel", "whm"],
    "tomcat":    ["tomcat", "ajp13"],
    "jmx":       ["jmx"],
    "ftp":       ["ftp"],
    "smtp":      ["smtp", "submission", "smtps"],
    "pop3":      ["pop3"],
    "imap":      ["imap"],
    "mysql":     ["mysql", "mariadb"],
    "postgres":  ["postgres", "postgresql"],
    "rdp":       ["rdp", "ms-wbt-server"],
    "smb":       ["smb", "microsoft-ds", "netbios-ssn", "samba"],
    "ldap":      ["ldap"],
    "kerberos":  ["kerberos", "kerberos-sec"],
    "winrm":     ["winrm"],
    "dns":       ["dns", "domain"],
    "redis":     ["redis"],
    "mongodb":   ["mongo", "mongodb"],
    "rtsp":      ["rtsp"],
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
        target_model = TargetModel.from_facts(scan_id, host, facts).to_dict()
        asset_graph = AssetGraph.from_facts(host, facts).to_dict()
        surface_states = SurfaceState(facts).to_dict()
        
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
            port_lower = self._service_text_from_port_fact(port_str)
            for svc_name, patterns in SERVICE_PATTERNS.items():
                if any(p in port_lower for p in patterns):
                    services.add(svc_name)
        for fact in facts:
            if fact.get("type") != "web_endpoint":
                continue
            endpoint_text = str(fact.get("value", "")).lower()
            services.add("http")
            if '"scheme": "https"' in endpoint_text or endpoint_text.startswith("https://"):
                services.add("https")
        
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
            "automation_policy": self._automation_policy(),
            "next_required_capability": self._next_required_capability(primary_state, open_questions),
            "network_graph": self._network_graph(facts),
            "asset_graph": asset_graph,
            "surface_states": surface_states,
            "target_model": target_model,
        }

    def _service_text_from_port_fact(self, port_fact: str) -> str:
        value = (port_fact or "").lower()
        match = re.match(r"\d+/(?:tcp|udp)\s+\(([^)]*)\)(?:\s+\[(.*?)\])?", value)
        if not match:
            return value
        service, banner = match.groups()
        return f"{service or ''} {banner or ''}".strip()

    def _network_graph(self, facts: List[Dict[str, Any]]) -> Dict[str, Any]:
        nodes = []
        edges = []
        seen_nodes = set()
        seen_edges = set()
        for fact in facts:
            ftype = fact.get("type")
            value = fact.get("value", "")
            if ftype not in {"network_node", "network_edge"}:
                continue
            try:
                parsed = json.loads(value)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            key = json.dumps(parsed, sort_keys=True)
            if ftype == "network_node" and key not in seen_nodes:
                seen_nodes.add(key)
                nodes.append(parsed)
            elif ftype == "network_edge" and key not in seen_edges:
                seen_edges.add(key)
                edges.append(parsed)
        return {"nodes": nodes, "edges": edges}
    
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
            if self._strategy_enabled("auto_persistence") and not state.get("persistence_established"):
                return ["persistence_needed"]
            if self._strategy_enabled("auto_internal_recon") and not state.get("internal_recon_completed"):
                return ["internal_network_recon_pending"]
            return []

        if primary_state == "persistence_established":
            if not state.get("post_access_inventory_completed"):
                return ["post_access_inventory_needed"]
            if self._strategy_enabled("auto_internal_recon") and not state.get("internal_recon_completed"):
                return ["internal_network_recon_pending"]
            if self._strategy_enabled("auto_data_exfil") and not state.get("exfiltration_completed"):
                return ["data_exfiltration_pending"]
            return []

        if primary_state == "internal_recon_completed":
            if not state.get("post_access_inventory_completed"):
                return ["post_access_inventory_needed"]
            if self._strategy_enabled("auto_data_exfil") and not state.get("exfiltration_completed"):
                return ["data_exfiltration_pending"]
            return []

        if primary_state == "exfiltration_completed":
            if self._strategy_enabled("auto_cleanup") and not state.get("cleanup_completed"):
                return ["cleanup_needed"]
            return []

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

    def _strategy_enabled(self, key: str, default: bool = False) -> bool:
        return bool((CFG.get("strategy") or {}).get(key, default))

    def _automation_policy(self) -> Dict[str, bool]:
        strategy = CFG.get("strategy") or {}
        return {
            "auto_post_access_inventory": bool(strategy.get(
                "auto_post_access_inventory",
                strategy.get("auto_ssh_inventory", True),
            )),
            "auto_ssh_inventory": bool(strategy.get("auto_ssh_inventory", True)),
            "auto_internal_recon": bool(strategy.get("auto_internal_recon", True)),
            "auto_payload_generation": bool(strategy.get("auto_payload_generation", False)),
            "auto_persistence": bool(strategy.get("auto_persistence", False)),
            "auto_data_exfil": bool(strategy.get("auto_data_exfil", False)),
            "auto_cleanup": bool(strategy.get("auto_cleanup", False)),
            "allow_active_msf": bool(strategy.get("allow_active_msf", False)),
        }

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
