#!/usr/bin/env python3


import json
from typing import Dict, Any

class StateResolver:
    def __init__(self, fact_store):
        self.fact_store = fact_store

    def resolve_state(self, scan_id: str, host: str) -> Dict[str, Any]:
        """
        Pulls all facts for a host and infers the current attack state.
        Returns a dictionary representing the state.
        """
        facts = self.fact_store.get_facts(scan_id, host)
        fact_values = [f['value'].lower() for f in facts]
        fact_types = [f['type'].lower() for f in facts]

        state = {
            "target": host,
            "recon_completed": False,
            "web_services_found": False,
            "ssh_service_found": False,
            "vulnerabilities_found": False,
            "credentials_found": False,
            "root_access_confirmed": False,
            "persistence_established": False,
            "internal_recon_completed": False,
            "exfiltration_completed": False,
            "cleanup_completed": False,
            "open_ports": []
        }

        # Group facts by session_id
        session_facts = {}
        for f in facts:
            sid = f.get('session_id', 'none')
            if sid not in session_facts:
                session_facts[sid] = []
            session_facts[sid].append(f)

        # Recon and Ports
        for f in facts:
            if f['type'] == 'port_open':
                state["recon_completed"] = True
                val = f['value'].lower()
                state["open_ports"].append(val)
                if 'http' in val or '80' in val or '443' in val:
                    state["web_services_found"] = True
                if '22' in val or 'ssh' in val:
                    state["ssh_service_found"] = True
            elif f['type'] in {'browser_rendered', 'web_title', 'web_surface', 'web_input', 'web_link'}:
                state["recon_completed"] = True
                state["web_services_found"] = True
                if f['type'] == 'browser_rendered':
                    val = f['value'].lower()
                    if val.startswith("https://") or ":443" in val:
                        state["open_ports"].append("443/tcp (https)")
                    elif val.startswith("http://") or ":80" in val:
                        state["open_ports"].append("80/tcp (http)")

        # Vulnerabilities (including hypotheses)
        if any('vuln' in ft for ft in fact_types) or any('cve' in fv for fv in fact_values) or any('exploit_success' in ft for ft in fact_types):
            state["vulnerabilities_found"] = True

        if any('uid=0' in fv or 'root_access_confirmed' in fv for fv in fact_values):
            state["root_access_confirmed"] = True
        if any('credential' in ft for ft in fact_types) or any('ssh_login_success' in fv for fv in fact_values):
            state["credentials_found"] = True

        # Credentials & Root Access (Correlated by session)
        for sid, sfacts in session_facts.items():
            s_values = [f['value'].lower() for f in sfacts]
            s_types = [f['type'].lower() for f in sfacts]
            
            has_creds = any('login_success' in v or 'credential' in t or 'cpanel_auth' in v or 'whm_session' in v for v, t in zip(s_values, s_types))
            has_uid0 = any('uid=0' in v for v in s_values)
            has_exploit_success = any('exploit_success' in t for t in s_types)
            
            if has_creds:
                state["credentials_found"] = True
            
            # Root access is confirmed if:
            # 1. login and uid=0 share the same session, OR
            # 2. exploit_success in session (e.g. cpanel auth bypass = admin), OR
            # 3. uid=0 from a named session
            if has_uid0 and (has_creds or sid != 'none'):
                state["root_access_confirmed"] = True
            if has_exploit_success and has_creds:
                # Exploit success + session = confirmed access
                state["root_access_confirmed"] = True

        if any('exploit_success' in ft for ft in fact_types) and any('uid=0' in fv for fv in fact_values):
            state["root_access_confirmed"] = True

        # Persistence
        if any('persistence' in ft for ft in fact_types) or any('mechanism_planted' in fv for fv in fact_values):
            state["persistence_established"] = True

        # Internal recon / pivot observations
        if any(ft in ("internal_host", "internal_subnet", "internal_network") for ft in fact_types):
            state["internal_recon_completed"] = True

        # Exfil & Cleanup
        if any('exfil' in ft for ft in fact_types):
            state["exfiltration_completed"] = True
        if any('cleanup' in ft and fv in ("success", "partial", "completed") for ft, fv in zip(fact_types, fact_values)):
            state["cleanup_completed"] = True

        state["open_ports"] = sorted(set(state["open_ports"]))
        return state

    def get_state_for_llm(self, scan_id: str, host: str) -> str:
        """Returns the inferred state as a JSON string for the Director LLM."""
        state = self.resolve_state(scan_id, host)
        return json.dumps(state, indent=2)
