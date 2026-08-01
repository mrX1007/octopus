#!/usr/bin/env python3


import json
from typing import Any

from core.ai.evaluated_facts import EvaluatedFactSnapshot
from core.ai.fact_predicates import (
    confirms_cleanup,
    confirms_credentials,
    confirms_exfiltration,
    confirms_persistence,
    confirms_root,
    confirms_system_access_exploit,
    fact_type,
    fact_value,
    is_vulnerability_fact,
    is_web_fact,
    parse_port_open,
    web_fact_port,
)


class StateResolver:
    def __init__(self, fact_store):
        self.fact_store = fact_store

    def resolve_state(self, scan_id: str, host: str) -> dict[str, Any]:
        """
        Pulls all facts for a host and infers the current attack state.
        Returns a dictionary representing the state.
        """
        snapshot = EvaluatedFactSnapshot.build(
            scan_id,
            host,
            self.fact_store.get_facts(scan_id, host),
        )
        return self.resolve_snapshot(snapshot)

    def resolve_snapshot(self, snapshot: EvaluatedFactSnapshot) -> dict[str, Any]:
        """Resolve state from one already-evaluated immutable fact snapshot."""

        all_facts = list(snapshot.historical_facts())
        facts = list(snapshot.decision_facts())
        host = snapshot.canonical_scope[0] if snapshot.canonical_scope else ""

        state: dict[str, Any] = {
            "target": host,
            "recon_completed": False,
            "web_services_found": False,
            "ssh_service_found": False,
            "vulnerabilities_found": False,
            "vulnerability_candidates_found": False,
            "verified_vulnerabilities_found": False,
            "credentials_found": False,
            "root_access_confirmed": False,
            "post_access_inventory_completed": False,
            "persistence_established": False,
            "internal_recon_completed": False,
            "exfiltration_completed": False,
            "cleanup_completed": False,
            "open_ports": [],
            "fact_assessment_counts": {
                status: sum(
                    1
                    for fact in all_facts
                    if str(fact.get("assessment_status") or "observed")
                    .strip()
                    .casefold()
                    == status
                )
                for status in ("observed", "inferred", "verified", "contradicted")
            },
        }

        # Group decision-usable facts by session_id for explicitly correlated
        # outcomes.  Free-form text never participates in the predicates.
        session_facts: dict[Any, list[dict[str, Any]]] = {}
        for f in facts:
            sid = f.get('session_id', 'none')
            if sid not in session_facts:
                session_facts[sid] = []
            session_facts[sid].append(f)

        # Recon and ports.  Values are fully parsed so port 8222 is not SSH and
        # 1800 is not mistaken for HTTP merely because it contains "80".
        for f in facts:
            port = parse_port_open(f)
            if port is not None:
                state["recon_completed"] = True
                state["open_ports"].append(port.rendered)
                if port.is_web:
                    state["web_services_found"] = True
                if port.is_ssh:
                    state["ssh_service_found"] = True
            elif is_web_fact(f):
                state["recon_completed"] = True
                state["web_services_found"] = True
                endpoint_port = web_fact_port(f)
                if endpoint_port is not None:
                    state["open_ports"].append(endpoint_port.rendered)

        # Vulnerabilities are recognized by a closed set of typed facts.  A
        # CVE-shaped string in an unrelated fact is not a vulnerability.
        vulnerability_facts = [fact for fact in facts if is_vulnerability_fact(fact)]
        if vulnerability_facts:
            state["vulnerability_candidates_found"] = True
            state["vulnerabilities_found"] = True
        if any(
            str(fact.get("assessment_status") or "observed") == "verified"
            for fact in vulnerability_facts
        ):
            state["verified_vulnerabilities_found"] = True

        state["credentials_found"] = any(confirms_credentials(fact) for fact in facts)
        state["root_access_confirmed"] = any(confirms_root(fact) for fact in facts)

        # Credentials remain useful for routing, but exploit status is not an
        # authority fact. Root requires a direct typed access observation.
        for sfacts in session_facts.values():
            has_creds = any(confirms_credentials(fact) for fact in sfacts)
            if has_creds:
                state["credentials_found"] = True

        if any(
            fact_type(fact) == "post_exploit_stage"
            and fact_value(fact) == "post_access_inventory_completed"
            for fact in facts
        ):
            state["post_access_inventory_completed"] = True

        # Persistence
        if any(confirms_persistence(fact) for fact in facts):
            state["persistence_established"] = True

        # Internal recon / pivot observations. Host/subnet facts can be observed
        # during SSH inventory, so only explicit network_recon evidence closes
        # this stage.
        if any(fact_type(fact) == "internal_network" for fact in facts):
            state["internal_recon_completed"] = True
        if any(
            fact_type(fact) == "post_exploit_stage"
            and fact_value(fact) == "internal_network_recon_completed"
            for fact in facts
        ):
            state["internal_recon_completed"] = True
        if any(
            fact_type(fact) == "service_status"
            and fact_value(fact)
            in {"network_recon_completed", "internal_network_recon_completed"}
            for fact in facts
        ):
            state["internal_recon_completed"] = True

        # Exfil & Cleanup
        # Not every loot-like fact means the data-exfiltration stage completed.
        # For example, /etc/shadow may be copied during privesc to verify root
        # or collect hashes. Only explicit exfil stage outcomes advance state.
        if any(confirms_exfiltration(fact) for fact in facts):
            state["exfiltration_completed"] = True
        if any(confirms_cleanup(fact) for fact in facts):
            state["cleanup_completed"] = True

        state["open_ports"] = sorted(set(state["open_ports"]))
        return state

    def _is_exfil_completion(self, fact_type: str, fact_value: str) -> bool:
        return confirms_exfiltration({"type": fact_type, "value": fact_value})

    def _is_system_access_exploit(self, fact_value: str) -> bool:
        return confirms_system_access_exploit(fact_value)

    def get_state_for_llm(self, scan_id: str, host: str) -> str:
        """Returns the inferred state as a JSON string for the Director LLM."""
        state = self.resolve_state(scan_id, host)
        return json.dumps(state, indent=2)
