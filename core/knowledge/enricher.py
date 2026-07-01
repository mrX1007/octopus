#!/usr/bin/env python3

import re
import logging
from typing import List, Tuple

from .graph import KnowledgeGraph
from .models import EdgeType


class KnowledgeEnricher:
    """
    Bridges the gap between raw tool output facts and the typed knowledge graph.

    Usage:
        enricher = KnowledgeEnricher(graph)
        enricher.enrich_from_facts("10.0.0.1", facts)
    """

    def __init__(self, graph: KnowledgeGraph):
        self.graph = graph
        self._processed = set()   # avoid duplicate processing

    def enrich_from_facts(self, target_ip: str, facts: List[Tuple[str, str]]):
        """
        Process (fact_text, source_tool) tuples and create graph nodes/edges.
        """
        # Ensure target asset exists
        self.graph.add_asset(target_ip)

        for item in facts:
            if isinstance(item, tuple) and len(item) == 2:
                fact_text, source = item
            else:
                fact_text = str(item)
                source = "unknown"

            # Dedup
            key = f"{target_ip}:{fact_text[:80]}"
            if key in self._processed:
                continue
            self._processed.add(key)

            try:
                self._process_fact(target_ip, fact_text, source)
            except Exception as e:
                logging.debug(f"Enricher error on '{fact_text[:50]}': {e}")

    def _process_fact(self, target_ip: str, fact_text: str, source: str):
        """Route a fact to the appropriate handler."""
        ft = fact_text.strip()
        ft_lower = ft.lower()

        # ── PORT OPEN ──
        m = re.match(r'Port (\d+) OPEN \((\S+)\)', ft)
        if m:
            port, svc_name = int(m.group(1)), m.group(2)
            self.graph.add_service(target_ip, port, service_name=svc_name)
            return

        # ── PORT FILTERED ──
        m = re.match(r'Port (\d+) FILTERED \((\S+)\)', ft)
        if m:
            port, svc_name = int(m.group(1)), m.group(2)
            self.graph.add_service(target_ip, port, service_name=svc_name,
                                   state="filtered")
            return

        # ── PORT CLOSED ──
        m = re.match(r'Port (\d+) CLOSED \((\S+)\)', ft)
        if m:
            port, svc_name = int(m.group(1)), m.group(2)
            self.graph.add_service(target_ip, port, service_name=svc_name,
                                   state="closed")
            return

        # ── PORT VERSION ──
        m = re.match(r'Port (\d+) version: (.+)', ft)
        if m:
            port, version = int(m.group(1)), m.group(2).strip()
            self.graph.add_service(target_ip, port, version=version)
            return

        # ── CREDENTIALS FOUND ──
        if "CREDENTIALS FOUND:" in ft:
            cred_part = ft.split("CREDENTIALS FOUND:")[-1].strip()
            # Formats: "user:pass", "ssh://user:pass on port 22"
            cred_clean = cred_part.split(" on ")[0]
            cred_clean = re.sub(r'^(ssh|ftp|http|mysql)://', '', cred_clean)
            if ":" in cred_clean:
                user, pwd = cred_clean.split(":", 1)
                user = user.strip("'\".,;:()[] ")
                pwd = pwd.strip("'\".,;:()[] ")
                if user and pwd and len(user) >= 2:
                    cred = self.graph.add_credential(
                        user, pwd, source=source,
                        service="ssh", verified=True, host=target_ip)
                    self.graph.link_credential_to_asset(
                        cred.node_id, f"asset:{target_ip}",
                        method="password_auth")
            return

        # ── SSH VALID USER ──
        m = re.match(r"SSH valid user confirmed: '(\S+)'", ft)
        if m:
            username = m.group(1).strip("'\"")
            self.graph.add_identity(username, identity_type="local")
            self.graph.link(f"asset:{target_ip}",
                            f"identity:{username}",
                            EdgeType.HAS_IDENTITY,
                            source=source)
            return

        # ── SYSTEM USER ──
        m = re.match(r"System user found: '(\S+)' \(UID (\d+)\)", ft)
        if m:
            username, uid = m.group(1), int(m.group(2))
            self.graph.add_identity(username, identity_type="local",
                                    uid=uid)
            self.graph.link(f"asset:{target_ip}",
                            f"identity:{username}",
                            EdgeType.HAS_IDENTITY)
            return

        # ── SYSTEM LOGIN USER ──
        m = re.match(r"System login user: '(\S+)' \(shell: (.+)\)", ft)
        if m:
            username, shell = m.group(1), m.group(2)
            self.graph.add_identity(username, identity_type="local",
                                    shell=shell)
            self.graph.link(f"asset:{target_ip}",
                            f"identity:{username}",
                            EdgeType.HAS_IDENTITY)
            return

        # ── TARGET IS ROOTED ──
        if "TARGET IS ROOTED" in ft:
            self.graph.add_asset(target_ip, rooted=True)
            return

        # ── NOPASSWD SUDO ──
        if "NOPASSWD sudo:" in ft:
            vuln = self.graph.add_vulnerability(
                f"nopasswd-sudo-{target_ip}",
                name="NOPASSWD Sudo",
                severity="high", confirmed=True,
                description=ft)
            # Find SSH service to link
            svc_id = f"svc:{target_ip}:22"
            self.graph.link(svc_id, vuln.node_id, EdgeType.VULNERABLE_TO)
            return

        # ── EXPLOITABLE SUID ──
        m = re.match(r"Exploitable SUID binary: (.+)", ft)
        if m:
            binary_path = m.group(1).strip()
            vuln = self.graph.add_vulnerability(
                f"suid-{binary_path.replace('/', '-')}",
                name=f"SUID: {binary_path}",
                severity="high", confirmed=True,
                description=ft)
            svc_id = f"svc:{target_ip}:22"
            self.graph.link(svc_id, vuln.node_id, EdgeType.VULNERABLE_TO)
            return

        # ── INTERNAL IP (pivot target) ──
        m = re.match(r"INTERNAL IP: ([\d.]+)", ft)
        if m:
            internal_ip = m.group(1)
            self.graph.add_asset(internal_ip)
            self.graph.link(f"asset:{target_ip}", f"asset:{internal_ip}",
                            EdgeType.TRUSTS, discovery=source)
            return

        # ── WEB APP DETECTED ──
        web_apps = {
            "WordPress CMS detected": "wordpress",
            "Zabbix web interface detected": "zabbix",
            "phpMyAdmin detected": "phpmyadmin",
            "Grafana dashboard detected": "grafana",
            "Jenkins CI detected": "jenkins",
            "Joomla CMS detected": "joomla",
            "Drupal CMS detected": "drupal",
            "Apache Tomcat detected": "tomcat",
            "Webmin panel detected": "webmin",
            "GitLab instance detected": "gitlab",
            "cPanel detected": "cpanel",
            "Cockpit web console detected": "cockpit",
        }
        for pattern, app_name in web_apps.items():
            if pattern in ft:
                # Add/update HTTP service with web_app tag
                self.graph.add_service(target_ip, 80, service_name="http",
                                       web_app=app_name)
                return

        # ── DB CREDENTIALS ──
        m = re.match(r"DB PASSWORD FOUND: (.+)", ft)
        if m:
            db_pass = m.group(1).strip()
            self.graph.add_credential("root", db_pass, source=source,
                                      service="mysql", host=target_ip)
            return

        m = re.match(r"DB USER FOUND: (.+)", ft)
        if m:
            db_user = m.group(1).strip()
            self.graph.add_identity(db_user, identity_type="service")
            return

        # ── SECRET KEYS ──
        if "SECRET KEY FOUND:" in ft:
            key_val = ft.split("SECRET KEY FOUND:")[-1].strip()
            self.graph.add_credential("api_key", key_val, source=source,
                                      secret_type="token", host=target_ip)
            return

        # ── LATERAL MOVEMENT ──
        m = re.match(r"LATERAL: Compromised (\S+)@(\S+)", ft)
        if m:
            user, host = m.group(1), m.group(2)
            self.graph.add_asset(host)
            self.graph.add_identity(user)
            self.graph.link(f"asset:{target_ip}", f"asset:{host}",
                            EdgeType.PIVOTS_TO, method="lateral_movement")
            return

        # ── PERSISTENCE ──
        if "PERSISTENCE:" in ft:
            vuln_id = f"persistence-{target_ip}"
            self.graph.add_vulnerability(
                vuln_id, name="Persistence Planted",
                severity="critical", confirmed=True,
                description=ft)
            return

        # ── KILL CHAIN STAGES (informational, no graph action needed) ──
        # These are tracked but don't create new nodes
        if ft.startswith("KILL CHAIN:"):
            return

        # ── HTTP HEADERS ──
        if ft.startswith("HTTP header:"):
            # Parse server version from headers
            m_server = re.search(r'Server:\s*(.+)', ft, re.IGNORECASE)
            if m_server:
                server_ver = m_server.group(1).strip()
                self.graph.add_service(target_ip, 80,
                                       service_name="http",
                                       version=server_ver)
            return

    def get_processed_count(self) -> int:
        """Return how many facts have been processed."""
        return len(self._processed)
