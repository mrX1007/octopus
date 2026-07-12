#!/usr/bin/env python3

import json
import logging
import os
import sqlite3
import time
from collections import deque
from contextlib import contextmanager, suppress
from typing import Optional

from core.secrets import redact_data

from .models import Asset, Campaign, Credential, EdgeType, Identity, NodeType, Service, Session, Vulnerability


class KnowledgeGraph:
    """
    SQLite-backed knowledge graph with typed nodes and edges.

    Usage:
        g = KnowledgeGraph()
        g.add_asset("10.0.0.1", os="Linux", ports=[22, 80])
        g.add_service("10.0.0.1", 22, "ssh", "OpenSSH 8.9")
        g.add_credential("admin", "pass123", source="hydra", verified=True)
        g.link_credential_to_asset("cred:admin:...", "asset:10.0.0.1")
        print(g.get_attack_surface("10.0.0.1"))
    """

    def __init__(self, db_path: Optional[str] = None):
        if not db_path:
            base = os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))))
            self.db_path = os.path.join(base, "data", "knowledge.db")
        else:
            self.db_path = db_path

        if self.db_path != ":memory:":
            db_dir = os.path.dirname(self.db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)

        # For :memory: we must keep ONE persistent connection
        # (each connect(':memory:') creates a new empty DB)
        self._persistent_conn = None
        if self.db_path == ":memory:":
            self._persistent_conn = sqlite3.connect(":memory:")
            self._persistent_conn.row_factory = sqlite3.Row
            self._persistent_conn.execute("PRAGMA foreign_keys=ON")

        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._persistent_conn is not None:
            return self._persistent_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _close_conn(self, conn):
        """Close connection only if it's not the persistent one."""
        if conn is not self._persistent_conn:
            conn.close()

    @contextmanager
    def _connect(self):
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._close_conn(conn)

    def close(self) -> None:
        if self._persistent_conn is not None:
            self._persistent_conn.close()
            self._persistent_conn = None

    def __del__(self):
        with suppress(Exception):
            self.close()

    def _init_db(self):
        """Create schema if not exists."""
        with self._connect() as conn:
            c = conn.cursor()

            c.execute('''
                CREATE TABLE IF NOT EXISTS nodes (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    properties TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS edges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src TEXT NOT NULL,
                    dst TEXT NOT NULL,
                    edge_type TEXT NOT NULL,
                    properties TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL,
                    UNIQUE(src, dst, edge_type)
                )
            ''')

            c.execute('CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(edge_type)')

            for row in c.execute("SELECT id, properties FROM nodes").fetchall():
                try:
                    properties = json.loads(row["properties"])
                except (TypeError, ValueError, json.JSONDecodeError):
                    properties = {}
                safe_properties = json.dumps(redact_data(properties), sort_keys=True)
                if safe_properties != row["properties"]:
                    c.execute("UPDATE nodes SET properties = ? WHERE id = ?", (safe_properties, row["id"]))
            for row in c.execute("SELECT id, properties FROM edges").fetchall():
                try:
                    properties = json.loads(row["properties"])
                except (TypeError, ValueError, json.JSONDecodeError):
                    properties = {}
                safe_properties = json.dumps(redact_data(properties), sort_keys=True)
                if safe_properties != row["properties"]:
                    c.execute("UPDATE edges SET properties = ? WHERE id = ?", (safe_properties, row["id"]))

    # NODE CRUD — Typed High-Level API

    def _upsert_node(self, node_id: str, node_type: NodeType,
                     properties: dict) -> str:
        """Insert or update a node. Returns node_id."""
        now = time.time()
        properties = redact_data(properties)
        with self._connect() as conn:
            conn.execute('''
                INSERT INTO nodes (id, type, properties, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    properties = excluded.properties,
                    updated_at = excluded.updated_at
            ''', (node_id, node_type.value, json.dumps(properties), now, now))
        return node_id

    def add_asset(self, ip: str, hostname: str = "", os: str = "",
                  ports: Optional[list[int]] = None, **kw) -> Asset:
        """Add or update a host asset."""
        asset = Asset(ip=ip, hostname=hostname, os=os,
                      ports=ports or [], **kw)
        self._upsert_node(asset.node_id, NodeType.ASSET, asset.to_dict())
        return asset

    def add_identity(self, username: str, domain: str = "",
                     identity_type: str = "local", **kw) -> Identity:
        """Add or update a user identity."""
        ident = Identity(username=username, domain=domain,
                         identity_type=identity_type, **kw)
        self._upsert_node(ident.node_id, NodeType.IDENTITY, ident.to_dict())
        return ident

    def add_credential(self, username: str, secret: str,
                       source: str = "", service: str = "",
                       verified: bool = False, host: str = "",
                       secret_type: str = "password") -> Credential:
        """Add or update a credential."""
        cred = Credential(username=username, secret=secret, source=source,
                          service=service, verified=verified, host=host,
                          secret_type=secret_type)
        self._upsert_node(cred.node_id, NodeType.CREDENTIAL, cred.to_dict())
        # Also ensure identity exists
        self.add_identity(username)
        # Auto-link identity → credential
        self.link(f"identity:{username}", cred.node_id,
                  EdgeType.HAS_CREDENTIAL, source=source)
        return cred

    def add_service(self, host: str, port: int,
                    service_name: str = "", version: str = "",
                    banner: str = "", state: str = "open",
                    web_app: str = "") -> Service:
        """Add or update a service on a host."""
        svc = Service(host=host, port=port, service_name=service_name,
                      version=version, banner=banner, state=state,
                      web_app=web_app)
        self._upsert_node(svc.node_id, NodeType.SERVICE, svc.to_dict())
        # Ensure asset exists and link
        self.add_asset(host, ports=[port])
        self.link(f"asset:{host}", svc.node_id, EdgeType.RUNS_SERVICE)
        return svc

    def add_session(self, session_id: str, session_type: str = "ssh",
                    username: str = "", host: str = "") -> Session:
        """Add or update a session."""
        sess = Session(session_id=session_id, session_type=session_type,
                       username=username, host=host)
        self._upsert_node(sess.node_id, NodeType.SESSION, sess.to_dict())
        # Link identity → session → asset
        if username:
            self.link(f"identity:{username}", sess.node_id,
                      EdgeType.ACTIVE_SESSION)
        if host:
            self.link(sess.node_id, f"asset:{host}", EdgeType.SESSION_TO)
        return sess

    def add_vulnerability(self, vuln_id: str, name: str = "",
                          cvss: float = 0.0, severity: str = "medium",
                          service: str = "", confirmed: bool = False,
                          exploit_available: bool = False,
                          description: str = "") -> Vulnerability:
        """Add or update a vulnerability."""
        vuln = Vulnerability(vuln_id=vuln_id, name=name, cvss=cvss,
                             severity=severity, service=service,
                             confirmed=confirmed,
                             exploit_available=exploit_available,
                             description=description)
        self._upsert_node(vuln.node_id, NodeType.VULNERABILITY,
                          vuln.to_dict())
        return vuln

    def add_campaign(self, name: str, objective: str = "",
                     targets: Optional[list[str]] = None) -> Campaign:
        """Add or update a campaign."""
        camp = Campaign(name=name, objective=objective,
                        targets=targets or [])
        self._upsert_node(camp.node_id, NodeType.CAMPAIGN, camp.to_dict())
        # Link targets
        for target_ip in (targets or []):
            self.add_asset(target_ip)
            self.link(f"asset:{target_ip}", camp.node_id, EdgeType.MEMBER_OF)
        return camp

    # EDGE (RELATIONSHIP) API

    def link(self, src_id: str, dst_id: str, edge_type: EdgeType,
             **properties):
        """Create a typed edge between two nodes. Idempotent."""
        now = time.time()
        properties = redact_data(properties)
        try:
            with self._connect() as conn:
                conn.execute('''
                    INSERT INTO edges (src, dst, edge_type, properties, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(src, dst, edge_type) DO UPDATE SET
                        properties = excluded.properties
                ''', (src_id, dst_id, edge_type.value,
                      json.dumps(properties), now))
        except Exception as e:
            logging.debug(f"KnowledgeGraph.link error: {e}")

    def link_credential_to_asset(self, cred_id: str, asset_id: str,
                                 method: str = "ssh"):
        """Link a credential to a target asset (CAN_ACCESS)."""
        self.link(cred_id, asset_id, EdgeType.CAN_ACCESS, method=method)

    def link_service_to_asset(self, svc_id: str, asset_id: str):
        """Link a service to its host asset."""
        self.link(asset_id, svc_id, EdgeType.RUNS_SERVICE)

    def link_vuln_to_service(self, vuln_id: str, svc_id: str):
        """Link a vulnerability to a service."""
        self.link(svc_id, vuln_id, EdgeType.VULNERABLE_TO)

    # QUERY API

    def get_node(self, node_id: str) -> Optional[dict]:
        """Get a single node by ID. Returns properties + metadata."""
        with self._connect() as conn:
            row = conn.execute(
                'SELECT * FROM nodes WHERE id = ?', (node_id,)
            ).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "type": row["type"],
            "properties": redact_data(json.loads(row["properties"])),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def get_nodes_by_type(self, node_type: NodeType) -> list[dict]:
        """Get all nodes of a specific type."""
        with self._connect() as conn:
            rows = conn.execute(
                'SELECT * FROM nodes WHERE type = ? ORDER BY created_at',
                (node_type.value,)
            ).fetchall()
        return [{
            "id": r["id"],
            "type": r["type"],
            "properties": redact_data(json.loads(r["properties"])),
        } for r in rows]

    def get_edges_from(self, node_id: str,
                       edge_type: EdgeType = None) -> list[dict]:
        """Get all outgoing edges from a node."""
        with self._connect() as conn:
            if edge_type:
                rows = conn.execute(
                    'SELECT * FROM edges WHERE src = ? AND edge_type = ?',
                    (node_id, edge_type.value)
                ).fetchall()
            else:
                rows = conn.execute(
                    'SELECT * FROM edges WHERE src = ?', (node_id,)
                ).fetchall()
        return [{
            "src": r["src"], "dst": r["dst"],
            "edge_type": r["edge_type"],
            "properties": redact_data(json.loads(r["properties"])),
        } for r in rows]

    def get_edges_to(self, node_id: str,
                     edge_type: EdgeType = None) -> list[dict]:
        """Get all incoming edges to a node."""
        with self._connect() as conn:
            if edge_type:
                rows = conn.execute(
                    'SELECT * FROM edges WHERE dst = ? AND edge_type = ?',
                    (node_id, edge_type.value)
                ).fetchall()
            else:
                rows = conn.execute(
                    'SELECT * FROM edges WHERE dst = ?', (node_id,)
                ).fetchall()
        return [{
            "src": r["src"], "dst": r["dst"],
            "edge_type": r["edge_type"],
            "properties": redact_data(json.loads(r["properties"])),
        } for r in rows]

    def get_attack_surface(self, host_ip: str) -> dict:
        """
        Get the full attack surface for a host:
          - Services (ports, versions)
          - Known vulnerabilities
          - Available credentials
          - Trust relationships
          - Active sessions
        """
        asset_id = f"asset:{host_ip}"
        result = {
            "host": host_ip,
            "asset": self.get_node(asset_id),
            "services": [],
            "vulnerabilities": [],
            "credentials": [],
            "trusts": [],
            "sessions": [],
        }

        # Get services via RUNS_SERVICE edges
        svc_edges = self.get_edges_from(asset_id, EdgeType.RUNS_SERVICE)
        for edge in svc_edges:
            svc_node = self.get_node(edge["dst"])
            if svc_node:
                result["services"].append(svc_node["properties"])

                # Get vulns for this service
                vuln_edges = self.get_edges_from(
                    edge["dst"], EdgeType.VULNERABLE_TO)
                for ve in vuln_edges:
                    vuln_node = self.get_node(ve["dst"])
                    if vuln_node:
                        result["vulnerabilities"].append(
                            vuln_node["properties"])

        # Get credentials that CAN_ACCESS this host
        cred_edges = self.get_edges_to(asset_id, EdgeType.CAN_ACCESS)
        for edge in cred_edges:
            cred_node = self.get_node(edge["src"])
            if cred_node:
                result["credentials"].append(cred_node["properties"])

        # Get trust relationships
        trust_out = self.get_edges_from(asset_id, EdgeType.TRUSTS)
        trust_in = self.get_edges_to(asset_id, EdgeType.TRUSTS)
        for edge in trust_out:
            result["trusts"].append({
                "direction": "outbound",
                "target": edge["dst"],
                "properties": edge["properties"]
            })
        for edge in trust_in:
            result["trusts"].append({
                "direction": "inbound",
                "source": edge["src"],
                "properties": edge["properties"]
            })

        # Get active sessions
        sess_edges = self.get_edges_to(asset_id, EdgeType.SESSION_TO)
        for edge in sess_edges:
            sess_node = self.get_node(edge["src"])
            if sess_node:
                result["sessions"].append(sess_node["properties"])

        return result

    def get_credentials_for_host(self, host_ip: str) -> list[dict]:
        """Get all credentials that can access a specific host."""
        asset_id = f"asset:{host_ip}"
        cred_edges = self.get_edges_to(asset_id, EdgeType.CAN_ACCESS)
        creds = []
        for edge in cred_edges:
            cred_node = self.get_node(edge["src"])
            if cred_node:
                cred_data = cred_node["properties"].copy()
                cred_data["access_method"] = edge["properties"].get(
                    "method", "unknown")
                creds.append(cred_data)
        return creds

    def find_paths(self, src_id: str, dst_id: str,
                   max_depth: int = 5) -> list[list[str]]:
        """
        BFS to find all attack paths from src to dst.
        Returns list of paths, each path is [node, edge_type, node, ...].
        """
        # Build adjacency list
        adj: dict[str, list[tuple[str, str]]] = {}
        with self._connect() as conn:
            rows = conn.execute('SELECT src, dst, edge_type FROM edges').fetchall()
        for r in rows:
            src = r["src"]
            if src not in adj:
                adj[src] = []
            adj[src].append((r["dst"], r["edge_type"]))

        # BFS
        all_paths = []
        queue = deque([(src_id, [src_id])])
        visited_paths = set()

        while queue:
            current, path = queue.popleft()

            if current == dst_id:
                path_key = "->".join(path)
                if path_key not in visited_paths:
                    visited_paths.add(path_key)
                    all_paths.append(path)
                continue

            if len(path) > max_depth * 2:  # node-edge-node = 2 per hop
                continue

            for neighbor, edge_type in adj.get(current, []):
                if neighbor not in path:  # prevent cycles
                    new_path = [*path, f"-[{edge_type}]->", neighbor]
                    queue.append((neighbor, new_path))

        return all_paths

    def get_pivot_targets(self, compromised_host: str) -> list[dict]:
        """
        Get potential lateral movement targets from a compromised host.
        Looks at:
          - TRUSTS relationships
          - Internal IPs discovered
          - Shared credentials
          - Network adjacency
        """
        asset_id = f"asset:{compromised_host}"
        targets = []
        seen = set()

        # Direct trust relationships
        trust_edges = self.get_edges_from(asset_id, EdgeType.TRUSTS)
        for edge in trust_edges:
            if edge["dst"] not in seen:
                seen.add(edge["dst"])
                node = self.get_node(edge["dst"])
                targets.append({
                    "target": edge["dst"],
                    "method": "trust",
                    "details": node["properties"] if node else {},
                })

        # Pivot via shared credentials
        # Get all creds for this host, then find other hosts they can access
        cred_edges = self.get_edges_to(asset_id, EdgeType.CAN_ACCESS)
        for ce in cred_edges:
            # Find other hosts this credential can access
            other_access = self.get_edges_from(ce["src"], EdgeType.CAN_ACCESS)
            for oa in other_access:
                if oa["dst"] != asset_id and oa["dst"] not in seen:
                    seen.add(oa["dst"])
                    node = self.get_node(oa["dst"])
                    targets.append({
                        "target": oa["dst"],
                        "method": "shared_credential",
                        "credential": ce["src"],
                        "details": node["properties"] if node else {},
                    })

        # PIVOTS_TO explicit edges
        pivot_edges = self.get_edges_from(asset_id, EdgeType.PIVOTS_TO)
        for edge in pivot_edges:
            if edge["dst"] not in seen:
                seen.add(edge["dst"])
                node = self.get_node(edge["dst"])
                targets.append({
                    "target": edge["dst"],
                    "method": "pivot",
                    "details": node["properties"] if node else {},
                })

        return targets

    # LLM CONTEXT GENERATION

    def to_llm_context(self, target_ip: str) -> str:
        """
        Generate a formatted text summary for injection into LLM prompts.
        Includes all known intel about a target.
        """
        surface = self.get_attack_surface(target_ip)
        lines = []

        # Header
        asset_props = surface.get("asset", {})
        if asset_props:
            props = asset_props.get("properties", {})
            lines.append(f"═══ CAMPAIGN INTEL FOR {target_ip} ═══")
            if props.get("os"):
                lines.append(f"OS: {props['os']}")
            if props.get("hostname"):
                lines.append(f"Hostname: {props['hostname']}")
            if props.get("rooted"):
                lines.append("STATUS: *** ROOT ACCESS ACHIEVED ***")

        # Services
        if surface["services"]:
            lines.append("\n── SERVICES ──")
            for svc in surface["services"]:
                port = svc.get("port", "?")
                name = svc.get("service_name", "unknown")
                ver = svc.get("version", "")
                state = svc.get("state", "open")
                web = svc.get("web_app", "")
                line = f"  Port {port}/{svc.get('protocol', 'tcp')} [{state}] {name}"
                if ver:
                    line += f" {ver}"
                if web:
                    line += f" ({web})"
                lines.append(line)

        # Vulnerabilities
        if surface["vulnerabilities"]:
            lines.append("\n── VULNERABILITIES ──")
            for vuln in surface["vulnerabilities"]:
                confirmed = "CONFIRMED" if vuln.get("confirmed") else "possible"
                lines.append(
                    f"  [{vuln.get('severity', 'medium').upper()}] "
                    f"{vuln.get('vuln_id', '?')}: "
                    f"{vuln.get('name', 'Unknown')} ({confirmed})"
                )

        # Credentials
        if surface["credentials"]:
            lines.append("\n── ACTIVE CREDENTIALS ──")
            for cred in surface["credentials"]:
                verified = "✓" if cred.get("verified") else "?"
                lines.append(
                    f"  [{verified}] {cred.get('service', '?')}://"
                    f"{cred.get('username', '?')}:{cred.get('secret', '***')}"
                    f" (source: {cred.get('source', 'unknown')})"
                )

        # Trust relationships
        if surface["trusts"]:
            lines.append("\n── TRUST RELATIONSHIPS ──")
            for trust in surface["trusts"]:
                if trust["direction"] == "outbound":
                    lines.append(f"  → Trusts: {trust['target']}")
                else:
                    lines.append(f"  ← Trusted by: {trust['source']}")

        # Active sessions
        if surface["sessions"]:
            lines.append("\n── ACTIVE SESSIONS ──")
            for sess in surface["sessions"]:
                lines.append(
                    f"  {sess.get('session_type', '?')}: "
                    f"{sess.get('username', '?')}@{sess.get('host', '?')} "
                    f"({'active' if sess.get('active') else 'inactive'})"
                )

        if not lines:
            return "No prior campaign context for this target."

        return "\n".join(lines)

    # STATISTICS

    def stats(self) -> dict:
        """Get counts by node type and edge type."""
        result = {"nodes": {}, "edges": {}, "total_nodes": 0, "total_edges": 0}

        with self._connect() as conn:
            # Node counts
            rows = conn.execute(
                'SELECT type, COUNT(*) as cnt FROM nodes GROUP BY type'
            ).fetchall()
            for r in rows:
                result["nodes"][r["type"]] = r["cnt"]
                result["total_nodes"] += r["cnt"]

            # Edge counts
            rows = conn.execute(
                'SELECT edge_type, COUNT(*) as cnt FROM edges GROUP BY edge_type'
            ).fetchall()
            for r in rows:
                result["edges"][r["edge_type"]] = r["cnt"]
                result["total_edges"] += r["cnt"]

        return result

    def clear(self):
        """Clear all data. Use with caution."""
        with self._connect() as conn:
            conn.execute('DELETE FROM edges')
            conn.execute('DELETE FROM nodes')
