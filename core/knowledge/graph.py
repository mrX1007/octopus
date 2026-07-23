#!/usr/bin/env python3

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from collections import deque
from contextlib import contextmanager, suppress
from typing import Any

from core.secrets import redact_data

from .identity import (
    ENTITY_NORMALIZATION_VERSION,
    canonical_asset,
    canonical_from_legacy,
)
from .models import (
    Asset,
    Campaign,
    Credential,
    EdgeType,
    Endpoint,
    Identity,
    NodeType,
    Service,
    Session,
    Vulnerability,
)

KNOWLEDGE_GRAPH_SCHEMA_VERSION = "2.0"


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

    def __init__(self, db_path: str | None = None):
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
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
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
            conn.execute("BEGIN IMMEDIATE")
            c = conn.cursor()

            c.execute('''
                CREATE TABLE IF NOT EXISTS knowledge_graph_schema (
                    schema_version TEXT PRIMARY KEY,
                    normalization_version TEXT NOT NULL,
                    applied_at REAL NOT NULL
                )
            ''')

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
                    updated_at REAL NOT NULL DEFAULT 0,
                    UNIQUE(src, dst, edge_type)
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS node_aliases (
                    alias_id TEXT PRIMARY KEY,
                    canonical_id TEXT NOT NULL,
                    normalization_version TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(canonical_id) REFERENCES nodes(id) ON DELETE CASCADE
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS graph_fact_projections (
                    fact_id INTEGER NOT NULL,
                    assessment_id TEXT NOT NULL,
                    normalization_version TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    node_ids TEXT NOT NULL DEFAULT '[]',
                    edge_keys TEXT NOT NULL DEFAULT '[]',
                    projected_at REAL NOT NULL,
                    PRIMARY KEY(fact_id, assessment_id, normalization_version)
                )
            ''')

            c.execute('CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(edge_type)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_alias_canonical ON node_aliases(canonical_id)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_projection_fact ON graph_fact_projections(fact_id)')
            self._ensure_column(c, "edges", "updated_at", "REAL NOT NULL DEFAULT 0")

            versions = {
                str(row[0])
                for row in c.execute(
                    "SELECT schema_version FROM knowledge_graph_schema"
                ).fetchall()
            }
            unsupported = versions - {KNOWLEDGE_GRAPH_SCHEMA_VERSION}
            if unsupported:
                raise RuntimeError(
                    "Unsupported knowledge-graph schema version(s): "
                    + ", ".join(sorted(unsupported))
                )

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

            if KNOWLEDGE_GRAPH_SCHEMA_VERSION not in versions:
                self._migrate_legacy_identities(c)
                c.execute(
                    """
                    INSERT INTO knowledge_graph_schema(
                        schema_version, normalization_version, applied_at
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        KNOWLEDGE_GRAPH_SCHEMA_VERSION,
                        ENTITY_NORMALIZATION_VERSION,
                        time.time(),
                    ),
                )

    @staticmethod
    def _ensure_column(
        cursor: sqlite3.Cursor,
        table: str,
        column: str,
        definition: str,
    ) -> None:
        columns = {
            str(row[1])
            for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in columns:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _migrate_legacy_identities(self, cursor: sqlite3.Cursor) -> None:
        """Re-key legacy nodes and edges while preserving aliases and timestamps."""

        node_rows = cursor.execute(
            "SELECT id, type, properties, created_at, updated_at FROM nodes"
        ).fetchall()
        if not node_rows:
            return
        existing_aliases = cursor.execute(
            "SELECT alias_id, canonical_id FROM node_aliases"
        ).fetchall()
        canonical_nodes: dict[str, dict[str, Any]] = {}
        alias_pairs: set[tuple[str, str]] = set()
        old_to_new: dict[str, str] = {}
        for row in sorted(node_rows, key=lambda item: (float(item[4]), str(item[0]))):
            old_id = str(row[0])
            node_type = str(row[1])
            properties = self._load_properties(row[2])
            identity = canonical_from_legacy(node_type, properties)
            canonical_id = identity.entity_id if identity else old_id
            old_to_new[old_id] = canonical_id
            properties["canonical_id"] = canonical_id
            properties["normalization_version"] = (
                ENTITY_NORMALIZATION_VERSION if identity else "legacy"
            )
            legacy_ids = list(properties.get("legacy_ids") or [])
            if old_id != canonical_id:
                legacy_ids.append(old_id)
            if identity:
                legacy_ids.extend(identity.aliases)
            properties["legacy_ids"] = list(
                dict.fromkeys(item for item in legacy_ids if item and item != canonical_id)
            )
            current = canonical_nodes.get(canonical_id)
            if current is None:
                canonical_nodes[canonical_id] = {
                    "type": node_type,
                    "properties": properties,
                    "created_at": float(row[3]),
                    "updated_at": float(row[4]),
                }
            else:
                current["properties"] = self._merge_properties(
                    current["properties"],
                    properties,
                )
                current["created_at"] = min(current["created_at"], float(row[3]))
                current["updated_at"] = max(current["updated_at"], float(row[4]))
            for alias in properties["legacy_ids"]:
                alias_pairs.add((str(alias), canonical_id))
        for alias_id, old_canonical_id in existing_aliases:
            canonical_id = old_to_new.get(str(old_canonical_id), str(old_canonical_id))
            alias_pairs.add((str(alias_id), canonical_id))

        edge_rows = cursor.execute(
            """
            SELECT src, dst, edge_type, properties, created_at, updated_at
            FROM edges ORDER BY created_at, id
            """
        ).fetchall()
        canonical_edges: dict[tuple[str, str, str], dict[str, Any]] = {}
        for row in edge_rows:
            src = old_to_new.get(str(row[0]), str(row[0]))
            dst = old_to_new.get(str(row[1]), str(row[1]))
            key = (src, dst, str(row[2]))
            properties = self._load_properties(row[3])
            properties.setdefault("normalization_version", ENTITY_NORMALIZATION_VERSION)
            current = canonical_edges.get(key)
            if current is None:
                canonical_edges[key] = {
                    "properties": properties,
                    "created_at": float(row[4]),
                    "updated_at": float(row[5] or row[4]),
                }
            else:
                current["properties"] = self._merge_properties(
                    current["properties"],
                    properties,
                )
                current["created_at"] = min(current["created_at"], float(row[4]))
                current["updated_at"] = max(
                    current["updated_at"],
                    float(row[5] or row[4]),
                )

        cursor.execute("DELETE FROM edges")
        cursor.execute("DELETE FROM node_aliases")
        cursor.execute("DELETE FROM nodes")
        for node_id, item in canonical_nodes.items():
            cursor.execute(
                """
                INSERT INTO nodes(id, type, properties, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    node_id,
                    item["type"],
                    json.dumps(redact_data(item["properties"]), sort_keys=True),
                    item["created_at"],
                    item["updated_at"],
                ),
            )
        now = time.time()
        for alias_id, canonical_id in sorted(alias_pairs):
            if alias_id == canonical_id or canonical_id not in canonical_nodes:
                continue
            cursor.execute(
                """
                INSERT OR IGNORE INTO node_aliases(
                    alias_id, canonical_id, normalization_version, created_at
                ) VALUES (?, ?, ?, ?)
                """,
                (alias_id, canonical_id, ENTITY_NORMALIZATION_VERSION, now),
            )
        for (src, dst, edge_type), item in canonical_edges.items():
            cursor.execute(
                """
                INSERT INTO edges(
                    src, dst, edge_type, properties, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    src,
                    dst,
                    edge_type,
                    json.dumps(redact_data(item["properties"]), sort_keys=True),
                    item["created_at"],
                    item["updated_at"],
                ),
            )

    @staticmethod
    def _load_properties(value: Any) -> dict[str, Any]:
        try:
            loaded = json.loads(value or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
        return loaded if isinstance(loaded, dict) else {}

    @classmethod
    def _merge_properties(
        cls,
        existing: dict[str, Any],
        incoming: dict[str, Any],
    ) -> dict[str, Any]:
        merged = dict(existing)
        union_keys = {
            "assessment_refs",
            "evidence_fact_ids",
            "fact_ids",
            "legacy_ids",
            "scans",
            "scopes",
            "source_execution_ids",
            "sources",
        }
        for key, value in incoming.items():
            if value in (None, ""):
                continue
            if key in union_keys:
                previous_items = merged.get(key) or []
                left_items = (
                    previous_items
                    if isinstance(previous_items, list)
                    else [previous_items]
                )
                right = value if isinstance(value, list) else [value]
                merged[key] = list(dict.fromkeys((*left_items, *right)))
            elif key == "first_seen" and merged.get(key) is not None:
                merged[key] = min(float(merged[key]), float(value))
            elif key == "last_seen" and merged.get(key) is not None:
                merged[key] = max(float(merged[key]), float(value))
            elif key == "provenance" and isinstance(value, dict):
                previous_provenance = merged.get(key)
                existing_provenance = (
                    previous_provenance
                    if isinstance(previous_provenance, dict)
                    else {}
                )
                # Each fact owns one current provenance record. Replacing an
                # incoming fact's record is required for one-way redaction:
                # recursively merging it would retain superseded plaintext
                # execution identifiers from the prior projection.
                merged[key] = {**existing_provenance, **value}
            elif isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = cls._merge_properties(merged[key], value)
            elif key.startswith("current_"):
                merged[key] = value
            elif isinstance(value, list) and isinstance(merged.get(key), list):
                merged[key] = list(dict.fromkeys((*merged[key], *value)))
            else:
                merged[key] = value
        return merged

    @classmethod
    def _normalize_assessment_metadata(
        cls,
        properties: dict[str, Any],
    ) -> dict[str, Any]:
        """Derive the current edge/node judgement from per-fact provenance.

        Top-level lists deliberately retain historical references, except for
        source execution identifiers: those are rebuilt from each fact's
        current provenance so late redaction can purge superseded plaintext.
        The ``current_*`` fields and ``assessment_status`` describe only the
        currently effective support, so a contradicted fact cannot erase a
        second fact that still verifies the same relationship.
        """

        normalized = dict(properties)
        raw_provenance = normalized.get("provenance")
        if not isinstance(raw_provenance, dict) or not raw_provenance:
            status = str(normalized.get("assessment_status") or "")
            if status == "contradicted":
                normalized["contradiction_state"] = "contradicted"
            elif status:
                normalized.setdefault("contradiction_state", "none")
            return normalized

        records = [item for item in raw_provenance.values() if isinstance(item, dict)]
        statuses = [str(item.get("assessment_status") or "observed") for item in records]
        priority = ("verified", "inferred", "observed", "contradicted")
        effective = next((status for status in priority if status in statuses), "observed")
        effective_records = [
            item
            for item in records
            if str(item.get("assessment_status") or "observed") == effective
        ]
        normalized["assessment_status"] = effective
        if statuses and all(status == "contradicted" for status in statuses):
            normalized["contradiction_state"] = "contradicted"
        elif "contradicted" in statuses:
            normalized["contradiction_state"] = "mixed"
        else:
            normalized["contradiction_state"] = "none"

        def collect(key: str, source_records: list[dict[str, Any]]) -> list[Any]:
            values: list[Any] = []
            for record in source_records:
                raw = record.get(f"current_{key}") or record.get(key) or []
                items = raw if isinstance(raw, list) else [raw]
                values.extend(item for item in items if item not in (None, ""))
            return list(dict.fromkeys(values))

        normalized["source_execution_ids"] = collect("source_execution_ids", records)
        normalized["current_assessment_refs"] = collect(
            "assessment_refs",
            effective_records,
        )
        normalized["current_evidence_fact_ids"] = collect(
            "evidence_fact_ids",
            effective_records,
        )
        normalized["current_source_execution_ids"] = collect(
            "source_execution_ids",
            effective_records,
        )
        confidences = [
            int(item.get("confidence", 0) or 0)
            for item in effective_records
            if str(item.get("confidence", "")).strip()
        ]
        if confidences:
            normalized["confidence"] = max(confidences)
        return normalized

    def _register_aliases_in_conn(
        self,
        conn: sqlite3.Connection,
        canonical_id: str,
        aliases: tuple[str, ...] | list[str],
    ) -> None:
        now = time.time()
        for alias in dict.fromkeys(str(item) for item in aliases if item):
            if alias == canonical_id:
                continue
            conn.execute(
                """
                INSERT INTO node_aliases(
                    alias_id, canonical_id, normalization_version, created_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(alias_id) DO NOTHING
                """,
                (alias, canonical_id, ENTITY_NORMALIZATION_VERSION, now),
            )

    @staticmethod
    def _resolve_node_id_in_conn(conn: sqlite3.Connection, node_id: str) -> str:
        row = conn.execute(
            "SELECT canonical_id FROM node_aliases WHERE alias_id = ?",
            (str(node_id),),
        ).fetchone()
        return str(row[0]) if row else str(node_id)

    def resolve_node_id(self, node_id: str) -> str:
        with self._connect() as conn:
            return self._resolve_node_id_in_conn(conn, node_id)

    # NODE CRUD — Typed High-Level API

    def _upsert_node(
        self,
        node_id: str,
        node_type: NodeType,
        properties: dict,
        *,
        aliases: tuple[str, ...] | list[str] = (),
    ) -> str:
        """Insert or update a node. Returns node_id."""
        now = time.time()
        properties = redact_data(properties)
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT properties FROM nodes WHERE id = ?",
                (node_id,),
            ).fetchone()
            merged = self._merge_properties(
                self._load_properties(existing[0]) if existing else {},
                properties,
            )
            merged = self._normalize_assessment_metadata(merged)
            merged["canonical_id"] = node_id
            merged.setdefault("normalization_version", ENTITY_NORMALIZATION_VERSION)
            conn.execute(
                '''
                    INSERT INTO nodes (id, type, properties, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        type = excluded.type,
                        properties = excluded.properties,
                        updated_at = excluded.updated_at
                ''',
                (
                    node_id,
                    node_type.value,
                    json.dumps(redact_data(merged), sort_keys=True),
                    now,
                    now,
                ),
            )
            self._register_aliases_in_conn(conn, node_id, aliases)
        return node_id

    def upsert_projected_node(
        self,
        node_id: str,
        node_type: NodeType,
        properties: dict[str, Any],
        *,
        aliases: tuple[str, ...] | list[str] = (),
    ) -> str:
        """Public projection boundary; facts remain owned by ``FactStore``."""

        return self._upsert_node(node_id, node_type, properties, aliases=aliases)

    def add_asset(self, ip: str, hostname: str = "", os: str = "",
                  ports: list[int] | None = None, **kw) -> Asset:
        """Add or update a host asset."""
        asset = Asset(ip=ip, hostname=hostname, os=os,
                      ports=ports or [], **kw)
        self._upsert_node(
            asset.node_id,
            NodeType.ASSET,
            asset.to_dict(),
            aliases=asset.legacy_node_ids,
        )
        return asset

    def add_identity(self, username: str, domain: str = "",
                     identity_type: str = "local", host: str = "", **kw) -> Identity:
        """Add or update a user identity."""
        ident = Identity(username=username, domain=domain,
                         identity_type=identity_type, host=host, **kw)
        self._upsert_node(
            ident.node_id,
            NodeType.IDENTITY,
            ident.to_dict(),
            aliases=ident.legacy_node_ids,
        )
        return ident

    def add_credential(self, username: str, secret: str,
                       source: str = "", service: str = "",
                       verified: bool = False, host: str = "",
                       secret_type: str = "password") -> Credential:
        """Add or update a credential."""
        cred = Credential(username=username, secret=secret, source=source,
                          service=service, verified=verified, host=host,
                          secret_type=secret_type)
        self._upsert_node(
            cred.node_id,
            NodeType.CREDENTIAL,
            cred.to_dict(),
            aliases=cred.legacy_node_ids,
        )
        # Also ensure identity exists
        identity = self.add_identity(username, host=host)
        # Auto-link identity → credential
        self.link(identity.node_id, cred.node_id,
                  EdgeType.HAS_CREDENTIAL, source=source)
        return cred

    def add_service(self, host: str, port: int,
                    service_name: str = "", version: str = "",
                    banner: str = "", state: str = "open",
                    web_app: str = "", protocol: str = "tcp") -> Service:
        """Add or update a service on a host."""
        svc = Service(host=host, port=port, service_name=service_name,
                      version=version, banner=banner, state=state,
                      web_app=web_app, protocol=protocol)
        self._upsert_node(
            svc.node_id,
            NodeType.SERVICE,
            svc.to_dict(),
            aliases=svc.legacy_node_ids,
        )
        # Ensure asset exists and link
        asset = self.add_asset(host, ports=[port])
        self.link(asset.node_id, svc.node_id, EdgeType.RUNS_SERVICE)
        return svc

    def add_endpoint(
        self,
        url: str,
        *,
        service: str = "",
        status: str = "",
        title: str = "",
    ) -> Endpoint:
        endpoint = Endpoint(url=url, service=service, status=status, title=title)
        self._upsert_node(
            endpoint.node_id,
            NodeType.ENDPOINT,
            endpoint.to_dict(),
            aliases=endpoint.legacy_node_ids,
        )
        return endpoint

    def add_session(self, session_id: str, session_type: str = "ssh",
                    username: str = "", host: str = "") -> Session:
        """Add or update a session."""
        sess = Session(session_id=session_id, session_type=session_type,
                       username=username, host=host)
        self._upsert_node(
            sess.node_id,
            NodeType.SESSION,
            sess.to_dict(),
            aliases=sess.legacy_node_ids,
        )
        # Link identity → session → asset
        if username:
            identity = self.add_identity(username, host=host)
            self.link(identity.node_id, sess.node_id,
                      EdgeType.ACTIVE_SESSION)
        if host:
            asset = self.add_asset(host)
            self.link(sess.node_id, asset.node_id, EdgeType.SESSION_TO)
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
        self._upsert_node(
            vuln.node_id,
            NodeType.VULNERABILITY,
            vuln.to_dict(),
            aliases=vuln.legacy_node_ids,
        )
        return vuln

    def add_campaign(self, name: str, objective: str = "",
                     targets: list[str] | None = None) -> Campaign:
        """Add or update a campaign."""
        camp = Campaign(name=name, objective=objective,
                        targets=targets or [])
        self._upsert_node(camp.node_id, NodeType.CAMPAIGN, camp.to_dict())
        # Link targets
        for target_ip in (targets or []):
            asset = self.add_asset(target_ip)
            self.link(asset.node_id, camp.node_id, EdgeType.MEMBER_OF)
        return camp

    # EDGE (RELATIONSHIP) API

    def link(self, src_id: str, dst_id: str, edge_type: EdgeType,
             **properties):
        """Create a typed edge between two nodes. Idempotent."""
        now = time.time()
        properties = redact_data(properties)
        try:
            with self._connect() as conn:
                canonical_src = self._resolve_node_id_in_conn(conn, src_id)
                canonical_dst = self._resolve_node_id_in_conn(conn, dst_id)
                existing = conn.execute(
                    """
                    SELECT properties FROM edges
                    WHERE src = ? AND dst = ? AND edge_type = ?
                    """,
                    (canonical_src, canonical_dst, edge_type.value),
                ).fetchone()
                merged = self._merge_properties(
                    self._load_properties(existing[0]) if existing else {},
                    properties,
                )
                merged = self._normalize_assessment_metadata(merged)
                merged.setdefault("normalization_version", ENTITY_NORMALIZATION_VERSION)
                conn.execute(
                    '''
                    INSERT INTO edges (
                        src, dst, edge_type, properties, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(src, dst, edge_type) DO UPDATE SET
                        properties = excluded.properties,
                        updated_at = excluded.updated_at
                    ''',
                    (
                        canonical_src,
                        canonical_dst,
                        edge_type.value,
                        json.dumps(redact_data(merged), sort_keys=True),
                        now,
                        now,
                    ),
                )
            return True
        except Exception as e:
            logging.debug(f"KnowledgeGraph.link error: {e}")
            return False

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

    def get_node(self, node_id: str) -> dict | None:
        """Get a single node by ID. Returns properties + metadata."""
        with self._connect() as conn:
            canonical_id = self._resolve_node_id_in_conn(conn, node_id)
            row = conn.execute(
                'SELECT * FROM nodes WHERE id = ?', (canonical_id,)
            ).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "type": row["type"],
            "properties": redact_data(json.loads(row["properties"])),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "requested_id": str(node_id),
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
                       edge_type: EdgeType | None = None) -> list[dict]:
        """Get all outgoing edges from a node."""
        with self._connect() as conn:
            canonical_id = self._resolve_node_id_in_conn(conn, node_id)
            if edge_type:
                rows = conn.execute(
                    'SELECT * FROM edges WHERE src = ? AND edge_type = ?',
                    (canonical_id, edge_type.value)
                ).fetchall()
            else:
                rows = conn.execute(
                    'SELECT * FROM edges WHERE src = ?', (canonical_id,)
                ).fetchall()
        return [{
            "src": r["src"], "dst": r["dst"],
            "edge_type": r["edge_type"],
            "properties": redact_data(json.loads(r["properties"])),
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        } for r in rows]

    def get_edges_to(self, node_id: str,
                     edge_type: EdgeType | None = None) -> list[dict]:
        """Get all incoming edges to a node."""
        with self._connect() as conn:
            canonical_id = self._resolve_node_id_in_conn(conn, node_id)
            if edge_type:
                rows = conn.execute(
                    'SELECT * FROM edges WHERE dst = ? AND edge_type = ?',
                    (canonical_id, edge_type.value)
                ).fetchall()
            else:
                rows = conn.execute(
                    'SELECT * FROM edges WHERE dst = ?', (canonical_id,)
                ).fetchall()
        return [{
            "src": r["src"], "dst": r["dst"],
            "edge_type": r["edge_type"],
            "properties": redact_data(json.loads(r["properties"])),
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
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
        asset_id = canonical_asset(host_ip).entity_id
        result: dict[str, Any] = {
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
        asset_id = canonical_asset(host_ip).entity_id
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
            src_id = self._resolve_node_id_in_conn(conn, src_id)
            dst_id = self._resolve_node_id_in_conn(conn, dst_id)
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

    @staticmethod
    def _edge_support(
        properties: dict[str, Any],
        *,
        include_inferred: bool,
    ) -> tuple[bool, str, list[dict[str, Any]]]:
        """Return whether an edge has an auditable current evidence chain."""

        allowed = {"verified"}
        if include_inferred:
            allowed.add("inferred")
        raw_provenance = properties.get("provenance")
        if isinstance(raw_provenance, dict):
            candidates = [
                dict(item)
                for item in raw_provenance.values()
                if isinstance(item, dict)
                and str(item.get("assessment_status") or "observed") in allowed
            ]
        else:
            candidates = []
        if not candidates:
            status = str(properties.get("assessment_status") or "unassessed")
            if status not in allowed:
                return False, f"assessment_status:{status}", []
            candidates = [{
                "assessment_status": status,
                "assessment_refs": (
                    properties.get("current_assessment_refs")
                    or properties.get("assessment_refs")
                    or []
                ),
                "evidence_fact_ids": (
                    properties.get("current_evidence_fact_ids")
                    or properties.get("evidence_fact_ids")
                    or []
                ),
                "source_execution_ids": (
                    properties.get("current_source_execution_ids")
                    or properties.get("source_execution_ids")
                    or []
                ),
                "confidence": properties.get("confidence", 0),
            }]

        chain: list[dict[str, Any]] = []
        for item in candidates:
            assessment_refs = (
                item.get("current_assessment_refs") or item.get("assessment_refs") or []
            )
            evidence_fact_ids = (
                item.get("current_evidence_fact_ids")
                or item.get("evidence_fact_ids")
                or []
            )
            if not isinstance(assessment_refs, list):
                assessment_refs = [assessment_refs]
            if not isinstance(evidence_fact_ids, list):
                evidence_fact_ids = [evidence_fact_ids]
            if not assessment_refs or not evidence_fact_ids:
                continue
            source_execution_ids = (
                item.get("current_source_execution_ids")
                or item.get("source_execution_ids")
                or []
            )
            if not isinstance(source_execution_ids, list):
                source_execution_ids = [source_execution_ids]
            chain.append({
                "fact_id": item.get("fact_id"),
                "assessment_id": item.get("assessment_id") or assessment_refs[-1],
                "assessment_status": str(item.get("assessment_status") or "observed"),
                "confidence": int(item.get("confidence", 0) or 0),
                "evidence_fact_ids": list(dict.fromkeys(evidence_fact_ids)),
                "source_execution_ids": list(dict.fromkeys(source_execution_ids)),
            })
        if not chain:
            return False, "missing_evidence_chain", []
        return True, "", chain

    @staticmethod
    def _edge_paths(
        adjacency: dict[str, list[dict[str, Any]]],
        source: str,
        destination: str,
        *,
        max_depth: int,
        max_paths: int,
        include_inferred: bool | None,
    ) -> list[list[dict[str, Any]]]:
        queue: deque[tuple[str, tuple[str, ...], list[dict[str, Any]]]] = deque(
            [(source, (source,), [])]
        )
        paths: list[list[dict[str, Any]]] = []
        while queue and len(paths) < max_paths:
            current, seen_nodes, steps = queue.popleft()
            if current == destination:
                paths.append(steps)
                continue
            if len(steps) >= max_depth:
                continue
            for edge in adjacency.get(current, []):
                neighbor = str(edge["dst"])
                if neighbor in seen_nodes:
                    continue
                if include_inferred is not None:
                    supported, _reason, _chain = KnowledgeGraph._edge_support(
                        edge["properties"],
                        include_inferred=include_inferred,
                    )
                    if not supported:
                        continue
                queue.append((neighbor, (*seen_nodes, neighbor), [*steps, edge]))
        return paths

    def find_evidence_paths(
        self,
        src_id: str,
        dst_id: str,
        *,
        max_depth: int = 5,
        include_inferred: bool = False,
        max_paths: int = 100,
    ) -> dict[str, Any]:
        """Find evidence-backed paths and explain a missing eligible link.

        Observed, contradicted, and unassessed edges are excluded.  Inferred
        edges are admitted only when ``include_inferred`` is explicit.
        """

        max_depth = max(0, min(int(max_depth), 32))
        max_paths = max(1, min(int(max_paths), 1_000))
        with self._connect() as conn:
            source = self._resolve_node_id_in_conn(conn, src_id)
            destination = self._resolve_node_id_in_conn(conn, dst_id)
            known_nodes = {
                str(row[0])
                for row in conn.execute(
                    "SELECT id FROM nodes WHERE id IN (?, ?)",
                    (source, destination),
                ).fetchall()
            }
            rows = conn.execute(
                """
                SELECT id, src, dst, edge_type, properties, created_at, updated_at
                FROM edges ORDER BY id
                """
            ).fetchall()

        result: dict[str, Any] = {
            "schema_version": "1.0",
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
            "mode": "include_inferred" if include_inferred else "verified_only",
            "source": source,
            "destination": destination,
            "paths": [],
            "missing_link": None,
        }
        missing_nodes = [
            label
            for label, node_id in (("source", source), ("destination", destination))
            if node_id not in known_nodes
        ]
        if missing_nodes:
            result["missing_link"] = {
                "reason": "unknown_node",
                "missing": missing_nodes,
            }
            return result

        adjacency: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            edge: dict[str, Any] = {
                "id": int(row["id"]),
                "src": str(row["src"]),
                "dst": str(row["dst"]),
                "edge_type": str(row["edge_type"]),
                "properties": self._load_properties(row["properties"]),
                "created_at": float(row["created_at"]),
                "updated_at": float(row["updated_at"]),
            }
            adjacency.setdefault(edge["src"], []).append(edge)

        eligible_paths = self._edge_paths(
            adjacency,
            source,
            destination,
            max_depth=max_depth,
            max_paths=max_paths,
            include_inferred=include_inferred,
        )
        for raw_path in eligible_paths:
            nodes: list[str] = [source]
            steps: list[dict[str, Any]] = []
            for edge in raw_path:
                supported, _reason, chain = self._edge_support(
                    edge["properties"],
                    include_inferred=include_inferred,
                )
                if not supported:
                    continue
                nodes.append(edge["dst"])
                steps.append({
                    "from": edge["src"],
                    "to": edge["dst"],
                    "edge_type": edge["edge_type"],
                    "assessment_status": edge["properties"].get("assessment_status"),
                    "confidence": edge["properties"].get("confidence", 0),
                    "contradiction_state": edge["properties"].get(
                        "contradiction_state", "none"
                    ),
                    "evidence_chain": chain,
                })
            result["paths"].append({"nodes": nodes, "steps": steps})

        if result["paths"]:
            return result

        structural_paths = self._edge_paths(
            adjacency,
            source,
            destination,
            max_depth=max_depth,
            max_paths=1,
            include_inferred=None,
        )
        if not structural_paths:
            result["missing_link"] = {
                "reason": "no_structural_path",
                "max_depth": max_depth,
            }
            return result

        structural = structural_paths[0]
        excluded_steps: list[dict[str, Any]] = []
        for edge in structural:
            supported, reason, _chain = self._edge_support(
                edge["properties"],
                include_inferred=include_inferred,
            )
            if not supported:
                excluded_steps.append({
                    "from": edge["src"],
                    "to": edge["dst"],
                    "edge_type": edge["edge_type"],
                    "reason": reason,
                })
        result["missing_link"] = {
            "reason": "excluded_edges",
            "structural_nodes": [source, *(edge["dst"] for edge in structural)],
            "excluded_steps": excluded_steps,
        }
        return result

    def find_verified_paths(
        self,
        src_id: str,
        dst_id: str,
        *,
        max_depth: int = 5,
        include_inferred: bool = False,
        max_paths: int = 100,
    ) -> dict[str, Any]:
        """Compatibility name for the canonical evidence path query."""

        return self.find_evidence_paths(
            src_id,
            dst_id,
            max_depth=max_depth,
            include_inferred=include_inferred,
            max_paths=max_paths,
        )

    def get_pivot_targets(self, compromised_host: str) -> list[dict]:
        """
        Get potential lateral movement targets from a compromised host.
        Looks at:
          - TRUSTS relationships
          - Internal IPs discovered
          - Shared credentials
          - Network adjacency
        """
        asset_id = canonical_asset(compromised_host).entity_id
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

    def projection_record(
        self,
        fact_id: int,
        assessment_id: str,
        *,
        normalization_version: str = ENTITY_NORMALIZATION_VERSION,
    ) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT fact_id, assessment_id, normalization_version,
                       fingerprint, node_ids, edge_keys, projected_at
                FROM graph_fact_projections
                WHERE fact_id = ? AND assessment_id = ?
                  AND normalization_version = ?
                """,
                (int(fact_id), str(assessment_id), normalization_version),
            ).fetchone()
        if row is None:
            return None
        return {
            "fact_id": int(row["fact_id"]),
            "assessment_id": str(row["assessment_id"]),
            "normalization_version": str(row["normalization_version"]),
            "fingerprint": str(row["fingerprint"]),
            "node_ids": json.loads(row["node_ids"]),
            "edge_keys": json.loads(row["edge_keys"]),
            "projected_at": float(row["projected_at"]),
        }

    def record_projection(
        self,
        *,
        fact_id: int,
        assessment_id: str,
        fingerprint: str,
        node_ids: list[str],
        edge_keys: list[str],
        normalization_version: str = ENTITY_NORMALIZATION_VERSION,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO graph_fact_projections(
                    fact_id, assessment_id, normalization_version,
                    fingerprint, node_ids, edge_keys, projected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fact_id, assessment_id, normalization_version)
                DO UPDATE SET
                    fingerprint = excluded.fingerprint,
                    node_ids = excluded.node_ids,
                    edge_keys = excluded.edge_keys,
                    projected_at = excluded.projected_at
                """,
                (
                    int(fact_id),
                    str(assessment_id),
                    normalization_version,
                    str(fingerprint),
                    json.dumps(list(dict.fromkeys(node_ids)), sort_keys=True),
                    json.dumps(list(dict.fromkeys(edge_keys)), sort_keys=True),
                    time.time(),
                ),
            )

    def stats(self) -> dict:
        """Get counts by node type and edge type."""
        result: dict[str, Any] = {
            "schema_version": KNOWLEDGE_GRAPH_SCHEMA_VERSION,
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
            "nodes": {},
            "edges": {},
            "total_nodes": 0,
            "total_edges": 0,
            "projected_assessments": 0,
        }

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
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM graph_fact_projections"
            ).fetchone()
            result["projected_assessments"] = int(row["cnt"] if row else 0)

        return result

    def clear(self):
        """Clear all data. Use with caution."""
        with self._connect() as conn:
            conn.execute('DELETE FROM graph_fact_projections')
            conn.execute('DELETE FROM edges')
            conn.execute('DELETE FROM node_aliases')
            conn.execute('DELETE FROM nodes')
