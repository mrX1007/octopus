# Canonical entity identity and graph projection

Status: implemented  
Identity normalization version: `1.0`  
KnowledgeGraph schema version: `2.0`  
Graph projection schema version: `1.0`  
Verified-path result schema version: `1.0`

## Ownership

`FactStore` remains the evidence source of truth. `FactAssessmentStore` owns the
current observed/inferred/verified/contradicted judgement. The other models are
rebuildable consumers:

| Consumer | Role | Persistence |
|---|---|---|
| `KnowledgeGraph` | cross-scan semantic projection with aliases and migration | SQLite |
| `TargetModel` | normalized per-scan planning/read model | none |
| `AssetGraph` | compact per-scan context/UI graph | none |
| report/path queries | derived output with evidence chains | none |

`GraphProjectionService` reads facts through `FactStore`; it never inserts or
updates a fact or assessment. Pipeline ingress projects only after the fact
transaction commits. A graph outage therefore cannot roll back or silently
replace evidence, and replaying the fact IDs repairs the projection.

## Canonical identity contract

Canonical IDs have the form `<kind>:v1:<sha256-prefix>`. The digest covers the
entity kind, normalization version, and normalized components. It does not
contain credential references or secret plaintext.

| Kind | Identity components |
|---|---|
| asset | IP/DNS address kind and normalized address |
| service | canonical asset, port, protocol |
| endpoint | scheme, normalized host, effective port, normalized path and query |
| identity | normalized username/type plus domain or host scope |
| credential | canonical identity, opaque `secret://` reference, type, service and asset scope |
| session | external session ID, session type, asset and identity scope |
| vulnerability | CVE/CWE/module/custom namespace and normalized key |

DNS names are IDNA/lowercase without a trailing dot; IP addresses use
`ipaddress` compressed form. HTTP default ports, fragments, dot segments and
percent-encoding are normalized. Query order remains significant. Endpoint
userinfo is rejected. A credential canonicalizer accepts only an opaque secret
reference.

Legacy IDs are aliases, not alternate primary identities. The protocol-free
`svc:<host>:<port>` alias is retained only for TCP because it cannot identify a
UDP service safely. When an inherently ambiguous historical alias already
exists, the first mapping is kept; canonical or protocol-aware IDs are required
for deterministic access.

## Persistent schema and migration

Schema `2.0` adds:

- `knowledge_graph_schema` with explicit identity-normalization version;
- `node_aliases` from legacy/display identity to canonical node ID;
- `updated_at` for edges;
- `graph_fact_projections`, keyed by fact, current assessment and normalization
  version, with a semantic fingerprint and emitted node/edge IDs.

Opening an unversioned legacy graph performs one transaction that canonicalizes
recognized nodes, merges collisions, remaps and deduplicates edges, preserves
the earliest `created_at` and latest `updated_at`, records aliases, redacts
properties, and then records schema `2.0`. An unknown recorded schema fails
closed. Reopening a migrated graph is a no-op.

## Projection and provenance

Every fact projects its scoped asset. Recognized facts also project services,
endpoints, discovered assets, scoped identities, credentials, sessions and
vulnerabilities with typed relationships. An internal service is attached to
its own asset; the scan target receives a `discovered_asset` relationship.

Each node/edge projection carries:

- fact and evidence fact IDs;
- current assessment ID/status/confidence and assessment history references;
- source execution IDs;
- first/last seen timestamps;
- scan and host scope;
- sources and normalization/projection versions;
- per-fact current provenance;
- contradiction state (`none`, `mixed`, or `contradicted`).

Repeated projection of the same fact-assessment fingerprint returns
`unchanged`. A new assessment creates a new ledger entry and updates that
fact's current provenance. Multiple facts supporting the same edge remain
independent: contradicting one produces `mixed` while another verified fact
keeps the relationship verified. Only when all current support is contradicted
does the edge become contradicted.

## Evidence path query

`KnowledgeGraph.find_verified_paths()` and `find_evidence_paths()` return a
versioned structured result. Default mode admits only verified edges;
`include_inferred=True` also admits inferred edges. Observed, contradicted and
unassessed edges are excluded. Every returned step includes its current
evidence chain, assessment, confidence and source execution IDs. An edge with
no assessment reference or evidence fact ID fails closed as
`missing_evidence_chain`.

When no eligible path exists, `missing_link` distinguishes:

- `unknown_node`;
- `no_structural_path` within the bounded depth;
- `excluded_edges`, with the shortest structural route and a reason for every
  ineligible step.

The older `find_paths()` remains a structural compatibility query and resolves
aliases, but it makes no evidence claim.

## Replay and repair

The projection is deterministic for a fact row, its current assessment and the
normalization/projection versions. Repair one set with
`GraphProjectionService.project_fact_ids(ids)` or rebuild a scan with
`project_scan(scan_id, host)`. `KnowledgeGraph.clear()` clears nodes, aliases,
edges and the projection ledger while retaining schema metadata, after which a
scan replay rebuilds the graph.

Contract coverage lives in `tests/test_entity_identity.py` and
`tests/test_knowledge_graph_projection.py`.
