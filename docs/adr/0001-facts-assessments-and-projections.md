# ADR 0001: Facts, assessments, and projections are separate contracts

- Status: accepted
- Date: 2026-07-15

## Context

OCTOPUS receives repeated, partial, inferred, and sometimes contradictory tool
observations. Treating every parsed value as current truth made graph edges,
target state, and reports disagree. It also made a candidate CVE look like a
verified vulnerability when a renderer ignored provenance.

## Decision

`FactStore` is the durable source of observed evidence. A canonical fact is
identified inside one scan by `(scan_id, host, type, value)` and retains its
observations and source execution IDs.

`FactAssessmentStore` records the current judgement over a fact and immutable
assessment history. Its statuses are `observed`, `inferred`, `verified`, and
`contradicted`. Promotion requires an assessment reason and evidence/source
references; contradiction does not delete the underlying evidence.

Entity identity is normalized by `core/knowledge/identity.py`. The persistent
`KnowledgeGraph`, per-scan `TargetModel`, lightweight `AssetGraph`, and report
are projections. They may be rebuilt from facts and assessments and may not
silently become a second source of truth.

Projection writes are idempotent. Edges carry fact/evidence IDs, assessment
state, confidence reference, first/last-seen data, scan/scope provenance, and
contradiction state. Verified-path queries default to verified evidence and
explain missing links; inferred paths require an explicit option.

## Consequences

- A raw observation or CVE match remains a candidate until assessed.
- Root or session access is an access finding, not automatically a
  vulnerability.
- Consumers must tolerate projection schema rebuilds and identity-version
  migrations.
- Tests must cover duplicate ingestion, contradiction, provenance, and
  idempotent replay.

## Rejected alternatives

- Using the knowledge graph as the write authority would duplicate FactStore
  transaction and observation semantics.
- Mutating fact rows to represent the latest judgement would erase history.
- Letting each projection invent identifiers would make cross-store joins and
  replay nondeterministic.
