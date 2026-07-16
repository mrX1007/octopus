# SQLite stores and migration contract

This inventory covers first-party durable SQLite state introduced or consumed
by the pipeline. Runtime configuration may relocate files; table ownership and
schema semantics do not change.

| Store owner | Version | Principal tables | Authority and retention |
| --- | --- | --- | --- |
| `FactStore` | evolving compatible base schema | `facts`, `fact_observations`, `hypotheses`, `command_results` | Durable evidence and execution-result source of truth. Canonical fact uniqueness is `(scan_id, host, type, value)`; observations remain separate. |
| `FactAssessmentStore` | `1.1` | `fact_assessment_schema`, `fact_assessments`, `fact_assessment_evidence`, `fact_assessment_executions`, `fact_assessment_heads` | Immutable judgement history plus one current head and stable rule ID per fact. Stored in the FactStore database. |
| `MissionStore` | `1.0` | `mission_lifecycle_schema`, `missions`, `mission_tasks`, `mission_task_dependencies`, `mission_task_attempts` | Crash-recoverable mission/task state, dependency graph, attempts, outcomes, and evidence/execution references. |
| `KnowledgeGraph` | `2.0` | `knowledge_graph_schema`, `nodes`, `edges`, `node_aliases`, `graph_fact_projections` | Rebuildable semantic projection with canonical entity normalization metadata. |
| `ProviderTelemetryStore` | `1.0` | `provider_telemetry_schema`, `provider_telemetry_events` | Bounded provider/capability/target-class observations used for selection; not mission truth. |
| `DecisionTraceStore` | `1.0` | `decision_trace_schema`, `decision_events` | Bounded, idempotent decision events. Metrics are calculated from these events and the report projection. |
| `SecretStore` | implementation schema | `secrets` | Encrypted secret values referenced by other stores. Plaintext is revealed only at a narrow execution consumer. |

## Transaction and identity rules

- Schema creation/version validation and legacy backfill run inside write
  transactions. Unsupported explicit versions fail the dependent component
  instead of guessing a downgrade.
- Fact ingestion serializes first observation and uses a database unique index,
  so concurrent duplicate input converges on one canonical fact.
- Assessment transitions use deterministic transition keys. Replaying one
  transition does not create a second assessment.
- Mission identities, task keys, and attempt numbers are stable. Only one
  running attempt per task is permitted by a partial unique index.
- Graph projection identity is `(fact_id, assessment_id,
  normalization_version)` and stores a projection fingerprint.
- Provider and decision events use stable unique event keys/IDs and enforce
  bounded retention after insert.
- SQLite foreign keys, busy timeouts, rollback-on-error, and WAL where supported
  are part of the persistence boundary.

## Version changes

A schema change requires all of the following:

1. A named component schema constant and an explicit supported-version check.
2. An idempotent, transactional forward migration or a documented rebuild from
   an authoritative store.
3. A fixture from the previous version and tests for forward migration,
   concurrent initialization, replay, and restart.
4. Redaction review for every new text/JSON column.
5. A migration note describing backup, validation, rollback, and whether old
   binaries can still read the database.

Do not edit a versioned table in place while keeping the same schema version.
Additive columns on the compatibility base FactStore schema must have safe
defaults and an `_ensure_column` migration. A semantic or destructive change
needs a new versioned component or a version bump.

## Backup, validation, and rollback

Stop writers and copy the database together with its `-wal` and `-shm` files,
or use SQLite's online backup API. After upgrade, run `PRAGMA integrity_check`,
open every store with the new binary, replay the migration fixture, and verify
schema/version rows and counts.

Rollback means restoring the pre-upgrade backup and the previous application
binary. It does not mean deleting version rows. `KnowledgeGraph`, provider
telemetry, and decision trace can be discarded and rebuilt when their owning
docs explicitly allow it; facts, assessments, mission state, and secrets must
be restored rather than reconstructed from projections.
