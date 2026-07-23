# SQLite stores and migration contract

This inventory covers first-party durable SQLite state introduced or consumed
by the pipeline. Runtime configuration may relocate files; table ownership and
schema semantics do not change.

| Store owner | Version | Principal tables | Authority and retention |
| --- | --- | --- | --- |
| `FactStore` | evolving compatible base schema | `facts`, `fact_observations`, `fact_observation_executions`, `hypotheses`, `command_results`, `scan_completion_generations`, `command_completion_claims`, `fact_assessment_projection_outbox` | Durable evidence and execution-result source of truth. Canonical fact uniqueness is `(scan_id, host, type, value)`; observations retain source/method/execution provenance. Retained keyed scan generations and completion claims fence reset races and conflicting idempotency-key reuse before parsing, while the outbox durably repairs the graph read model after assessment changes. |
| `FactAssessmentStore` | `1.1` | `fact_assessment_schema`, `fact_assessments`, `fact_assessment_evidence`, `fact_assessment_executions`, `fact_assessment_heads` | Immutable judgement history plus one current head and stable rule ID per fact. Stored in the FactStore database. |
| `MissionStore` facade; schema/migrations in `core.ai.mission_store_schema` | `1.4` | `mission_lifecycle_schema`, `missions`, `mission_tasks`, `mission_task_dependencies`, `mission_task_attempts`, `mission_task_retry_commands`, `mission_evaluated_fact_snapshots` | Crash-recoverable mission/task state, scoped versioned task identity, retry/backoff scheduling, attempts, outcomes, and complete content-addressed evaluated-fact snapshots referenced by tasks. The facade composes focused task, replan, codec, and maintenance layers without creating another store. |
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
- Versioned execution completion reserves a hashed idempotency key before
  parsing. Its scope and request fingerprint are immutable; exact replay reads
  the completed result, while an abandoned pending owner can be replaced only
  after its bounded lease expires. Each completion-owned fact insert validates
  and renews that owner in the same immediate write transaction. `clear_scan()`
  rejects an unexpired pending owner, advances a retained generation keyed from
  the scan identity, and fences pre-claim or expired owners before deleting scan
  state. Production captures that generation before dispatch; generation-only
  tokens protect legacy completions without an idempotency key as well.
- Assessment transitions use deterministic transition keys. Replaying one
  transition does not create a second assessment.
- Fact batches read facts, observations, assessment heads/provenance, and
  execution outcomes inside one explicit deferred transaction and evaluate
  freshness at one captured instant.
- Mission identities, scoped/versioned task keys, and attempt numbers are
  stable. Only one running attempt per task is permitted by a partial unique
  index. Compatibility `agent/task` keys are deliberately non-unique and may
  be used without a typed scope only when they resolve to one row.
- Typed task-scope entity IDs must pass the canonical graph identity validator;
  legacy labels use a distinct keyed legacy-scope codec. Evaluated snapshot
  payloads are mission-owned and checked against their content-addressed
  reference when resolved after restart.
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
