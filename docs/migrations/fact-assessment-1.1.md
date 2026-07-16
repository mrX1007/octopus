# FactAssessmentStore 1.0 to 1.1

Schema `1.1` adds the non-secret `rule_id` column to `fact_assessments`.
Initialization accepts `1.0`, acquires the existing immediate write lock, adds
the column idempotently with `fact.assessment.legacy.v1`, records version `1.1`,
then runs the existing redaction and backfill checks. Assessment, evidence, and
execution rows are not deleted or rewritten.

Before upgrading, stop writers and back up the facts database together with
its WAL/SHM files (or use SQLite online backup). After upgrade, verify both
version rows, `PRAGMA integrity_check`, non-empty rule IDs, unchanged fact and
assessment counts, and focused contract tests. Rollback requires restoring the
backup with the previous binary because a `1.0` binary does not understand the
new transition field.

Freshness policy `1.0` is not a SQLite migration: it is a versioned read-time
view. Changing TTLs can change fresh/stale output but never base facts,
confidence, or assessment history.
