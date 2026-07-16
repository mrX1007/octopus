# Fact assessment contract

## Boundary

`FactStore` remains the source of truth for observations. A fact row says that
the pipeline recorded a value; its type, task outcome, parser confidence, or
tool exit status does not by itself prove a security conclusion.

`FactAssessmentStore` owns the separate, versioned judgement attached to a
fact. It is composed by `FactStore` and exposed by `PipelineRuntime` as the same
instance. The assessment tables share the FactStore SQLite database so fact
and evidence references use database foreign keys.

The current schema version is `1.1`. Version `1.1` adds a mandatory stable
`rule_id` to every transition. Version `1.0` databases are forward-migrated
with the conservative `fact.assessment.legacy.v1` rule for existing history.

## Status and confidence

The canonical statuses are:

- `observed`: a direct ingress observation;
- `inferred`: a deterministic or analytical conclusion derived from other
  facts or a read model;
- `verified`: an explicit conclusion with a persisted evidence chain;
- `contradicted`: the current evidence conflicts with the assessed fact.

Confidence is an independent integer from 0 through 100. It does not replace
status. In particular, a high-confidence observation is not automatically a
verified finding.

Every assessment reason has a machine-stable lowercase `rule_id`. Human text
may improve without becoming an API. Manual callers default to
`fact.assessment.manual_<status>.v1`; ingress, migration, corroboration, and
contradiction use their own named rules.

New ingress facts receive an initial assessment in the fact transaction.
Facts with valid `derived_from` provenance start as `inferred`; other facts
start as `observed`. Repeated observations may add execution provenance and
increase confidence, but they do not downgrade a later verified or
contradicted assessment.

## Freshness and coverage policy

Freshness is a read-time derivation and never rewrites the fact or its base
confidence. `FreshnessPolicy` version `1.0` uses deterministic maximum ages:
24 hours by default, shorter bounds for access and service-status facts, and a
six-hour bound for vulnerability facts. Deployments and tests may inject a
different policy explicitly.

Serialized canonical facts expose `freshness_status`, `coverage_status`, and a
`freshness` object with the policy version, rule ID, observation/evaluation
times, maximum age, and actual age. A timeout is `unknown` freshness with
`degraded` coverage under `fact.coverage.timeout.v1`; it is never negative
evidence. When a fact has multiple producing executions, the chronologically
latest persisted command outcome (with command-result row ID as the stable
tie-breaker) controls freshness and coverage. Therefore success followed by a
timeout is unknown/degraded, while a later success restores fresh/complete
coverage. Capability summaries consume these markers. Legacy dictionaries
without them remain `not_assessed`.

## Automatic scoped rules

Two observations of one canonical fact promote an `observed` or `inferred`
assessment to `verified` only when at least two distinct keyed execution-
provenance IDs have latest persisted outcomes of `succeeded`. Failed, partial,
blocked, unavailable, cancelled, and timed-out outcomes do not corroborate.
Provider labels alone do not establish independence. A `contradicted` head is
never automatically promoted by a duplicate observation or idempotent
provenance attachment. The stable rule is
`fact.corroborated.independent_execution.v1`.

Automatic contradiction recognizes only explicit opposite assertion markers
and requires the same scan, normalized target, fact type, semantic subject,
configured time window, and disjoint execution provenance. The later assertion
marks the older assessment contradicted with the newer fact as evidence under
`fact.contradicted.scoped_opposite.v1`. Both sides require latest persisted
`succeeded` outcomes. The opposing execution remains provenance of the
evidence fact; it is never copied into the older fact as if it had produced the
same claim. Different targets, subjects, expired windows, reused execution
IDs, or unsuccessful outcomes cannot contradict one another.

`FactStore.add_command_result()` persists the command result and re-evaluates
all directly and scope/time-dependent facts in the same SQLite transaction.
This makes corroboration and contradiction independent of whether fact rows or
opposing successful outcomes arrived first: readers observe either the old
state or the committed result plus all rule transitions, never an intermediate
combination.

## Append-only transitions

`fact_assessments` is an append-only history in the application contract.
`fact_assessment_heads` is the mutable pointer to the current assessment. A
new judgement records `supersedes_assessment_id`; it never overwrites the fact
or deletes the previous judgement.

Repeating the current semantic judgement is idempotent. Re-applying an older
judgement after a contradiction creates a new transition, because it represents
a real state change. Semantic and transition identities are keyed digests, so
idempotency does not depend on mutable redacted display text.

The supporting tables keep ordered evidence fact IDs and source execution IDs.
Evidence facts must exist and belong to the same scan as the assessed fact.
`verified` and `contradicted` require a non-empty evidence chain. Different
hosts in the same scan are allowed so later attack-path assessments can cross
assets without crossing scan scope.

## Verification behavior

`EvidenceVerifier` now requires an explicit non-empty `required_evidence`
list. It resolves requirements against non-contradicted facts and returns the
supporting fact IDs.

- When every requirement maps to persisted facts, it creates a
  `verified_claim` with a `verified` assessment.
- When a requirement is satisfied only by a derived context/read-model term,
  it creates an `inferred_claim` with an `inferred` assessment.
- Candidate, hypothesis, open-question, inferred, and analysis/LLM-produced
  facts can contribute provenance but cannot by themselves promote a claim to
  `verified`; an explicitly verified assessment can later make them hard
  evidence.
- Missing evidence rejects the hypothesis and does not create a claim fact.

The result preserves the compatibility `accepted|rejected` field while adding
`assessment_status`, `assessment_id`, `evidence_fact_ids`, and
`source_execution_ids`.

## Readers

`FactStore.get_facts()` embeds the current assessment and exposes convenience
`assessment_id` and `assessment_status` fields. Current readers use them as
follows:

- evidence verification excludes contradicted facts;
- state, context, target, surface, and capability inputs exclude contradicted
  facts;
- state exposes candidate and verified vulnerability flags separately while
  retaining the legacy `vulnerabilities_found` compatibility flag;
- context and trace reports expose bounded assessment counts and IDs;
- evidence indexes include assessment reason, evidence fact IDs, and source
  execution IDs;
- exploit action applicability blocks a matching vulnerability candidate when
  every matching assessment is contradicted, stale, or backed only by degraded
  coverage; unrelated facts do not affect applicability. The action adapters
  and the production `AIPipeline` compatibility command path use the same pure
  rule after policy authorization and before provider dispatch;
- report finding groups do not promote an assessed observation merely because
  its fact type contains `vulnerability` or a positive marker.

Pure reporting helpers retain their legacy fallback only for caller-supplied
fact dictionaries that contain no assessment fields. Facts loaded from the
canonical store always carry the assessment.

## Migration and deletion

Initialization creates the schema and backfills legacy facts once. Valid
`derived_from` rows become inferred; all other legacy rows become observed.
Legacy `verified_claim` names are deliberately not promoted without a
persisted evidence chain.

FactStore initialization also merges legacy duplicate canonical facts before
installing its unique identity index. Observation rows, derived fact IDs,
mission-attempt fact IDs, assessment histories, current heads, and assessment
evidence references are redirected to the retained fact ID.

`FactStore.clear_scan()` deletes facts after their observations, command
results, and hypotheses. Foreign-key cascades delete all assessment heads,
history, evidence links, and execution links for that scan in the same
transaction.

## Security properties

Reasons, assessor labels, and execution IDs are bounded and redacted before
persistence. If the shared `SecretStore` learns a secret later, a repeated
idempotent assessment applies one-way display redaction without changing its
semantic identity. Raw values used for idempotency are never stored as plain
hash or display fields.

This contract does not define canonical graph entity IDs, action success, or
the final report schema. Those layers consume assessment references; they do
not redefine verification. Exploit applicability may reject unusable evidence,
but its positive check and final execution authorization remain separate gates.
