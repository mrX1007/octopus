# Evidence reporting and decision observability

## Canonical report

`core/ai/report_schema.py` owns machine report schema `1.0`. Rendering the same
persisted snapshot produces stable item/report IDs and a snapshot time derived
from inputs rather than the wall clock. Each section is capped at 256 items;
evidence chains and reference lists are independently bounded. Omitted counts
remain visible in the summary.

Sections have fixed order and distinct meaning:

| Section | Promotion rule |
| --- | --- |
| `verified_vulnerabilities` | Current verified vulnerability assessment with reason, evidence chain, and source execution IDs. |
| `access_findings` | Independently verified authentication/session/system access. Access is not converted to a vulnerability. |
| `misconfigurations` | Configuration/security observations; verification state remains explicit. |
| `observations` | Parsed evidence that is neither contradicted nor promoted to a stronger semantic class. |
| `hypotheses_candidates` | Hypotheses, CVE/exploit candidates, and incomplete vulnerability claims with a verification gap. |
| `attempted_unverified` | Check/action was attempted but independent verification is absent. |
| `coverage_gaps` | Required or expected surface remains untested/unknown. |
| `policy_blocked_degraded_checks` | Policy denial, unavailable provider, partial, timeout, cancellation, or failure. |
| `cleanup_outcomes` | Cleanup succeeded, failed, was skipped, or remains unknown independently of action outcome. |

All values pass through recursive redaction and JSON-safe bounded normalization.
The machine report is added by `core/ai/reporting.py`, used by
`TraceReporter`, and passed from the CLI adapter with facts, hypotheses,
command results, scan identity, and target. Legacy fields remain compatibility
views and must not be used to promote an item.

## Decision trace

`DecisionTraceStore` persists schema `1.0` events with stable `event_id` and
`scope_key`. Events record mission/task/goal, candidates and rejected reasons,
chosen action, capability/policy references, supporting facts, expected/actual
outcome, duration/cost, retry/fallback counts, and state transition. Per-scope
and global retention bounds are enforced after every idempotent insert.

The store records decisions, not raw prompts or full stdout. Text/collections
are bounded, secrets are redacted, and unexpected provider exception messages
are reduced to safe outcome data or an error class at their owning boundary.

## Metrics

Decision metrics schema `1.0` defines explicit denominators for:

- time to first useful and first verified evidence;
- useful and parsed facts per executed tool;
- duplicate result and no-op rates;
- parser yield and candidate-to-verification conversion;
- invalid planner, provider fallback, retry, and timeout rates;
- durable resume success and report evidence completeness;
- total recorded decision duration and estimated cost units.

An inapplicable rate is `null`, not zero. Metrics are snapshot projections and
can be rebuilt from facts, command results, task outcomes, decision events, and
the canonical report. They do not drive mission recovery.

## Change rules

A new report section or semantic promotion rule requires a schema version bump,
contract fixture, legacy-renderer review, migration note, and evidence/redaction
tests. A new decision event must remain bounded, use stable identity, document
metric impact, and avoid duplicating authoritative mission or fact state.
