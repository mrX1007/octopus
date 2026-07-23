# Provider selection, telemetry, and fallback

Status: implemented runtime boundary  
Selection/trace schema: `1.0`  
Telemetry schema: `1.0`

## Ownership

`PipelineRuntime` owns one lazy `ProviderTelemetryStore`, `ProviderSelector`,
and `ProviderFallbackExecutor`. The telemetry database is separate from the
fact database (`data/provider-telemetry.db` by default, or a sibling database
for a custom fact store). Telemetry is advisory: `FactStore` remains the
evidence authority and telemetry failures never rewrite an action result.

The selector consumes existing `ActionCatalog` descriptors. It does not invoke
checks or providers. Applicability and a preliminary policy decision can reject
a candidate, but neither decision grants execution authority. `ActionExecutor`
always performs the authoritative policy check again immediately before each
provider call.

Production mission dispatch supplies a bounded set of the task's concrete
commands to `PipelineRuntime`. The runtime resolves only decorator-registry
commands to canonical action IDs, keeps command strings in the in-memory
`ActionRequest`, and excludes active/manual-gated alternatives. Only task
profiles classified `passive`, `safe`, `check_only`, or `post_access_read` can
supply production fallback candidates. Active/change/unknown profiles remain
single-provider explicit dispatch and never opt into automatic fallback.

## Bounded telemetry

Events are keyed by provider action ID, capability, and a non-identifying target
class. They record dependency availability, scope compatibility, active risk,
duration, normalized outcome, useful and duplicate fact yield, parser items and
errors, partial-output ingestion, and retryability. Raw targets and provider
output are not stored.

The store retains at most 100 events per key and 10,000 total by default.
Both limits are clamped to hard upper bounds. An execution ID makes repeated
recording idempotent. SQLite writes use an immediate transaction; pruning is in
the same transaction. Schema versions other than `1.0` fail closed.

## Ranking and explanation

Eligible candidates receive a deterministic score from a neutral baseline.
Success, dependency/scope availability, parser quality, and useful fact yield
raise it. Timeouts, failures, unavailable results, duplicates, duration, and
active risk lower it. Candidates with no history remain usable and tie-break by
canonical action ID.

Registered-tool active risk is classified by the same pure policy rule used by
the final approval gate, including ordinary manual-gated registry tools and
argument-sensitive plugin/cPanel gateways. The trace carries both the numeric
penalty and the typed `read_only`/`active` class.

`ProviderSelection` contains the chosen ID, ranked eligible candidates, rejected
candidates, and every score/rejection reason. The target is represented only by
class such as `dns`, `ip4_private`, or `url_https_dns`. Candidate input and trace
sizes are bounded.

## Fallback contract

At most eight ranked providers are attempted. Fallback is permitted only for:

- `unavailable`;
- `timeout`;
- `failed` with an allowlisted typed transient error class or explicit
  `metadata.retryable=true`.

`partial`, `blocked`, `cancelled`, `succeeded`, and untyped failures are
terminal for provider selection. When a retryable result contains partial
stdout/stderr, its ingestion callback must complete before another provider is
called. Missing or failed ingestion stops the chain. Each attempt records the
ingestion outcome, retry classification, whether fallback occurred, and its
stop reason.

For production missions, that callback enters
`PipelineRuntime.complete_execution()` with the scan-generation fence captured
before dispatch. Partial facts, command result, assessment/projection work, and
attempt provenance are therefore durable before fallback. The final provider
result then crosses the same completion ingress once at the normal pipeline
boundary.

Policy denial is not provider unavailability. Selection and final
reauthorization retain a secret-safe typed `PolicyDenial` (phase, reason code,
decision reference), and `ProviderRunResult.status` is `blocked`. A final denial
is terminal even when an earlier check produced a successful check result; no
later provider runs.

Three consecutive recent `unavailable` events open a provider circuit. The
candidate remains traceable but is rejected until the cooldown elapses; a
post-cooldown selection is marked half-open and receives a score penalty.
The breaker is derived from bounded telemetry, so a newer successful/failed
attempt closes the repeated-unavailable sequence without a second health store.

Contract coverage is in `tests/test_provider_selection.py`.
