# ADR 0003: Reports and decision traces are bounded evidence projections

- Status: accepted
- Date: 2026-07-15

## Context

Human-readable reports and logs previously mixed findings, access, candidates,
and operational errors. Free-form trace text was hard to compare across replay
runs and could grow without bound.

## Decision

The machine-readable evidence report uses schema `1.0` and fixed, separate
sections for verified vulnerabilities, access findings, misconfigurations,
observations, hypotheses/candidates, attempted-but-unverified actions, coverage
gaps, policy-blocked/degraded checks, and cleanup outcomes.

Verified items require a current verified assessment, evidence chain, source
execution IDs, and assessment reason. All report values pass through bounded
normalization and secret redaction. Stable IDs make repeated rendering
deterministic.

Decision events use schema `1.0` and contain bounded mission/task/goal identity,
candidates and rejection reasons, chosen action, capability/policy references,
supporting fact IDs, expected and actual outcomes, duration/cost, and state
transition. `DecisionTraceStore` uses idempotent event IDs, retention bounds,
and a SQLite schema version. Metrics are derived projections, not mutable
counters of record.

Human trace and legacy report fields remain compatibility renderers over these
canonical projections.

## Consequences

- Report consumers must select a named section rather than infer semantics from
  a generic findings list.
- Trace retention may prune old events; durable facts and mission records remain
  the reconstruction authority.
- Schema changes require a version bump, migration notes, fixtures, and contract
  tests.
- Raw stdout, plaintext secrets, and exception messages do not belong in
  decision events.

## Rejected alternatives

- Treating the human report as the machine contract is unstable and ambiguous.
- Persisting all prompts/stdout would violate boundedness and secret controls.
- Using telemetry counters as authoritative mission state would weaken crash
  recovery.
