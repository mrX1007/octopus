# ADR 0002: Actions use adapters and reauthorize immediately before execution

- Status: accepted
- Date: 2026-07-15

## Context

Registered tools, plugins, Metasploit helpers, `ExploitBase` implementations,
and legacy kill-chain functions expose different result and lifecycle shapes.
Planner approval alone is insufficient because target scope, capability, and
operator configuration can change between planning and execution.

## Decision

`core/actions/` provides one catalog of descriptors and adapters over existing
implementations. Adapters do not replace those implementations. The lifecycle
is descriptor, requirements, applicability, check, execute, verify, cleanup,
and normalized result.

Lifecycle state distinguishes `candidate`, `applicable`, `checked`,
`attempted`, `succeeded`, `verified`, and cleanup outcome. A successful process
exit does not imply verification.

Every adapter calls deterministic execution policy immediately before its
`execute` boundary. Planner assessments and earlier applicability checks are
supporting input only. Scope, active-risk authorization, capability, and
execution context remain mandatory at the final boundary. Results normalize to
the canonical execution contract while compatibility adapters preserve legacy
text and object access where required.

## Consequences

- New action families implement an adapter instead of adding another dispatch
  path.
- A policy denial is a first-class blocked result and report/trace event.
- Cleanup is attempted and recorded independently from action success.
- Legacy aliases remain only during a measured compatibility window.

## Rejected alternatives

- Replacing all legacy implementations at once would create a parallel system
  and lose characterized behavior.
- Authorizing only in the planner creates a time-of-check/time-of-use gap.
- Collapsing check, success, and verification would overstate evidence.
