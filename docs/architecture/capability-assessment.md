# Capability assessment contract

Snapshot date: 2026-07-14

`CapabilityAssessment` is a read-only planning facade. It brings the existing
capability-related signals into one deterministic document without changing
which component owns any signal and without invoking a tool.

## Existing semantic owners

| Axis | Authority | Assessment behavior |
|---|---|---|
| Execution permission | `ExecutionContext` and `ExecutionPolicy` | Summarizes stable allow/deny reason for the exact supplied context. Request IDs and other per-call audit entropy are excluded. The result is advisory. |
| Provider availability | `ToolRegistry` and decorator `ToolDef.is_available()` | Expands a task to leaf providers and reads existing dependency checks. It does not format secrets, call provider functions, start plugins, or dispatch commands. |
| Target-state evidence | `FactStore`, projected by `StateResolver`, `TargetModel`, and `ContextBuilder` | Reports canonical fact IDs and observation confidence/time bounds that support satisfied requirements. Facts remain the evidence authority. |
| Strategic request | `ContextBuilder.next_required_capability` | Marks whether the assessed capability is the requested strategic capability or one of its concrete task expansions. |
| Prerequisites and stage gates | `ToolRegistry.task_profiles`, `ContextBuilder.stage_gates`, and `automation_policy` | Lists declared requirements and missing requirements separately from provider and authorization state. |

These axes must not be collapsed into a single availability boolean. In
particular, an installed provider may be denied by current policy, and an
authorized provider may still lack target-state prerequisites.

## Model

The immutable assessment exposes:

- capability and whether it is currently requested;
- target and the exact supplied execution scope;
- per-provider availability and authorization summaries;
- aggregate provider availability and authorization decision;
- evidence state;
- requirements and missing requirements;
- stable blocking reasons;
- supporting canonical FactStore IDs;
- observation time and confidence bounds.

Canonical facts carry the Fact Assessment freshness-policy version and a
`fresh | stale | unknown` marker. Capability summaries aggregate those markers;
an execution timeout produces `degraded`, not absence. Caller-supplied legacy
dictionaries without freshness metadata remain `not_assessed`. This read-time
policy never rewrites base confidence.

## Stable state vocabulary

Provider availability:

- `available`: at least one concrete provider passes its existing dependency check;
- `unavailable`: providers are declared, but none currently passes dependency checks;
- `no_provider`: no concrete provider is declared for executable work;
- `not_applicable`: in-process analysis or control-plane flow does not use a tool provider.

Authorization decision:

- `allowed` or `denied`: stable summary of current `ExecutionPolicy` decisions;
- `unknown`: no exact execution context or assessable available command was supplied;
- `not_applicable`: no execution authorization is required for the in-process/control-plane flow.

Evidence state uses the existing projection vocabulary
`confirmed_present | confirmed_absent | unknown`. Freshness and degraded
coverage remain a separate summary axis. Missing stage gates are
unknown unless a surface projection explicitly proves absence.

Blocking reasons use bounded prefixes:

- `provider:no_provider`;
- `provider:unavailable`;
- `authorization:denied:<existing-policy-reason>`;
- `authorization:unknown:<reason>`;
- `requirement:missing:<requirement>`.

Only `unavailable` and true `no_provider` are hard provider failures for the
Phase 3 plan compiler. Authorization and prerequisite summaries remain visible
but do not become cached permissions or introduce a second policy authority.

## Strategic-to-task expansion

Strategic capabilities are not assumed to be registry task names. The resolver
uses an explicit expansion for privilege escalation, persistence, internal
reconnaissance, data exfiltration, and cleanup. `conclude` is control-plane
work, while the exact `AnalysisAgent/analyze_vulnerabilities` pair is
in-process; both are `not_applicable`, not `no_provider`. Unknown or mismatched
analysis tasks remain true `no_provider` failures.

## Integration and authorization invariant

`ContextBuilder` exposes one serialized `capability_assessment` for
`next_required_capability`. The pipeline injects its shared `ToolRegistry`, the
scheduler's `ExecutionPolicy`, and the same execution-context factory used by
the command path.

After planner normalization and optimization, `MissionPlanCompiler` performs
one final provider pass over LLM, fallback, enriched, and forced plans. It
rejects hard-unavailable/no-provider tasks before agent execution.

Every surviving command still reaches `CommandScheduler.decide()`, which calls
`ExecutionPolicy.authorize_command()` again. The production runner also keeps
its dispatch-time authorization. A capability assessment is never accepted as
proof that later execution is authorized.
