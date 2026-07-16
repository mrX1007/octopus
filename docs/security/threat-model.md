# Threat model and security boundaries

## Scope

OCTOPUS is a dual-use assessment engine intended for explicitly authorized
labs, internal audits, and controlled security exercises. This model covers the
local operator process, pipeline stores, external tool processes, plugins,
optional local LLM provider, and optional C2 components. It does not assume that
a target, imported artifact, tool output, model response, or plugin is trusted.

## Assets to protect

- authorization scope and operator intent;
- target and internal network data;
- credentials, tokens, keys, and secret references;
- evidence provenance and assessment/report integrity;
- mission/task idempotency and audit history;
- host process integrity and availability;
- plugin, vendor, model, and benchmark artifact integrity.

## Trust boundaries

| Boundary | Untrusted input | Required control |
| --- | --- | --- |
| Operator/config to execution | target, action, flags, allowlists | Typed `ExecutionContext`, deterministic target normalization, capability and policy checks. |
| Planner/model to scheduler | goals, tasks, arguments, explanations | Model has no execution authority; normalize, validate, deduplicate, and reauthorize immediately before execute. |
| Target/tool to parser | stdout/stderr, files, network records | Bounded capture, deterministic family parser, redaction, provenance, no positive finding from error prose. |
| Provider/plugin to host | return objects, exceptions, process behavior | Isolated or managed execution, typed result adaptation, time/output limits, process-tree termination, error-class-only persistence. |
| Facts to projections | repeated or contradictory evidence | Canonical identity, assessment history, idempotent projection, explicit contradiction and verified-only query mode. |
| Secrets to consumers | credential plaintext | Encryption at rest, references in facts/tasks, narrow reveal at use, recursive redaction in logs/traces/reports. |
| Local process to C2/agents | task and event protocol | Explicit protocol/version/auth controls, bounded task/result payloads, separate agent execution policy and lifecycle supervision. |
| Replay/benchmark to repository | recorded artifacts and ground truth | Versioned metadata, content review, allowed-action budgets, no harness-launched external tool. |

## Principal threats and mitigations

### Scope escape and unauthorized active action

A malicious model response, imported task, alias, or stale plan could request an
off-scope or higher-risk action. Applicability and planner checks are not
authorization. `ExecutionPolicy` evaluates the typed invocation and current
context directly before execute. Active actions require explicit capability,
configuration, and authorized target scope. Denials are recorded as blocked
outcomes.

### Command and argument injection

Target, credential, and plugin-controlled strings can reach legacy wrappers.
Canonical execution prefers argv, validates targets, requires an explicit
managed-shell capability for shell use, redacts audit representations, bounds
runtime/output, and terminates the process group on timeout/cancellation.
Legacy shell paths remain a migration risk and must not be expanded.

### Prompt/tool-output injection and false promotion

Target-controlled text may tell the model to take actions or claim a
vulnerability. Raw output is parsed deterministically where possible. The model
cannot write a verified assessment. Reports promote only a current verified
assessment with evidence fact IDs, source execution IDs, and a reason. Root
access and CVE candidates remain separate semantic classes.

### Secret disclosure

Secrets can leak through commands, facts, exceptions, telemetry, and exports.
Secret values are encrypted in `SecretStore`; persistent consumers use
references or redacted forms. All fact, assessment, report, trace, and canonical
result boundaries apply bounded redaction. Persisting raw stdout, prompt text,
or exception messages in decision telemetry is forbidden.

### Persistence corruption, replay, and duplicate execution

Crashes and concurrent workers can duplicate facts or actions. SQLite writes
use transactions, stable keys, unique indexes, and rollback. Missions persist
tasks, dependencies, attempts, incremental fact/execution references, and
interrupted states. Resume drains durable work and uses idempotent task/attempt
identity rather than reconstructing work from log text.

### Resource exhaustion and orphan processes

Providers and plugins may hang, fork descendants, or emit unbounded output.
Execution contexts bound time and bytes; cancellation propagates cooperatively;
managed processes run in their own group and receive graceful termination then
kill. Provider failures feed bounded retry/circuit state. Partial output is
ingested before a retry or fallback when available.

### Plugin, vendor, and dependency compromise

Plugins and vendored tools execute code with significant local authority.
Plugin processes are isolated where supported, vendor integrity is checked by
the repository manifest/CI, dependency locks are enforced, and failures are
normalized at the host boundary. These controls reduce impact but do not make
unreviewed code safe; only reviewed sources belong in a release.

### Observability tampering or data growth

Provider telemetry and decision trace influence explanations and selection but
are not mission or evidence authority. Events use stable IDs, bounded labels and
JSON, retention limits, and schema versions. Metrics are derived. Deleting these
stores loses diagnostics, not facts or mission state.

## Residual risks

- Some legacy kill-chain/C2 helpers still use independent subprocess or shell
  boundaries and broad compatibility catches.
- Local LLM, external scanners, MariaDB, optional OSINT services, and target
  networks have their own availability and supply-chain risks.
- Process-group termination cannot guarantee cleanup of a process that escapes
  the group or delegates work to an external service.
- A local operator with access to the same account and secret-store key can
  access authorized assessment data.
- Rebuildable projections can be stale until replay; consumers must honor
  schema and normalization versions.

## Security invariants for releases

1. No model/planner output bypasses final policy authorization.
2. No verified report item lacks assessment reason, evidence, and execution
   provenance.
3. No plaintext test secret appears in facts, missions, graph, traces, reports,
   telemetry, or logs.
4. Timeout/cancellation leaves no managed child process and retains bounded
   partial evidence.
5. Resume does not duplicate a completed attempt.
6. Clean-negative and contradiction scenarios do not emit a verified finding.
7. Vendor and dependency integrity checks pass from a clean environment.
