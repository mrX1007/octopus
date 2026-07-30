# OCTOPUS current system map

Baseline date: 2026-07-29

Reference revision: working tree after Waves 4–6 completion

This document records the architecture that exists at the reference revision.
It is descriptive, not a target design. In particular, a class name or
docstring that claims ownership is distinguished below from the call paths that
actually run in production.

## Scope and notation

- A `read` is an in-process read of state, facts, configuration, or a durable
  store.
- A `write` is an in-process mutation, filesystem write, database write, or
  emitted subprocess request.
- `Persistent` means data can survive the process. Objects described as
  projections or read models are not persistent unless the current code writes
  them to a store.
- File references are `path:start-end` against the reference revision.

## Top-level lifecycle

`octopus.py` is now a thin executable and compatibility import facade. Argument
dispatch is owned by `core.cli.main.main()`; `create_parser()` is pure and
`create_app()` is composition-only. `OctopusCLIApplication.run()` explicitly
owns logging/readline, supervisor and signal lifecycle, preflight, automatic C2
startup, plugin discovery, the interactive menu, and shutdown. Importing the
CLI modules performs none of those actions. See
`docs/architecture/cli-lifecycle.md`.

There are three principal scan paths:

1. A direct scan creates a MariaDB session, runs reconnaissance, constructs
   `AIPipeline`, calls `run_scan()`, and adapts/saves the result
   (`core.cli.application._new_scan_direct`). This path marks the session
   complete before all result rows are saved.
2. Shodan parallel mode confines worker threads to reconnaissance, then creates
   sessions and runs each `AIPipeline` on the main thread
   (`core.cli.application._run_shodan_parallel_scans`). This path saves results
   before marking the session complete.
3. Resume reads a JSON checkpoint, optionally refreshes reconnaissance or
   rebuilds input from MariaDB, constructs a new `AIPipeline`, and removes the
   checkpoint after success (`core.cli.application.resume_scan`). It also marks
   the session complete before `_save_and_show_results()` finishes.

The central runtime flow currently looks like this:

```text
octopus.py -> core.cli.main
  -> core.cli.application workflows
  -> AIPipeline.run_scan()
     -> ScanLifecycle
     -> deterministic raw-output parsing -> FactStore
     -> StateResolver + ContextBuilder
     -> DirectorLLM -> MissionPlanner -> PipelinePlanningMixin
     -> PipelineMissionMixin -> durable Task/TaskAttempt
     -> task agents
     -> PipelineRuntime.decide()
     -> PipelineRuntime.execute()
     -> PipelineRuntime.complete_execution()
        -> shared OutputParser -> FactStore + FactAssessmentStore
     -> PipelineObservabilityMixin -> outcomes/trace/retry
     -> StateResolver + report/result adaptation
  -> MariaDB row-by-row persistence -> export/trace files
```

`PipelineRuntime` is instantiated exactly once per `AIPipeline` in production.
Production and replay completion both cross `complete_execution()`; the main
pipeline no longer parses or persists a completed execution independently.
Initial reconnaissance, the visible pre-run state, and explicit manual seed
compatibility remain separate ingestion paths, as detailed next.

The historical 2,956-line facade has been decomposed below the 2,400-line
acceptance ceiling enforced by
`tests/test_pipeline_remaining_acceptance.py`. The test, rather than this
document, is the authority for the current physical-line limit. `run_scan()`
remains public; `ScanLifecycle` owns the loop, and mission, planning, replay,
observability, and follow-up behavior is composed from the bounded pipeline
modules. See
`docs/architecture/pipeline-decomposition.md` for the ownership and
characterization contract.

## Pipeline and `PipelineRuntime` ownership

### Declared owner

`PipelineRuntime` describes `AIPipeline` as mission control and itself as the
single stateful I/O boundary (`core/ai/runtime.py:38-59`). Its constructor owns:

- `FactStore`;
- `CommandScheduler`;
- `OutputParser`;
- `TraceReporter`;
- the injected command runner.

Its methods cover scheduling, context binding, execution, parsing, redaction,
and fact persistence. `dispatch()` remains a decide/execute convenience API.
`complete_execution()` is the production completion ingress. It first reserves
a durable, payload-bound completion claim, then parses output, persists base
and derived facts, records the command result (which applies assessment
transitions), refreshes the graph, and finally records attempt provenance.
Conflicting reuse is rejected before parser/callback side effects. Exact replay
loads the committed result and fact IDs, drains projection repair, and repairs
only the attempt tail. Fact writes renew and validate claim ownership inside
their own write transaction. The pipeline captures a keyed scan-generation
fence before its running fact and provider dispatch; scan clearing rejects a
live owner, advances that generation, and therefore rejects results from both
expired claims and pre-claim dispatches. `ingest_output()` remains a smaller
public compatibility facade. The canonical `complete_execution()` ingress
fails closed when that bound fence is omitted. Completion callbacks are
idempotent, at-least-once projection hooks rather than an exactly-once external
transaction.

### Actual production ownership

`AIPipeline.__init__()` constructs one `PipelineRuntime` and exposes aliases to
its facts, missions, scheduler, parser, and reporter. No
second `PipelineRuntime` is constructed in production. The actual task command
path calls `runtime.decide()` and `runtime.execute()`, then hands completion to
`runtime.complete_execution()`. The facade supplies pure normalization,
derived-fact, check-result, and credential-sync adapters; it no longer writes
parsed execution facts or command results itself. `_store_fact()` remains for
the visible pre-run state and explicit manual seed compatibility paths.

Consequently:

| Responsibility | Declared/current component | Actual main-loop caller | Durable write |
|---|---|---|---|
| Command authorization and scheduling | `PipelineRuntime` -> `CommandScheduler` | `AIPipeline._run_task_commands()` | decision trace/result later |
| Context-bound command execution | `PipelineRuntime.execute()` | `AIPipeline._run_task_commands()` | no direct durable write |
| Output parsing | `PipelineRuntime.complete_execution()` / `parse_output()` | runtime completion ingress | no separate write |
| Execution completion | `PipelineRuntime.complete_execution()` | production command path and replay | facts, command results, assessment outbox, graph projection, and attempt provenance |
| Compatibility/manual fact ingestion | `PipelineRuntime.ingest_output()` / `AIPipeline._store_fact()` | public compatibility, pre-run state, and manual seed | `FactStore` SQLite |
| Mission/task lifecycle | `MissionStore` owned by `PipelineRuntime` | `ScanLifecycle` and `AIPipeline` compatibility facades | mission/task/attempt tables plus incremental provenance in FactStore SQLite |
| Decide/execute facade | `PipelineRuntime.dispatch()` | tests/contracts; not the production scan loop | none directly |

The main pipeline itself is stateful. It resets per-run compatibility
collections, then hydrates them from `MissionStore` and FactStore command
records. Persisted pending/interrupted tasks are topologically drained before
new Director/Planner decisions. The loop then parses initial input, resolves
state/context, enforces anti-loop and budget checks, runs discovery,
verification, and analysis, and finally resolves state.

### Pipeline read/write inventory

| Pipeline operation | Reads | Writes | Persistence |
|---|---|---|---|
| Initial ingest | raw reconnaissance text, parser configuration | normalized facts | `data/facts.db` by default |
| Context construction | facts, resolved state, target, tool availability | in-memory `TargetModel`, `AssetGraph`, surface/risk context | none |
| Mission decision | durable resume queue or bounded facts/context and LLM response | topologically ordered plan and decision trace; registered durable tasks | mission tables; trace/report writes later |
| Task execution | plan, dependencies, tool availability, scheduler decision, `ExecutionContext` | subprocess/tool result, command-result record, facts, incremental attempt provenance, terminal attempt | fact and mission tables plus tool-owned stores/files |
| Final adaptation | facts, hypotheses, resolved state | legacy result dict and evidence-backed reporting fields | MariaDB/files via `core.cli.application` |

The pipeline’s result adapter reads facts/hypotheses and builds legacy
vulnerability/exploit structures before applying the reporting enricher and
recursive redaction (`core.cli.application._adapt_state_to_result`).

## Facts, parsing, state, and context

### `FactStore`

`FactStore` is the durable source of truth used by the AI pipeline. It opens a
SQLite database and selects a matching `SecretStore`; the default fact database
uses the default secret path, while a custom fact database gets a sibling
`.secrets` database (`core/ai/fact_store.py:14-28`). Connections commit or roll
back and always close through `_get_conn()` (`core/ai/fact_store.py:30-40`).

Its schema contains canonical facts, hypotheses, fact observations, command
results, completion claims, and an assessment-projection outbox. At
initialization it also redacts
legacy rows (`core/ai/fact_store.py:122-161`). `add_fact_with_status()` redacts
input, finds a matching canonical fact, updates or inserts it, and records a
separate observation (`core/ai/fact_store.py:197-256`). Reads return facts in a
defined order with observation/source/session metadata
(`core/ai/fact_store.py:295-351`). Command results are separate durable rows
(`core/ai/fact_store.py:403-427`).

The composed `FactAssessmentStore` owns a separate schema `1.1` in the same
database. Every fact has a current observed/inferred/verified/contradicted
assessment plus append-only history, evidence fact IDs, source execution IDs,
and supersession. Facts remain evidence; assessments are judgements over that
evidence. See `docs/architecture/fact-assessment.md`.

Current production fact writers are bounded to these paths:

- `PipelineRuntime.complete_execution()` for production and replay output;
- `PipelineRuntime.ingest_output()` for its public compatibility contract;
- `AIPipeline._store_fact()` only for pre-run state and explicit manual seed
  compatibility;
- `EvidenceVerifier`, which uses `add_fact_with_status()` with a compatibility
  fallback (`core/ai/evidence.py:187-204`).

The canonical fact identity `(scan_id, host, type, value)` is protected by a
unique index. Ingress takes an immediate write transaction before its
select/insert/update, so concurrent first observations converge on one row.
Initialization merges legacy duplicates, observations, derived references,
mission fact links, and assessment provenance before creating the index.

### Parser chain

`OutputParser` owns deterministic family parsers, a web-endpoint parser, legacy
regular expressions, structured parsing, and an optional LLM extractor
(`core/ai/evidence.py:1935-1948`). Its order is:

1. status/negative-result handling;
2. family parsers;
3. web endpoint parsing;
4. conditional legacy regular expressions;
5. structured parsing;
6. LLM extraction only when deterministic parsing found nothing;
7. final sanitization.

That order is implemented at `core/ai/evidence.py:2047-2079`. The family
registry currently runs thirteen parser families sequentially
(`core/ai/parsers/families.py:22-44`), exported from
`core/ai/parsers/__init__.py:3-33`.

### State and read models

`ContextBuilder` captures one immutable `EvaluatedFactSnapshot` and gives the
same object to `StateResolver` and all context projections. Contradicted,
stale, and degraded facts remain in snapshot history and assessment counts but
are excluded from decision facts, so they cannot close current service/access
stage gates. `TargetModel`, `AssetGraph`, `SurfaceState`, capability assessment,
and the LLM context are constructed from that one decision view; the snapshot
reference and bounded assessment-head metadata are included in context.
FactStore constructs each batch from facts, observations, assessment
heads/provenance, and execution outcomes in one SQLite read transaction and
uses one captured freshness-evaluation time, preventing a concurrent writer
from producing a mixed decision view.

`TargetModel` is explicitly a normalized read model
(`core/ai/target_model.py:13-19`). It derives services, endpoints, access,
credentials, and graph/risk views from facts without writing another store
(`core/ai/target_model.py:46-76`). `LLMContextBuilder` bounds and trims this
material before use (`core/ai/llm_context.py:16-110`); it relies on upstream
fact redaction rather than owning secret persistence. `PipelineRuntime` also
owns one schema-`2.0` `KnowledgeGraph` and its `GraphProjectionService`.
Committed facts are projected with normalization version `1.0`; `TargetModel`
and `AssetGraph` reuse the same asset/service/endpoint IDs. The persistent
graph keeps migration aliases and per-fact assessment provenance. It remains a
projection, not an evidence writer. See
`docs/architecture/canonical-graph.md`.

## Director, planner, scheduler, and policy

| Component | Called by | Reads | Writes / returns | Persistence |
|---|---|---|---|---|
| `DirectorLLM` | `AIPipeline.run_scan()` | target, resolved state, bounded context, LLM | validated goal or deterministic fallback | none directly |
| `MissionPlanner` | `AIPipeline.run_scan()` | goal, state, context, LLM | task plan or deterministic fallback | none directly |
| `DeterministicPolicy` | director and pipeline plan handling | state, config authorization | accepted/filtered goal and plan | none |
| `CommandScheduler` | `PipelineRuntime.decide()` | command, facts, execution context, prior commands | redacted `CommandDecision` | none directly |
| `ExecutionPolicy` | scheduler and command runners | registered tools, target/scope, capabilities, approvals | final allow/deny/dispatch classification | none directly |

`DirectorLLM` asks the LLM for a goal, then validates it with deterministic
policy and stage gates; exceptions use a deterministic fallback
(`core/ai/director.py:30-100`, `core/ai/director.py:102-185`).
`MissionPlanner` similarly parses bounded JSON and falls back to a deterministic
state-to-plan map (`core/ai/planner.py:15-113`).

The pipeline normalizes planner output and filters unknown tasks
(`core/ai/pipeline.py:511-650`). It enriches and validates normal plans through
`DeterministicPolicy` (`core/ai/pipeline.py:656-761`). Some empty/forced-plan
branches return before the final plan validation at line 761, so plan-level
policy is not the sole execution boundary. Every command still reaches the
scheduler’s execution-policy check.

`CommandScheduler` calls `ExecutionPolicy.authorize_command()` before duplicate
and negative-fact checks (`core/ai/command_scheduler.py:31-85`). It canonicalizes
commands for deduplication and applies fact-derived negative gates
(`core/ai/command_scheduler.py:87-177`). If no explicit context is supplied it
creates a legacy automatic context (`core/ai/command_scheduler.py:44-47`).

`ExecutionPolicy` validates network targets and scope
(`core/execution/policy.py:93-212`), authorizes registered tools
(`core/execution/policy.py:313-404`), denies every unregistered direct-binary
invocation (`core/execution/policy.py:406-422`), and permits managed shell only with the
required interactive origin, capability, approval, scope, and destructive
capability checks (`core/execution/policy.py:424-462`). Command lookup imports
the tool registry lazily and returns a typed dispatch classification
(`core/execution/policy.py:486-532`).

The runtime now also exposes the versioned `core.actions` adapter boundary.
It lazily wraps the existing decorator registry and can register concrete
`ExploitBase`, Metasploit and isolated-plugin providers without replacing
them. `ActionExecutor` preserves candidate/applicable/checked/attempted/
succeeded/verified/cleanup states and re-runs `ExecutionPolicy` immediately
before provider execution. See `docs/architecture/action-lifecycle.md`.

Provider choice is a separate runtime-owned read/execute boundary. A bounded
SQLite history ranks applicable catalog actions per capability and target
class, while selection records both score contributions and rejection reasons.
Fallback is limited to unavailable, timeout, or explicitly typed retryable
failures. Partial output must be ingested before the next provider is called.
The final `ActionExecutor` policy check is never reused from selection. See
`docs/architecture/provider-selection.md`.

Execution contexts now carry cooperative cancellation. Both canonical and
legacy local runners enforce bounded lifetime/output and process-group cleanup;
the MSF process path follows the same TERM/grace/KILL contract. SIGINT unwinds
normally, partial cancelled output is persisted before the mission is
interrupted, and repeated unavailable providers are circuit-broken. Durable
command writes have a hashed execution idempotency key. See
`docs/architecture/reliability-recovery.md`.

The execution context model carries origin, automation, scope, capabilities,
approval, and limits (`core/execution/models.py:63-139`). Its current legacy
fallback returns an automatic empty-scope context when no context is bound
(`core/execution/models.py:199-209`). `AIPipeline` normally builds a target-bound
context and adds active capability only when configuration and target scope
allow it (`core/ai/pipeline.py:461-488`).

## Tools and execution paths

There are two distinct current registries.

### Strategic task/tool registry

`core/ai/tool_registry.py` maps planner task names to profiles and command
templates. It generates commands only for available providers
(`core/ai/tool_registry.py:559-679`), checks registry coverage
(`core/ai/tool_registry.py:685-723`), and creates a `PluginManager` to include
plugin availability summaries (`core/ai/tool_registry.py:725-735`).
`DiscoveryAgent` and `VerificationAgent` consume this registry as command
proposal sources; they do not execute commands themselves
(`core/ai/task_agents.py:14-20`, `core/ai/task_agents.py:67-78`).

### Executable function registry

`core/tools/registry.py` maintains the decorator-backed global `_REGISTRY` and
its lookup functions (`core/tools/registry.py:101-217`). Its registered
`plugin` action is a gateway into `PluginManager`, not an import of each plugin
into the main registry (`core/tools/registry.py:246-278`). Importing
`core.tools` registers the decorated functions by import side effect; the
package then re-exports legacy names (`core/tools/__init__.py:4-75`,
`core/tools/__init__.py:77-140`). The canonical application entry is
`core.tools.dispatch_registered_tool()`: it requires an `ExecutionContext` and
can reach only the registered, policy-authorized runner. Top-level `tools.py`
is a deprecated wildcard compatibility facade, and
`DEPRECATED_TOOL_EXPORTS` identifies its raw process, shell/REPL, menu and
direct-provider migration surfaces without removing them.

The runner resolves a registered definition, binds/validates arguments, derives
network targets, authorizes the call, and invokes `tool_def.func()`
(`core.tools.runner.run_tool_by_command`). `run_single_tool()` is another policy
wrapper for menu-driven execution (`core.tools.runner.run_single_tool`).

Managed process execution creates a process group, applies time/output limits,
and uses `subprocess.Popen` (`core.tools.runner._execute_process`). Intentional
shell mode is isolated to `core.tools.runner.run_managed_shell`. Despite its
compatibility name, `run_arbitrary_cmd()` performs policy-authorized typed
dispatch and fails unknown commands closed; it remains available for approved
shell compatibility. New application callers use the registered-only
`dispatch_registered_tool()` facade instead. `AIPipeline` imports that facade
directly and retains a local `run_arbitrary_cmd` name only as a patch-compatible
adapter.

`core/tools/base.py` is a second, lower-level argv process helper
(`core.tools.base.run_tool`). It does not itself call `ExecutionPolicy`; safety
therefore depends on callers entering through the registered runner. Direct
imports can bypass that outer boundary. `core.tools.base.ToolResult` is the sole
implementation (`core/tools/base.py:40-105`);
`core.tools.exploit_tools.ToolResult` is an import-compatibility alias
(`core/tools/exploit_tools.py:30-32`) covered by
`tests/test_release_cleanup.py`.

Tool availability uses a mutable module cache (`core/tools/base.py:29-37`).
Exploit-tool credential helpers delegate to the canonical reference-only
credential facade. Their old ambiguous names remain as warning compatibility
aliases, but return `CredentialRef` objects and never maintain or reveal a
separate plaintext cache (`core/tools/exploit_tools.py:36-90`).

## Plugins

Plugins are already isolated in one-shot subprocesses. The parent process does
not import a discovered plugin module (`core/plugins/loader.py:1-7`). Discovery
validates containment/symlinks and asks a worker for inert metadata
(`core/plugins/loader.py:82-185`). Execution uses a minimal environment, a fresh
process group, a JSON request/response protocol, timeout termination followed
by kill, and result/event redaction (`core/plugins/loader.py:251-372`,
`core/plugins/loader.py:513-575`). Check and event-hook calls use the same worker
boundary (`core/plugins/loader.py:581-633`,
`core/plugins/loader.py:668-707`).

The protocol accepts only JSON-safe values (`core/plugins/protocol.py:1-6`,
`core/plugins/protocol.py:24-97`). The worker is the only process that loads the
plugin file, captures bounded output, runs setup/action/cleanup, and writes one
JSON response (`core/plugins/worker.py:28-126`,
`core/plugins/worker.py:191-224`, `core/plugins/worker.py:261-320`).

Current callers are the registered plugin gateway
(`core/tools/post_tools.py:1856-1879`), other explicit post-tool plugin
integrations (`core/tools/post_tools.py:588-608`,
`core/tools/post_tools.py:1309-1314`), startup discovery
(`core.cli.main.OctopusCLIApplication._discover_extensions`), and strategic availability summaries
(`core/ai/tool_registry.py:725-735`).

The isolation boundary is process, environment, path validation, JSON, timeout,
and output bounds. It is not an OS syscall, filesystem, or network sandbox.

## Exploits and kill-chain modules

Registered tool dispatch enters exploit selection through
`core/tools/post_tools.py:1156-1159`. The selector can perform a lightweight
service probe when no reconnaissance result exists, maps observed services,
and invokes the exploit intelligence engine (`core/exploits/selector.py:224-280`).
The engine owns a separate SQLite database, initializes/seeds its schema, and
queries/ranks candidates (`core/exploits/exploit_mapper.py`). Its payload
adapter no longer invents a simulated payload: it renders only an explicit,
bounded local template containing `__LHOST__` and `__LPORT__` after target/port
validation.

Legacy kill-chain modules remain callable from the menu and registered wrappers
(`core/tools/runner.py:89-170`, `core/tools/post_tools.py:1156-1159`). They can
write their own reports and loot outside `FactStore`; for example, the
orchestrator writes a report file directly (`core/killchain/orchestrator.py:251-260`).
Those writes are not automatically a canonical fact or evidence observation.

## Graphs and credential projection

Graph projections serve different read purposes while sharing canonical entity
identity normalization.

| Graph | Source/caller | Reads | Writes | Persistence |
|---|---|---|---|---|
| `core.ai.AssetGraph` | `ContextBuilder` and `TargetModel` | current facts | in-memory nodes/edges | none |
| `core.knowledge.KnowledgeGraph` | `PipelineRuntime.graph_projector`, explicit graph APIs | committed facts/assessments and explicit compatibility inputs | versioned nodes/edges/projection ledger | `data/knowledge.db` |

`AssetGraph` is rebuilt deterministically from facts
(`core/ai/asset_graph.py:10-85`) and is attached by `ContextBuilder` and
`TargetModel` (`core/ai/context_builder.py:65-67`,
`core/ai/target_model.py:46-76`).

`KnowledgeGraph` schema `2.0` stores canonical nodes, aliases, edges and a
fact/assessment/normalization projection ledger. `GraphProjectionService`
projects committed runtime facts idempotently and carries evidence IDs,
assessment state, first/last seen, scope/scan provenance and contradiction
metadata. Verified-path queries default to verified edges and return evidence
chains or missing-link explanations; inferred paths require an explicit option.
`KnowledgeEnricher` remains an uncalled public compatibility adapter and is not
an evidence authority.

`CredentialStore` is the sole in-process credential reference index. A write
seals plaintext in `SecretStore`, caches an immutable `CredentialRef`, and may
persist only its `secret_ref` through the optional MariaDB compatibility layer
(`core/credentials.py:215-331`). Public and legacy getters return references.
Plaintext is revealed only inside the lexical `material_for_execution()`
context and the application-owned reference is cleared on exit
(`core/credentials.py:424-473`). The former direct `KnowledgeGraph` fan-out and
`_KNOWN_CREDS` plaintext cache no longer exist.

## Reporting and export

`core/ai/report_schema.py` owns machine report schema `1.0`. It renders nine
bounded sections and promotes a verified vulnerability only from a current
verified assessment with reason, evidence chain and source execution IDs.
Access, candidates, attempted-but-unverified actions, degraded checks and
cleanup remain distinct. `core/ai/reporting.py` attaches this projection while
retaining legacy fields and recursively redacts the result.

`TraceReporter` reads canonical facts, command results and bounded decision
events. It emits the machine report, decision metrics schema `1.0`, and
human/JSON trace representations. `DecisionTraceStore` persists idempotent,
retention-bounded schema `1.0` decision events in a separate SQLite store.
`core.cli.application` writes trace JSON and text below the configured log path.

MariaDB exposes a typed `SessionReport` contract (`db.py:35-42`). Export first
normalizes that contract, including the `vulns` field and compatibility alias
(`export.py:38-56`), then derives a contained filename
(`export.py:65-93`). HTML/ReportLab/CSV-specific escaping and formula
neutralization helpers are at `export.py:96-113`; the format writers are PDF
(`export.py:183-383`), HTML (`export.py:386-540`), JSON
(`export.py:594-685`), and CSV (`export.py:694-732`).

Application persistence is not a single report transaction. The adapter loops
over vulnerabilities, fixes, exploits, and summary rows through separate DB
calls, then reads the session back and offers export
(`core.cli.application._save_and_show_results`).

## Replay

Replay is a deterministic decision snapshot, not a live execution replay.
`AIPipeline.replay_outputs()` normalizes supplied output and routes completion
through the same `PipelineRuntime.complete_execution()` ingress as production:
facts and derived facts, command result, assessment transitions, graph
projection/outbox repair, and attempt provenance retain the same ordering and
idempotency rules. One bound generation fence is captured before preprocessing
and covers the entire replay batch, so reset during preparation or between
entries cancels the remaining batch. It then rebuilds context and snapshots proposed actions
without executing a provider. The fixture runner constructs a real pipeline,
invokes that method, then compares facts, actions, and context to the expected
fixture.

Because the replay pipeline uses a real `FactStore`, replay writes to the
configured SQLite fact database. Isolation therefore depends on the caller
passing a dedicated test/replay database; replay is not intrinsically
read-only.

## C2 subsystem

### Startup and boundaries

The interactive application automatically starts the daemon only from
`OctopusCLIApplication.run()`. `core.cli.application._start_c2_daemon()`
launches it as a detached subprocess and sends output to
`data/c2_daemon.log`. The interactive thin client communicates over a
Unix-domain socket through `core.cli.application._send_to_daemon()`.

Daemon configuration owns its data directory, keys directory, SQLite database,
operator socket, and request/task/result limits (`core/c2/daemon.py:32-45`).
Importing the daemon creates only the FastAPI application and handler
definitions. Persistent components are initialized exactly once by
`_initialize_components()` when the ASGI lifespan, `create_app()`, or `main()`
enters the executable lifecycle (`core/c2/daemon.py:74-148`). Import-smoke
contracts verify that imports leave both a read-only working directory and the
configured C2 data path untouched (`tests/test_import_smoke.py:14-46`).

`KeyStore` persists the Ed25519 identity in a strictly bounded, versioned
AES-GCM envelope whose authenticated header records the mandatory Scrypt KDF
and fixed parameters. Historical environment-selected Argon2id, Scrypt, and
PBKDF2 blobs are read only for one-way atomic migration. Static X25519 private
material is sealed by the unlocked store; loading repairs an interrupted public
key projection and removes a legacy plaintext PEM only after its public key is
confirmed to match. Atomic replacements and plaintext removal fsync the parent
directory where the platform supports it. `C2CryptoEngine` may read an existing
legacy PEM for compatibility but never creates one implicitly.

### Agent protocol

Enrollment consumes a signed single-use token, performs X25519 key agreement,
assigns the server-generated immutable agent ID, and appends/projects an agent
event (`core/c2/daemon.py:227-280`). Beacon handling authenticates/decrypts the
agent request, validates task ownership for ACK/results, enforces bounds,
updates task state, leases pending work, and encrypts the response
(`core/c2/daemon.py:285-376`).

The SQLite backend enables WAL per connection and owns agents, tasks, key
epochs, and consumed enrollment tokens (`core/c2/db_backend.py:9-89`). Agent
insert is immutable (`core/c2/db_backend.py:108-125`); queue, lease, ACK, and
owner-scoped result transitions are implemented at
`core/c2/db_backend.py:201-303`.

### Operator and event protocol

The operator socket enforces operator authentication/role checks and appends
task events (`core/c2/daemon.py:381-490`); its filesystem permissions are set at
startup (`core/c2/daemon.py:496-521`). `OperatorManager` persists operators in
the same C2 database and creates a first-run admin key file
(`core/c2/operators.py:37-104`). Enrollment signing keys and token consumption
are owned by `EnrollmentAuthority` (`core/c2/enrollment.py:25-110`).

`EventStore` persists append-only events, invokes in-process projection
handlers, and tracks replay offsets (`core/c2/event_store.py:59-150`,
`core/c2/event_store.py:179-211`). Projection handlers translate agent/task
events into `C2Database` mutations (`core/c2/daemon.py:153-168`). A handler
failure is logged after the event append and is not part of the same SQLite
transaction (`core/c2/event_store.py:213-221`), so event persistence and the
read-model projection are not atomic. Operator result retrieval deletes the
corresponding completed rows after reading them
(`core/c2/db_backend.py:295-303`).

## Durable stores and file ownership

| Data | Current owner/writer | Default location | Main readers |
|---|---|---|---|
| facts, observations, hypotheses, command results | `FactStore` | `data/facts.db` | pipeline, state, context, reporting, replay |
| fact assessment history, heads, evidence/execution links | `FactAssessmentStore` | same SQLite file as `FactStore` | verifier, state/context/capability read models, graph projection, reporting |
| AI missions, planner tasks, dependencies, attempts | `MissionStore` | same SQLite file as `FactStore` | scan recovery, pipeline compatibility views, trace reporting |
| encrypted secrets/references | `SecretStore` | `data/secrets.db` plus key file | fact redactor, credentials, memory |
| scan/session legacy rows | `db.py` | configured MariaDB | octopus resume/report/export |
| semantic graph | `KnowledgeGraph` | `data/knowledge.db` | runtime projector, verified-path and graph consumers |
| provider selection telemetry | `ProviderTelemetryStore` | `data/provider-telemetry.db` | provider selector and fallback trace |
| bounded decision events | `DecisionTraceStore` | `data/decision-trace.db` | trace reporter and decision metrics |
| exploit candidate intelligence | `ExploitIntelligenceEngine` | `data/exploit_intel.db` | exploit selector |
| C2 agents/tasks/events/operators/tokens | C2 DB/event/operator/enrollment layers | `data/c2.db` | daemon agent/operator paths |
| C2 keys and bootstrap operator key | C2 key/operator layers | `data/keys/`, `data/default_admin.key` | C2 daemon/operators |
| optional vector memory | `VectorMemory` | configured Chroma memory path | memory recall |
| scan checkpoint | octopus checkpoint path | configured checkpoints path | resume |
| rendered evidence/decision trace | octopus/`TraceReporter` | configured logs path | operator/user |
| exported reports | export functions | configured reports path | operator/user |
| C2 daemon log | C2 startup wrapper | `data/c2_daemon.log` | operator/user |
| legacy kill-chain output | individual kill-chain modules | module/config-specific report/loot paths | operator/module code |

`SecretStore` encrypts payloads with AES-GCM in SQLite and uses a sidecar key or
configured key material (`core/secrets.py:55-80`,
`core/secrets.py:147-238`). Its recursive redactor handles nested values and
fact-aware content before persistence/logging (`core/secrets.py:251-448`).
`VectorMemory` redacts stored and recalled documents and stores credentials as
secret references (`memory.py:30-55`, `memory.py:57-147`).

MariaDB connection pooling, transaction, and cursor helpers are in
`db.py:58-134`; schemas cover session history, findings, summaries, tool
results, C2 compatibility rows, and credentials (`db.py:143-407`). `db.py`
defines idempotent `init_db()` but does not execute it at import. Interactive
startup invokes it explicitly during the non-critical MariaDB preflight
(`core/cli/application.py:229-239`), and direct script execution invokes it
before its connection probe. Import safety is covered by
`tests/test_db.py:21-65`. This remains a separate lifecycle from the SQLite
stores.

## Import-time state and lifecycle coupling seams

The current system deliberately uses lazy imports in several places, so the
important coupling is not always visible as a static import cycle:

- `ExecutionPolicy` lazily imports `core.tools` to resolve registered commands
  (`core/execution/policy.py:395-439`).
- importing `core.tools` populates the global decorator registry
  (`core/tools/__init__.py:4-75`, `core/tools/registry.py:101-168`);
- `CredentialStore` is a reference-only singleton that lazily resolves its
  optional MariaDB compatibility backend; exploit-tool helpers depend on it in
  one direction (`core/credentials.py:92-118`,
  `core/tools/exploit_tools.py:36-90`);
- default `SecretStore`/redactor singletons are module state
  (`core/secrets.py:466-502`);
- C2 component names remain module-level compatibility attributes, but receive
  values only after explicit lifecycle initialization
  (`core/c2/daemon.py:74-148`);
- MariaDB keeps a lazy process-global connection pool, while schema migration is
  an explicit startup or script operation (`db.py:58-92`, `db.py:143-412`).

Other mutable globals include the executable tool registry, tool-availability
cache, credential-store singleton, secret-store singletons, the lazy MariaDB
pool, explicitly initialized C2 daemon components, and compatibility
application supervisor/session state in `core.cli.application`. The lifecycle
owner is now explicit, although these compatibility globals remain
process-wide. Tests and later decomposition work must account for those
lifetimes.

## Broad exception boundaries in critical paths

Broad exception handlers have different current semantics and must not be
treated as one category:

| Boundary | Current behavior | Reference |
|---|---|---|
| Fact/MariaDB transaction helpers | roll back and re-raise | `core/ai/fact_store.py:30-40`, `db.py:95-134` |
| Director and planner LLM calls | convert any provider/parsing exception into deterministic fallback output | `core/ai/director.py:80-100`, `core/ai/planner.py:41-74` |
| Evidence parsing | several optional extractor failures are contained so later parsers can continue | `core/ai/evidence.py:1229-1402`, `core/ai/evidence.py:1769-1770` |
| Registered tool invocation | logs the exception and converts it to a legacy error string | `core.tools.runner.run_tool_by_command` |
| C2 HTTP register/beacon | preserves `HTTPException`; maps other failures to generic client errors | `core/c2/daemon.py:227-280`, `core/c2/daemon.py:285-376` |
| C2 event projection | logs handler failure and continues after the event has been committed | `core/c2/event_store.py:213-221` |
| MariaDB explicit preflight migration | `init_db()` logs and contains migration failure; preflight then probes availability and reports a warning for a failed dependent backend | `db.py:143-407`, `core/cli/application.py:229-239` |
| Application startup plugin discovery | logs discovery failure and continues into the menu | `core/cli/main.py:OctopusCLIApplication._discover_extensions` |

The transaction handlers preserve failure, while fallback/containment handlers
change the error contract. Later typed-result work must characterize those
specific boundaries before narrowing exceptions.

## Observed ownership gaps and duplication

These are current-state facts that constrain later phases; they are not a new
architecture proposal.

1. `PipelineRuntime` owns canonical execution/result adapters, graph projection,
   action/provider facades, and decision trace; the characterized production
   loop still performs some orchestration-specific fact writes through its
   shared store/projector seam.
2. Strategic task mapping and executable function registration are separate
   registries with different identifiers and availability semantics.
3. `FactStore` and `MissionStore` share a file but retain ordered, separate
   transactions; MariaDB session tables, `KnowledgeGraph`, exploit intelligence,
   vector memory, and C2 each have independent schema/lifecycle/transaction
   boundaries.
4. `AssetGraph` and `TargetModel` are ephemeral projections;
   `KnowledgeGraph` is a versioned durable projection with idempotent runtime
   refresh. Legacy direct graph APIs remain compatibility seams.
5. Main session persistence is row-by-row and direct/resume paths declare
   completion before every result write; Shodan mode uses the opposite order.
6. Replay writes facts and therefore requires explicit store isolation.
7. Plugins are already out of process; the remaining boundary is isolation
   strength and contract coverage, not moving imports out of the main process.
8. Registered runner dispatch is policy-bound, while lower-level tool helpers
   can still be imported and called directly.
9. Legacy kill-chain paths remain callable and can persist output outside the
   canonical facts/evidence path.
10. Importing `core.tools` still populates the decorator registry. MariaDB and
    C2 persistent initialization is explicit, although their lazy pool and
    initialized component references remain process-global compatibility state.
11. Machine reports and decision metrics are versioned projections, while
    MariaDB/export presentation schemas remain compatibility consumers.

This map is the baseline for contract/ownership decisions. Any later extraction
should first preserve the call paths and durable-write semantics documented
above, then change one ownership boundary at a time with characterization or
contract tests.
