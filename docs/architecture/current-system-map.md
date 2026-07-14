# OCTOPUS current system map

Baseline date: 2026-07-14

Reference revision: `36f0677`

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

The interactive application enters through `octopus.py:2444-2527`. Startup
configures logging/readline, constructs and starts the supervisor, registers a
shutdown hook, runs preflight, starts C2 automatically, discovers isolated
plugins, and then enters the menu (`octopus.py:2470-2527`). C2 auto-start is
therefore current intended behavior, not an inferred future feature
(`octopus.py:2508-2509`).

There are three principal scan paths:

1. A direct scan creates a MariaDB session, runs reconnaissance, constructs
   `AIPipeline`, calls `run_scan()`, and adapts/saves the result
   (`octopus.py:573-621`). This path marks the session complete before all
   result rows are saved (`octopus.py:618-621`).
2. Shodan parallel mode confines worker threads to reconnaissance, then creates
   sessions and runs each `AIPipeline` on the main thread
   (`octopus.py:769-890`). This path saves results before marking the session
   complete (`octopus.py:876-879`).
3. Resume reads a JSON checkpoint, optionally refreshes reconnaissance or
   rebuilds input from MariaDB, constructs a new `AIPipeline`, and removes the
   checkpoint after success (`octopus.py:1242-1351`). It also marks the session
   complete before `_save_and_show_results()` finishes
   (`octopus.py:1341-1343`).

The central runtime flow currently looks like this:

```text
octopus.py
  -> AIPipeline.run_scan()
     -> deterministic raw-output parsing -> FactStore
     -> StateResolver + ContextBuilder
     -> DirectorLLM -> MissionPlanner -> task normalization
     -> task agents
     -> PipelineRuntime.decide()
     -> PipelineRuntime.execute()
     -> OutputParser directly from AIPipeline -> FactStore directly
     -> StateResolver + report/result adaptation
  -> MariaDB row-by-row persistence -> export/trace files
```

`PipelineRuntime` is instantiated exactly once per `AIPipeline` in production
(`core/ai/pipeline.py:38-55`). Its declared I/O ownership is real for decision
and execution, but the main pipeline currently bypasses its parsing/ingestion
methods after execution. That distinction is detailed next.

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
and fact persistence (`core/ai/runtime.py:61-128`). `dispatch()` composes only
decision and execution (`core/ai/runtime.py:86-94`); callers must invoke
`ingest_output()` separately to parse and persist output
(`core/ai/runtime.py:96-128`).

### Actual production ownership

`AIPipeline.__init__()` constructs one `PipelineRuntime` and exposes aliases to
its facts, scheduler, parser, and reporter (`core/ai/pipeline.py:38-55`). No
second `PipelineRuntime` is constructed in production. The actual task command
path calls `runtime.decide()` and `runtime.execute()`, then invokes the aliased
parser and writes facts itself (`core/ai/pipeline.py:944-1022`). Its `_store_fact`
helper normalizes/redacts data and calls `FactStore.add_fact_with_status()`
directly (`core/ai/pipeline.py:1256-1292`).

Consequently:

| Responsibility | Declared/current component | Actual main-loop caller | Durable write |
|---|---|---|---|
| Command authorization and scheduling | `PipelineRuntime` -> `CommandScheduler` | `AIPipeline._run_task_commands()` | decision trace/result later |
| Context-bound command execution | `PipelineRuntime.execute()` | `AIPipeline._run_task_commands()` | no direct durable write |
| Output parsing | `PipelineRuntime.parse_output()` | `AIPipeline` calls the shared `OutputParser` alias directly | no |
| Fact ingestion | `PipelineRuntime.ingest_output()` | `AIPipeline._store_fact()` and explicit command-result writes | `FactStore` SQLite |
| Decide/execute facade | `PipelineRuntime.dispatch()` | tests/contracts; not the production scan loop | none directly |

The main pipeline itself is stateful. It resets per-scan collections and
counters in `core/ai/pipeline.py:60-87`; parses/stores initial raw output in
`core/ai/pipeline.py:88-115`; resolves state and context, invokes director and
planner, and enforces anti-loop checks in `core/ai/pipeline.py:174-225`; then
runs discovery, verification, analysis, and final state resolution in
`core/ai/pipeline.py:237-392`.

### Pipeline read/write inventory

| Pipeline operation | Reads | Writes | Persistence |
|---|---|---|---|
| Initial ingest | raw reconnaissance text, parser configuration | normalized facts | `data/facts.db` by default |
| Context construction | facts, resolved state, target, tool availability | in-memory `TargetModel`, `AssetGraph`, surface/risk context | none |
| Mission decision | bounded facts/context and LLM response | in-memory goal/plan and decision trace | trace/report writes later |
| Task execution | plan, tool availability, scheduler decision, `ExecutionContext` | subprocess/tool result, command-result record, facts | fact store plus tool-owned stores/files |
| Final adaptation | facts, hypotheses, resolved state | legacy result dict and evidence-backed reporting fields | MariaDB/files in `octopus.py` |

The pipeline’s result adapter reads facts/hypotheses and builds legacy
vulnerability/exploit structures before applying the reporting enricher and
recursive redaction (`octopus.py:1354-1498`).

## Facts, parsing, state, and context

### `FactStore`

`FactStore` is the durable source of truth used by the AI pipeline. It opens a
SQLite database and selects a matching `SecretStore`; the default fact database
uses the default secret path, while a custom fact database gets a sibling
`.secrets` database (`core/ai/fact_store.py:14-28`). Connections commit or roll
back and always close through `_get_conn()` (`core/ai/fact_store.py:30-40`).

Its schema contains canonical facts, hypotheses, fact observations, and command
results (`core/ai/fact_store.py:42-115`). At initialization it also redacts
legacy rows (`core/ai/fact_store.py:122-161`). `add_fact_with_status()` redacts
input, finds a matching canonical fact, updates or inserts it, and records a
separate observation (`core/ai/fact_store.py:197-256`). Reads return facts in a
defined order with observation/source/session metadata
(`core/ai/fact_store.py:295-351`). Command results are separate durable rows
(`core/ai/fact_store.py:403-427`).

Current production fact writers are bounded to these paths:

- `PipelineRuntime.ingest_output()` (`core/ai/runtime.py:96-116`);
- `AIPipeline._store_fact()` and explicit pipeline-derived facts
  (`core/ai/pipeline.py:1256-1292`, `core/ai/pipeline.py:2289-2305`);
- `EvidenceVerifier`, which uses `add_fact_with_status()` with a compatibility
  fallback (`core/ai/evidence.py:187-204`).

The store has no database uniqueness constraint over the complete canonical
fact identity. The current select-then-insert/update implementation therefore
provides application-level deduplication, not a database-enforced concurrent
upsert (`core/ai/fact_store.py:197-256`).

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

`StateResolver` reads `FactStore` and derives an in-memory state snapshot; it
does not persist state (`core/ai/state_resolver.py:8-17`,
`core/ai/state_resolver.py:21-147`). `ContextBuilder` reads that state and the
facts, then constructs `TargetModel`, `AssetGraph`, `SurfaceState`, and the LLM
context (`core/ai/context_builder.py:46-67`,
`core/ai/context_builder.py:117-133`).

`TargetModel` is explicitly a normalized read model
(`core/ai/target_model.py:13-19`). It derives services, endpoints, access,
credentials, and graph/risk views from facts without writing another store
(`core/ai/target_model.py:46-76`). `LLMContextBuilder` bounds and trims this
material before use (`core/ai/llm_context.py:16-110`); it relies on upstream
fact redaction rather than owning secret persistence.

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
(`core/execution/policy.py:290-319`), fails unknown direct execution closed
except for the explicit `rustscan` direct path
(`core/execution/policy.py:321-335`), and permits managed shell only with the
required interactive origin, capability, approval, scope, and destructive
capability checks (`core/execution/policy.py:337-373`). Command lookup imports
the tool registry lazily and returns a typed dispatch classification
(`core/execution/policy.py:395-439`).

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
`core/tools/__init__.py:77-140`). Top-level `tools.py` is a wildcard
compatibility facade (`tools.py:1-4`).

The runner resolves a registered definition, binds/validates arguments, derives
network targets, authorizes the call, and invokes `tool_def.func()`
(`core/tools/runner.py:719-962`). `run_single_tool()` is another policy wrapper
for menu-driven execution (`core/tools/runner.py:536-557`).

Managed process execution creates a process group, applies time/output limits,
and uses `subprocess.Popen` (`core/tools/runner.py:1171-1308`). Intentional shell
mode is isolated to the managed-shell path (`core/tools/runner.py:1323-1343`).
Despite its compatibility name, `run_arbitrary_cmd()` performs policy-authorized
typed dispatch, fails unknown commands closed, and uses direct argv execution
for the narrow direct-command case (`core/tools/runner.py:1346-1375`).

`core/tools/base.py` is a second, lower-level argv process helper
(`core/tools/base.py:103-214`). It does not itself call `ExecutionPolicy`; safety
therefore depends on callers entering through the registered runner. Direct
imports can bypass that outer boundary. Two current `ToolResult` definitions
also coexist (`core/tools/base.py:35-76` and
`core/tools/exploit_tools.py:120-175`).

Tool availability uses a mutable module cache (`core/tools/base.py:24-32`). A
legacy in-memory credential cache also remains in exploit tooling
(`core/tools/exploit_tools.py:28-58`), alongside the unified credential lookup
path (`core/tools/exploit_tools.py:60-117`).

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
(`octopus.py:2511-2521`), and strategic availability summaries
(`core/ai/tool_registry.py:725-735`).

The isolation boundary is process, environment, path validation, JSON, timeout,
and output bounds. It is not an OS syscall, filesystem, or network sandbox.

## Exploits and kill-chain modules

Registered tool dispatch enters exploit selection through
`core/tools/post_tools.py:1156-1159`. The selector can perform a lightweight
service probe when no reconnaissance result exists, maps observed services,
and invokes the exploit intelligence engine (`core/exploits/selector.py:224-280`).
The engine owns a separate SQLite database, initializes/seeds its schema, and
queries/ranks candidates (`core/exploits/exploit_mapper.py:24-149`). Its payload
adapter is currently simulated (`core/exploits/exploit_mapper.py:151-164`).

Legacy kill-chain modules remain callable from the menu and registered wrappers
(`core/tools/runner.py:89-170`, `core/tools/post_tools.py:1156-1159`). They can
write their own reports and loot outside `FactStore`; for example, the
orchestrator writes a report file directly (`core/killchain/orchestrator.py:251-260`).
Those writes are not automatically a canonical fact or evidence observation.

## Graphs and credential projection

Two graph implementations serve different purposes.

| Graph | Source/caller | Reads | Writes | Persistence |
|---|---|---|---|---|
| `core.ai.AssetGraph` | `ContextBuilder` and `TargetModel` | current facts | in-memory nodes/edges | none |
| `core.knowledge.KnowledgeGraph` | primarily credential synchronization; optional enricher | explicit graph calls | SQLite nodes/edges | `data/knowledge.db` |

`AssetGraph` is rebuilt deterministically from facts
(`core/ai/asset_graph.py:10-85`) and is attached by `ContextBuilder` and
`TargetModel` (`core/ai/context_builder.py:65-67`,
`core/ai/target_model.py:46-76`).

`KnowledgeGraph` opens a separate WAL-enabled SQLite database, creates its own
schema, and upserts nodes and edges (`core/knowledge/graph.py:17-152`,
`core/knowledge/graph.py:243-258`). `CredentialStore` synchronizes credential
metadata to it (`core/credentials.py:162-179`). `KnowledgeEnricher` can translate
legacy result text into graph writes (`core/knowledge/enricher.py:10-46`), but no
main scan caller currently projects every `FactStore` observation into this
database. The persistent graph is therefore not a canonical projection of all
facts at this revision.

`CredentialStore` itself fans a credential write out to `SecretStore`, optional
MariaDB, `KnowledgeGraph`, and a legacy cache (`core/credentials.py:97-191`).
Reads explicitly reveal stored secrets when returning usable credentials
(`core/credentials.py:195-225`).

## Reporting and export

`core/ai/reporting.py` builds an evidence index and separates finding groups,
including access findings, before recursively redacting the enriched result
(`core/ai/reporting.py:11-112`, `core/ai/reporting.py:268-279`).
`TraceReporter` reads canonical facts and command results and builds redacted
evidence, finding, coverage, path, remediation, and trace sections
(`core/ai/trace_report.py:16-63`); it emits text and JSON representations
(`core/ai/trace_report.py:65-174`). `octopus.py` writes trace JSON and text below
the configured log path (`octopus.py:208-220`).

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
(`octopus.py:1851-1920`).

## Replay

Replay is a deterministic decision snapshot, not a live execution replay.
`AIPipeline.replay_outputs()` parses supplied outputs into its `FactStore`,
rebuilds context, and snapshots proposed actions without executing them
(`core/ai/pipeline.py:394-434`). The fixture runner constructs a real
`AIPipeline`, invokes that method, then compares facts, actions, and context to
the expected fixture (`core/ai/replay_snapshot.py:9-63`).

Because the replay pipeline uses a real `FactStore`, replay writes to the
configured SQLite fact database. Isolation therefore depends on the caller
passing a dedicated test/replay database; replay is not intrinsically
read-only.

## C2 subsystem

### Startup and boundaries

The main application automatically starts the daemon
(`octopus.py:2508-2509`). `_start_c2_daemon()` launches it as a detached
subprocess and sends output to `data/c2_daemon.log`
(`octopus.py:2244-2290`). The interactive thin client communicates over a
Unix-domain socket (`octopus.py:2218-2242`).

Daemon configuration owns its data directory, keys directory, SQLite database,
operator socket, and request/task/result limits (`core/c2/daemon.py:29-48`).
Importing the daemon module constructs `KeyStore`, crypto, `C2Database`,
`EventStore`, `OperatorManager`, and `EnrollmentAuthority`
(`core/c2/daemon.py:77-94`), so imports have schema/key filesystem side effects.

### Agent protocol

Enrollment consumes a signed single-use token, performs X25519 key agreement,
assigns the server-generated immutable agent ID, and appends/projects an agent
event (`core/c2/daemon.py:184-239`). Beacon handling authenticates/decrypts the
agent request, validates task ownership for ACK/results, enforces bounds,
updates task state, leases pending work, and encrypts the response
(`core/c2/daemon.py:242-333`).

The SQLite backend enables WAL per connection and owns agents, tasks, key
epochs, and consumed enrollment tokens (`core/c2/db_backend.py:9-89`). Agent
insert is immutable (`core/c2/db_backend.py:108-125`); queue, lease, ACK, and
owner-scoped result transitions are implemented at
`core/c2/db_backend.py:201-303`.

### Operator and event protocol

The operator socket enforces operator authentication/role checks and appends
task events (`core/c2/daemon.py:338-446`); its filesystem permissions are set at
startup (`core/c2/daemon.py:449-474`). `OperatorManager` persists operators in
the same C2 database and creates a first-run admin key file
(`core/c2/operators.py:37-104`). Enrollment signing keys and token consumption
are owned by `EnrollmentAuthority` (`core/c2/enrollment.py:25-110`).

`EventStore` persists append-only events, invokes in-process projection
handlers, and tracks replay offsets (`core/c2/event_store.py:59-150`,
`core/c2/event_store.py:179-211`). Projection handlers translate agent/task
events into `C2Database` mutations (`core/c2/daemon.py:103-124`). A handler
failure is logged after the event append and is not part of the same SQLite
transaction (`core/c2/event_store.py:213-221`), so event persistence and the
read-model projection are not atomic. Operator result retrieval deletes the
corresponding completed rows after reading them
(`core/c2/db_backend.py:295-303`).

## Durable stores and file ownership

| Data | Current owner/writer | Default location | Main readers |
|---|---|---|---|
| facts, observations, hypotheses, command results | `FactStore` | `data/facts.db` | pipeline, state, context, reporting, replay |
| encrypted secrets/references | `SecretStore` | `data/secrets.db` plus key file | fact redactor, credentials, memory |
| scan/session legacy rows | `db.py` | configured MariaDB | octopus resume/report/export |
| semantic graph | `KnowledgeGraph` | `data/knowledge.db` | credential and graph consumers |
| exploit candidate intelligence | `ExploitIntelligenceEngine` | `data/exploit_intel.db` | exploit selector |
| C2 agents/tasks/events/operators/tokens | C2 DB/event/operator/enrollment layers | `data/c2.db` | daemon agent/operator paths |
| C2 keys and bootstrap operator key | C2 key/operator layers | `data/keys/`, `data/default_admin.key` | C2 daemon/operators |
| optional vector memory | `VectorMemory` | configured Chroma memory path | memory recall |
| scan checkpoint | octopus checkpoint path | configured checkpoints path | resume |
| evidence/decision trace | octopus/`TraceReporter` | configured logs path | operator/user |
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
results, C2 compatibility rows, and credentials (`db.py:137-387`). The module
runs `init_db()` during import and suppresses initialization failures after
logging (`db.py:388-406`). This is a separate lifecycle from the SQLite stores.

## Import-time state and coupling seams

The current system deliberately uses lazy imports in several places, so the
important coupling is not always visible as a static import cycle:

- `ExecutionPolicy` lazily imports `core.tools` to resolve registered commands
  (`core/execution/policy.py:395-439`).
- importing `core.tools` populates the global decorator registry
  (`core/tools/__init__.py:4-75`, `core/tools/registry.py:101-168`);
- `CredentialStore` and exploit credential compatibility use lazy references to
  synchronize their caches (`core/credentials.py:181-191`,
  `core/tools/exploit_tools.py:28-58`);
- default `SecretStore`/redactor singletons are module state
  (`core/secrets.py:466-502`);
- C2 daemon imports construct database/key-owning components
  (`core/c2/daemon.py:77-94`);
- MariaDB migration runs at `db` import (`db.py:388-406`).

Other mutable globals include the executable tool registry, tool-availability
cache, legacy credential cache, credential-store singleton, secret-store
singletons, C2 daemon components, and top-level application supervisor/session
state (`core/credentials.py:32-59`, `core/secrets.py:466-502`,
`octopus.py:127-128`, `octopus.py:2216-2242`). Tests and decomposition work must
account for those process-wide lifetimes.

## Broad exception boundaries in critical paths

Broad exception handlers have different current semantics and must not be
treated as one category:

| Boundary | Current behavior | Reference |
|---|---|---|
| Fact/MariaDB transaction helpers | roll back and re-raise | `core/ai/fact_store.py:30-40`, `db.py:95-134` |
| Director and planner LLM calls | convert any provider/parsing exception into deterministic fallback output | `core/ai/director.py:80-100`, `core/ai/planner.py:41-74` |
| Evidence parsing | several optional extractor failures are contained so later parsers can continue | `core/ai/evidence.py:1229-1402`, `core/ai/evidence.py:1769-1770` |
| Registered tool invocation | logs the exception and converts it to a legacy error string | `core/tools/runner.py:943-970` |
| C2 HTTP register/beacon | preserves `HTTPException`; maps other failures to generic client errors | `core/c2/daemon.py:184-239`, `core/c2/daemon.py:242-333` |
| C2 event projection | logs handler failure and continues after the event has been committed | `core/c2/event_store.py:213-221` |
| MariaDB import migration | logs and suppresses initialization failure | `db.py:388-406` |
| Application startup plugin discovery | logs discovery failure and continues into the menu | `octopus.py:2511-2521` |

The transaction handlers preserve failure, while fallback/containment handlers
change the error contract. Later typed-result work must characterize those
specific boundaries before narrowing exceptions.

## Observed ownership gaps and duplication

These are current-state facts that constrain later phases; they are not a new
architecture proposal.

1. `PipelineRuntime` owns the canonical objects, but the production loop uses
   only its decision/execution half and directly performs parse/ingest.
2. Strategic task mapping and executable function registration are separate
   registries with different identifiers and availability semantics.
3. `FactStore`, MariaDB session tables, `KnowledgeGraph`, exploit intelligence,
   vector memory, and C2 each have independent schema/lifecycle/transaction
   boundaries.
4. `AssetGraph` is an ephemeral facts projection; `KnowledgeGraph` is durable
   but is not automatically projected from all canonical facts.
5. Main session persistence is row-by-row and direct/resume paths declare
   completion before every result write; Shodan mode uses the opposite order.
6. Replay writes facts and therefore requires explicit store isolation.
7. Plugins are already out of process; the remaining boundary is isolation
   strength and contract coverage, not moving imports out of the main process.
8. Registered runner dispatch is policy-bound, while lower-level tool helpers
   can still be imported and called directly.
9. Legacy kill-chain paths remain callable and can persist output outside the
   canonical facts/evidence path.
10. Importing DB/C2/tool packages can mutate schemas, keys, or registries before
    the application lifecycle explicitly starts them.

This map is the baseline for contract/ownership decisions. Any later extraction
should first preserve the call paths and durable-write semantics documented
above, then change one ownership boundary at a time with characterization or
contract tests.
