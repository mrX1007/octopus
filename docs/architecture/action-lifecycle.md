# Unified action catalog and adapter lifecycle

Status: implemented adapter boundary  
Descriptor schema: `1.0`  
Lifecycle/report schema: `1.0`

## Purpose and boundary

`core.actions` is a catalog and lifecycle wrapper over existing providers. It
does not copy or replace provider implementation:

- decorator-registry tools are wrapped by `RegisteredToolAdapter`;
- `killchain_*` registry entries use the named `KillchainActionAdapter`;
- `ExploitBase` instances use `ExploitBaseAdapter`;
- a concrete Metasploit module uses `MetasploitActionAdapter` and the existing
  `run_msf_module()` function;
- inert `PluginManager` descriptors use `PluginActionAdapter`; execution stays
  isolated in the existing plugin worker.

`PipelineRuntime.action_catalog` lazily adapts the current decorator registry
and exposes `execute_action()` as the migration seam. Existing command/replay
facades remain intact. Concrete exploit, Metasploit-module and plugin adapters
are registered when those provider candidates are known; the catalog supplies
`register_exploit()`, `register_metasploit()` and `register_plugins()` helpers.

The production compatibility command path shares the pure canonical-assessment
applicability rule with these adapters. After `CommandScheduler` has performed
its policy and state checks, but before a durable retry grant is consumed or a
provider is dispatched, `exploit_select`, `msf_check`, and `msf_run` are
rejected when every matching vulnerability candidate is contradicted, stale,
or backed only by degraded coverage. Absence of a matching candidate does not
block candidate discovery or a safe check, and unrelated assessments do not
affect the command.

## Descriptor and requirements

Every adapter exposes a versioned, inert `ActionDescriptor` containing stable
ID, provider, kind, category, description/version, compatibility aliases and
requirements. Requirements separate dependency/target applicability from
execution authority. `active=True` is classification metadata; it does not
grant the active-tool capability.

Canonical IDs are namespaced:

- `tool:<registry-name>`;
- `killchain:<registry-name>`;
- `exploit:<cve-or-name>`;
- `metasploit:<module-path>`;
- `plugin:<plugin-name>`.

Alias collisions fail registration instead of silently changing ownership.
Candidate listing calls only `applicability()` and has no execution side
effects.

## Lifecycle semantics

The report intentionally does not collapse these concepts:

| Stage | Values |
|---|---|
| candidate | true once resolved from catalog |
| applicability | unknown / applicable / not applicable |
| check | not run / blocked / completed / failed / unavailable, plus independent positive/negative/unknown result |
| attempt | not attempted / blocked / attempted |
| outcome | unknown / succeeded / failed / partial / timeout / unavailable / cancelled / blocked |
| verification | not run / verified / unverified |
| cleanup | not required / pending / succeeded / failed |

A positive provider check makes a candidate applicable; a negative check is a
completed check and a not-applicable action, not an execution failure. A
successful provider return is only `succeeded`. It becomes `verified` only
when an adapter supplies an independent verification result backed by canonical
evidence and assessment references. Cleanup failure is retained separately and
does not rewrite a successful/verified outcome.

## Authorization order

`ActionExecutor` uses `ExecutionPolicy` twice when a provider supports a check:

1. immediately before the provider check;
2. after applicability/check and immediately before the provider execute call.

Candidate selection, planner output, a positive check and earlier scheduler
approval are not reused as execution authorization. Registered-tool dispatch
continues to enforce its own existing policy boundary as defense in depth.
Synthetic adapters map to the existing registered policy names: exploit checks
to `killchain_vuln_assess`, exploit execution to `killchain_privesc`, MSF phases
to `msf_check`/`msf_run`, and plugin phases to the `plugin` gateway/action.

The lifecycle stores only a SHA-256 policy-decision reference. Invocation audit
metadata includes target and argument counts, not raw argv. Exceptions and
provider results pass through the canonical `ExecutionResult` adapter and the
runtime redactor before appearing in a report.

## Provider-specific compatibility

- Registered tools retain their old command parser/dispatcher and aliases.
- `ExploitBase.normalize_check_result()` and `normalize_run_result()` remain the
  conversion authority for legacy tuple/dict returns; a provider handle is an
  applicability requirement.
- Metasploit module identifiers are structurally validated. Availability is a
  dependency result, check mode remains separate from run mode, and no check
  marker automatically proves final verification.
- `PluginManager` already executes plugin cleanup in its isolated worker. The
  plugin adapter records that provider-managed cleanup as succeeded or failed
  from the explicit worker marker instead of running plugin code in-process.

Contract coverage is in `tests/test_action_catalog.py`.
Production command-gate coverage is in
`tests/test_exploit_command_applicability.py`.
