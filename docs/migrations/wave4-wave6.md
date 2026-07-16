# Wave 4–6 migration notes

These changes add canonical identity/projections, action lifecycle adapters,
provider telemetry, recovery controls, evidence reports, decision trace, and a
benchmark contract. They preserve existing public tool, report, and pipeline
facades unless noted below.

## Before upgrading

1. Stop active scans and C2 lifecycle processes cleanly.
2. Back up configured fact, mission, graph, telemetry, decision-trace, secret,
   and application databases, including SQLite WAL/SHM companions.
3. Record the current application revision, Python/dependency lock, config, and
   plugin/vendor manifests.
4. Confirm the backup can be restored in an isolated directory.

## Forward initialization

Opening the new runtime performs idempotent initialization:

- FactStore merges legacy duplicate facts/observations/references before
  enforcing canonical uniqueness and extends canonical command-result fields.
- FactAssessmentStore `1.1` backfills an observed assessment for legacy facts,
  migrates `1.0` history to stable rule IDs, and redacts legacy assessment text.
- MissionStore `1.0` adds stable scan/target/reason/outcome keys and validates
  one supported component version.
- KnowledgeGraph `2.0` migrates legacy identities to normalization version
  metadata and records fact projection fingerprints.
- ProviderTelemetryStore and DecisionTraceStore create independent schema `1.0`
  stores; both are disposable observability projections.

An unsupported explicit component version stops that component. Do not remove
or rewrite the version row to force startup.

## Compatibility behavior

- `core.tools.exploit_tools.ToolResult` is now an import-compatible alias of
  `core.tools.base.ToolResult`; object/string display compatibility remains.
- Registered tools, plugins, exploits, Metasploit, and kill-chain functions are
  wrapped by adapters; their provider implementations are not replaced.
- Legacy result/report fields remain renderers alongside `machine_report`.
- `PipelineRuntime.dispatch()` and `ingest_output()` remain public compatibility
  methods.
- `KnowledgeEnricher` remains available during its deprecation/usage-observation
  window.
- Payload adaptation now requires an explicit bounded local template containing
  `__LHOST__` and `__LPORT__`; built-in simulated payload generation is removed.

## Validation after upgrade

Run the release checklist, then verify:

- repeated fact and graph projection replay does not change row counts;
- an interrupted mission resumes without duplicate execution;
- verified findings have assessments, evidence chains, and execution IDs;
- candidates, access, blocked/degraded checks, and cleanup remain in distinct
  report sections;
- decision events and provider telemetry contain no raw secret or stdout;
- the ten benchmark scenarios load and each aggregate contains at least five
  repetitions with median and variance.

## Rollback

Restore all authoritative database backups and the prior binary/config
together. Graph, provider telemetry, and decision trace created only by the new
version may be removed after writers stop, because they are rebuildable
projections. Do not attempt a row-level downgrade of facts, assessments,
missions, or secrets.
