# Pipeline decomposition contract

Baseline: 2,956 lines in `core/ai/pipeline.py`

`AIPipeline` remains the public composition root and compatibility facade, but
the iteration lifecycle and the lowest-dependency orchestration seams now live
in bounded modules:

| Owner | Responsibility |
|---|---|
| `core.ai.scan_loop.ScanLifecycle` | iteration lifecycle, budgets, stop conditions, durable resume bookkeeping, and bounded state-change replan control |
| `core.ai.pipeline_mission.PipelineMissionMixin` | mission/task registration, dependency order, attempts, resume, typed retry metadata, and state-transition signatures |
| `core.ai.pipeline_planning.PipelinePlanningMixin` | plan normalization, enrichment, capability compilation, configurable candidate scoring, and deterministic fallbacks |
| `core.ai.pipeline_observability.PipelineObservabilityMixin` | outcome persistence facades plus goal, command, retry, and efficiency telemetry |
| `core.ai.pipeline_replay.PipelineReplayMixin` | replay and trace-report facades |
| `core.ai.pipeline_telemetry` | pure trace/metric emission helpers |
| `core.ai.outcomes` | pure command/task outcome classification and legacy serialization |
| `core.ai.credential_sync` | runtime credential synchronization without secret-store ownership |
| `core.ai.followups` | bounded proposal rules that do not dispatch commands |

`AIPipeline.run_scan()` still has the original public role and delegates to
`ScanLifecycle`. The facade continues to expose the same runtime-owned stores,
parser, scheduler, reporter, action catalog, and provider services; extraction
does not create a parallel runtime or policy boundary.

The acceptance contract keeps `pipeline.py` at or below 2,400 lines, more than
18% below the baseline. Replay, follow-up ordering, result shapes, scan-loop
delegation, mission resume, telemetry wiring, and outcome classification are
covered by domain characterization tests. Any further extraction must preserve
those contracts or introduce an explicit versioned behavior change.
