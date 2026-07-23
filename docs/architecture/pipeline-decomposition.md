# Pipeline decomposition contract

Historical baseline: 2,956 physical lines in `core/ai/pipeline.py`

Current measurement (2026-07-23): 2,369 physical lines. The facade is therefore
31 lines below the enforced 2,400-line ceiling.

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
| `core.ai.pipeline_followups.PipelineFollowupsMixin` | controlled post-access dispatch and shared strategy-limit/configuration helpers |
| `core.ai.pipeline_telemetry` | pure trace/metric emission helpers |
| `core.ai.outcomes` | pure command/task outcome classification and legacy serialization |
| `core.ai.credential_sync` | runtime credential synchronization without secret-store ownership |
| `core.ai.followups` | bounded proposal rules that do not dispatch commands |

`AIPipeline.run_scan()` still has the original public role and delegates to
`ScanLifecycle`. The facade continues to expose the same runtime-owned stores,
parser, scheduler, reporter, action catalog, and provider services; extraction
does not create a parallel runtime or policy boundary.

The acceptance contract requires `pipeline.py` to stay at or below 2,400 lines,
more than 18% below the historical baseline. The current working tree meets
that contract. Replay, follow-up ordering, result shapes, scan-loop delegation,
mission resume, telemetry wiring, and outcome classification are covered by
domain characterization tests. Further extraction must preserve the ceiling
and those contracts or introduce an explicit versioned behavior change.
