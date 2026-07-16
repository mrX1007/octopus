# Mission task scoring

Schema version: `1.0`

`core.ai.task_scoring.TaskScorer` is the pure ranking boundary for mission task
candidates. It consumes bounded signals derived by mission control, applies
configuration-owned weights, and returns a deterministic score plus an ordered
explanation. It does not execute tasks, mutate mission state, or authorize an
action; `ExecutionPolicy` remains the final execution authority.

## Signals

All signals are normalized to the inclusive range `0..1`. Invalid, non-finite,
or boolean values fail closed.

| Signal | Direction | Meaning |
| --- | --- | --- |
| `information_gain` | reward | Expected new evidence or reduction in an evidence gap. |
| `coverage_value` | reward | Expected progress against an uncovered mission surface. |
| `verification_value` | reward | Expected corroboration or contradiction of an existing claim. |
| `path_value` | reward | Expected progress along a currently reachable mission path. |
| `cost` | penalty | Normalized time/resource cost. |
| `repeat` | penalty | Prior equivalent attempts or already-covered work. |
| `risk` | penalty | Intrusiveness and operational risk; this is advisory, not authorization. |
| `uncertainty` | penalty | Missing prerequisites or weak expectation that the task can produce value. |

Mission control owns signal derivation because it has the current facts,
coverage gaps, task history, dependency state, and capability assessment. The
scorer owns only the arithmetic and stable ordering.

## Configuration

Every weight is loaded from `strategy.task_scoring.weights`. There are no
fallback weights in the scorer. Both `config.DEFAULTS` and the shipped
`config.yaml` define all eight weights; missing, unknown, negative, non-finite,
or excessively large values are rejected. A factor can be disabled explicitly
with weight `0`.

The score is:

```text
information_gain * W_information_gain
+ coverage_value * W_coverage_value
+ verification_value * W_verification_value
+ path_value * W_path_value
- cost * W_cost
- repeat * W_repeat
- risk * W_risk
- uncertainty * W_uncertainty
```

## Determinism and traceability

Components always appear in the documented order. Contributions and the final
score are rounded to six decimals, `math.fsum` is used for the total, and exact
ties are broken by canonical task ID. `TaskScore.to_trace_dict()` emits schema
version, task ID, total, every signal/weight/contribution, and a stable textual
explanation. The trace contains no target, command, tool output, or credential.

Changing a ranking policy therefore requires only a reviewed configuration
change. Tests cover configuration ownership, reward/penalty decomposition,
stable explanations, tie-breaking, and fail-closed validation.

Mission control may additionally mark a candidate as critical when a bounded
domain rule requires it (for example, a target-specific verification gap).
Criticality is a hard eligibility tier so a plan-size limit cannot hide the
candidate; the configured score still orders candidates within the critical
and ordinary tiers. The trace publishes both the tier and the score breakdown.
