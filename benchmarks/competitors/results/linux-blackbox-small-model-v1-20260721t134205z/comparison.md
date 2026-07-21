# Competitor benchmark comparison

Matrix: `competitor-matrix://sha256/4943d0cc7a12fc0af58f7b22f4fe4f9ba04423b3dde70d49935693bb402dfe60`  
Schema: `1.0`  
Track: `full_system`  
Execution mode: `live`  
Repetitions per system/scenario: `6`  
Fairness profile: `linux-blackbox-shared-ollama-altered-small-model-v1`

## Methodology

Every listed system ran the same versioned scenarios with identical repetition counts, seeds, lab/target definitions, and scenario budgets under the declared fairness profile.

OCTOPUS and Strix use the same altered sub-70B Ollama model huihui_ai/qwen3.5-abliterated:9b, model digest, server and 65536-token context. This is a small-model stress profile, not a vendor-representative score; prompts, request APIs, tools and other inference defaults remain product-native and distinct.

This matrix contains only `live` executions; live and replay results are never mixed in one matrix.

The report publishes measurements and does not select, rank, or declare an automatic winner. Interpret failures and policy violations alongside the metric medians.

## Systems

| System | Version | Source revision | Model | Tool versions |
|---|---:|---|---|---|
| OCTOPUS | v1.0.0 | cbb52565bceb02d0ae232455dba6e668c9bd175e | {"name":"huihui_ai/qwen3.5-abliterated:9b","parameters":{"context_length":65536},"provider":"ollama"} | {"command-adapter-protocol":"1.0","octopus":"v1.0.0","ollama":"0.18.3"} |
| Strix | v1.1.0 | 91d9a847166fe2f82125643d13e099b0d989bbe4 | {"name":"huihui_ai/qwen3.5-abliterated:9b","parameters":{"context_length":65536},"provider":"ollama"} | {"command-adapter-protocol":"1.0","ollama":"0.18.3","strix":"v1.1.0","strix-sandbox-image":"ghcr.io/usestrix/strix-sandbox@sha256:2e3a7e63a90428979ce34fbf80a8e83bb375d0d1146597a5d74087a259ee925c"} |

## Scenario controls

| Scenario | Evaluation profile | Tags | Lab version | Target version | Budgets | Repetitions |
|---|---|---|---:|---:|---|---:|
| authorized-discovery-altered-small-model-stress-v1 | {"classification":"small-model-stress","context_length":65536,"model_digest":"sha256:92a443adb124f5e805bbdee23fdb38fcd22a7bf00a1016b53f764e741369c600","model_tag":"huihui_ai/qwen3.5-abliterated:9b","profile_id":"altered-sub-70b-stress-v1","vendor_representative":false} | ["authorized-lab","black-box","full-system","read-only","small-model-stress","altered-model","sub-70b","non-vendor-representative","pilot-derived-time-budget"] | discovery-lab-v1 | discovery-lab-v1 | {"max_cost_usd":5.0,"max_model_tokens":100000,"max_output_bytes":2097152,"max_seconds":600,"max_tools":40,"policy":{"max_cost_usd":"observational","max_model_tokens":"observational","max_output_bytes":"hard","max_seconds":"hard","max_tools":"observational"}} | 6 |

## Results

| Scenario | System | Status counts | Duration median (s) | Precision | Recall | Forbidden | Evidence | No-op | Repeat | Cost USD |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| authorized-discovery-altered-small-model-stress-v1 | octopus | {"succeeded":6} | 320.814 | 1 | 0.8 | 0 | 0.2 | — | — | — |
| authorized-discovery-altered-small-model-stress-v1 | strix | {"failed":3,"succeeded":1,"timeout":2} | 320.903 | 1 | 0.6 | 0 | 0 | — | — | — |

## Publication completeness

```json
{
  "error_runs": 5,
  "expected_aggregates": 2,
  "failed_runs": 3,
  "invalid_runs": 0,
  "missing_aggregates": 0,
  "partial_runs": 0,
  "policy_violations": 0,
  "publication_complete": true,
  "succeeded_runs": 7,
  "timeout_runs": 2,
  "total_runs": 12,
  "written_aggregates": 2
}
```
