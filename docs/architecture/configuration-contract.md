# Runtime Configuration Contract

Status: current architecture contract, 2026-07-29.

## Invariant

Every supported runtime setting must have one traceable path:

```text
schema/default -> validation -> CFG -> runtime consumer -> policy/execution gate
               -> focused test -> operator documentation
```

A key is not supported merely because it appears in YAML. A key without a
validated default, a real consumer, focused coverage and documented behavior is
dead configuration and should be removed or explicitly deprecated. Security
switches fail closed at the final execution boundary even when an earlier
planner, wrapper or alias makes an incorrect decision.

## Ownership

| Contract layer | Owner | Required behavior |
| --- | --- | --- |
| Schema and defaults | `config.DEFAULTS`; shipped `config.yaml` is its operator-facing instance | Known keys, types and defaults agree. `config.KILLCHAIN_STAGE_KEYS` enumerates the accepted YAML stage keys. |
| Source precedence and validation | `config.load_config()`, `_deep_merge()` and `_validate_value()` | Explicit `OCTOPUS_CONFIG`, user, system and bundled sources have deterministic precedence. Unknown keys, wrong types and out-of-range values raise `ConfigValidationError`; they are not silently replaced by an enabled default. |
| Runtime consumption | The narrow module that uses the value; shared limit composition belongs in `core.runtime_config` | Consumers read the validated `CFG` value. They must not maintain a second default or reinterpret strings as booleans. |
| Named-stage identity | `core.killchain.policy.STAGE_REGISTRY` | One immutable `StageSpec` registry derives `KILLCHAIN_STAGES`, `TASK_STAGE_MAP`, `GOAL_STAGE_MAP` and `TOOL_STAGE_MAP`. Registry aliases normalize to the same canonical stage. |
| Automation selection | `automated_stage_enabled()` and `policy_snapshot()` | `strategy.auto_killchain` may remove autonomous candidates. It grants no execution authority and cannot override hard gates. |
| Final authorization | `ExecutionPolicy.authorize_registered()` | Both the canonical registered name and alternate executable/alias are checked. Master-off, disabled-stage, malformed-stage and unknown reserved `killchain_*` names are denied before provider dispatch. |
| Provider boundary | The registered action/provider adapter | Providers receive only already-authorized requests. Policy code never calls a provider or resolves credential material. |
| Regression proof | `tests/test_config.py` and `tests/test_killchain_config_policy.py` | Tests cover source/schema validation, exact stage parity, aliases, malformed values, master/stage denial and a legitimate enabled approved control. |

The configuration loader and stage registry deliberately remain separate
modules to avoid importing provider packages while configuration is being
constructed. Their shared interface is closed by an exact parity test between
`config.KILLCHAIN_STAGE_KEYS`, the default `killchain.stages` keys and
`KILLCHAIN_STAGES`.

## Seven Named Stages

The canonical stages, in orchestration order, are:

1. `vuln_assess`
2. `exploitation`
3. `privesc`
4. `persistence`
5. `lateral_movement`
6. `data_exfil`
7. `cleanup`

Numeric labels in legacy console output or historical documents are not
configuration keys and must not be used for authorization. Tasks, AI goals,
canonical tool names and registered aliases all resolve through
`STAGE_REGISTRY`.

`killchain_full` and its registered alias are workflow entries rather than an
eighth stage. The final execution policy applies the master gate to that entry;
the orchestrator applies each named stage gate before its provider boundary.

## Fail-Closed Semantics

At the policy boundary, only the YAML boolean `true` enables the master switch
or a stage. Missing mappings, missing keys, string values such as `"true"`,
unknown canonical stage names and wrong container types do not grant authority.
Stable machine reasons are returned for audit and tests:

- `killchain_disabled`
- `killchain_stage_disabled:<canonical-stage>`
- `killchain_unknown_stage:<name>`
- `killchain_unknown_tool:<reserved-name>`

Human-facing wrappers may render those reasons as blocked or skipped status
lines, but they must not turn a denial into success. Registry aliases and the
registry-compatible `run_` prefix are normalized before the decision. The
execution policy checks both `ToolInvocation.registered_name` and
`ToolInvocation.executable`, so a benign-looking alternate name cannot mask a
gated alias.

## CredentialRef Boundary

Credential identity and secret material have different owners:

- `CredentialRef` is the control-plane value used by planning, scheduling,
  policy evaluation, registry dispatch and orchestration.
- `SecretStore` owns stored secret material; `CredentialStore` indexes opaque
  references.
- `ExecutionPolicy` evaluates capabilities, scope, approval and named-stage
  configuration without resolving a reference.
- Only the immediate, already-authorized provider may enter
  `credential_material_for_execution()` (or the equivalent bounded material
  context). Plaintext must not be returned to the control plane, placed in
  policy metadata, persisted in reports or retained beyond that context.

This ordering is mandatory: gate first, reveal immediately before the provider,
clear material on context exit.

## Change Checklist

For every added or changed setting:

1. Add or update its built-in default and shipped YAML instance.
2. Define accepted type, range, enum or exact-key constraints in the loader.
3. Identify one runtime consumer and remove duplicate local defaults.
4. Add a final policy check when the value controls execution authority.
5. Test a valid non-default value, invalid input and the consumer-visible
   effect. For gates, test denial through the final execution policy and one
   legitimate allowed control without invoking a provider.
6. Update this contract and operator-facing README/config comments.
7. Remove unsupported keys instead of leaving plausible but inert controls.

Any configuration change that cannot satisfy this chain is incomplete.
