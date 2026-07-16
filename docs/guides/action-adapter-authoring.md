# Action adapter authoring guide

Use an adapter when an existing registered tool, plugin, exploit, Metasploit
module, or kill-chain action must participate in the unified lifecycle. Do not
copy the provider implementation into `core/actions/`.

## Contract

1. Create an immutable `ActionDescriptor` with a stable lowercase
   `action_id`, kind, category, risk, requirements, capabilities, and any
   compatibility aliases.
2. Subclass `ActionAdapter` and implement `invocation()` and `execute()`.
3. Implement `check()` only when the provider has a safe, meaningful check.
4. Override `verify()` only when independent evidence can prove the outcome.
   Process success alone is not verification.
5. Override `cleanup()` for resources created by the action. Cleanup result is
   recorded even after failed execution.
6. Return the provider's native result; `normalize_result()` converts it to the
   canonical `ExecutionResult`.

`ActionExecutor` owns the lifecycle and invokes policy authorization directly
before execution. Adapter code must not bypass that boundary, spawn an
unbounded subprocess, or treat a planner recommendation as authorization.

## Minimal shape

```python
class ExampleAdapter(ActionAdapter):
    descriptor = ActionDescriptor(...)

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        return ToolInvocation(
            argv=("example", "--target", request.target),
            registered_name=self.descriptor.name,
        )

    def execute(self, request: ActionRequest):
        return existing_provider(request.target)
```

Prefer typed argv and secret references. Never interpolate credentials into a
shell command, trace, error, or descriptor. Scope is derived from the
`ExecutionContext`; do not add an adapter-local allowlist with different
semantics.

## Registration and compatibility

- Decorator-registered tools are wrapped by `build_action_catalog()`.
- Exploits, Metasploit modules, and plugins are registered through the catalog
  helpers.
- Aliases are collision checked. Add an alias only for a documented existing
  name and record its deprecation window.
- A new provider selection signal belongs in `core/actions/selection.py` and
  bounded telemetry, not inside the adapter.

## Required tests

Add contract tests for descriptor stability, requirements, policy denial at the
final boundary, native-result normalization, lifecycle transitions,
verification evidence, cleanup failure, redaction, and any legacy alias. Tests
must inject a provider; they must not launch real external tools.

Run:

```bash
venv/bin/python -m pytest -q tests/test_action_catalog.py tests/test_action_provider_contracts.py
venv/bin/python -m pytest -q -m security
```
