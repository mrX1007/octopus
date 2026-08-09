# Pre-Strix remediation ledger

Status date: 2026-08-09

Baseline revision: `3be8bd2a88b3e218e92f5a4b933b270d16326d11`

This ledger is the acceptance record for the first delivery goal: repair the
known OCTOPUS runtime, security-boundary, packaging, reporting, and quality
gaps before any Strix code is integrated. It is intentionally separate from a
future Strix integration plan.

## Non-negotiable invariants

1. `ExecutionPolicy` remains the final authority for every executable action.
2. Completed executions enter evidence through
   `PipelineRuntime.complete_execution()`.
3. Secrets are persisted and passed by canonical secret/credential reference;
   plaintext does not enter facts, traces, reports, or logs.
4. Cleanup is limited to artifacts created and recorded by the current
   authorized run.
5. One application version owner feeds every user-facing format.
6. Package and source-checkout behavior are covered by explicit capability and
   asset manifests.
7. The removed browser and cPanel vendor integrations have no remaining
   runtime, configuration, packaging, benchmark, or vendor-integrity paths.
   Their names may appear only in this historical ledger and in the regression
   test that proves the removed paths cannot return.

## Starting evidence

- Full local suite before edits:
  `4324 passed, 4 skipped, 1 failed` in 1154.43 seconds.
- The failure was
  `test_parent_termination_kills_nested_product_process_group`; its immediate
  isolated rerun passed (`1 passed in 4.19s`), so it is tracked as a timing
  instability rather than hidden as a green baseline.
- The local interpreter is CPython 3.9.6 although the project requires Python
  3.10 or newer. Final release evidence must therefore include the supported
  Python matrix; this local run is useful but not release certification.
- Both removed vendor submodules had pre-existing executable-bit changes; the
  ShardBrowser tree also had generated `__pycache__` files. Their complete
  recoverable working trees and original metadata were moved to
  `/private/tmp/octopus-removed-vendors.5gXjPB` before removal.

## Work ledger

| ID | Requirement | State | Acceptance evidence |
|---|---|---|---|
| R-01 | Remove cPanel Sniper completely | implemented | Source, gitlink, manifest, registry, wrapper, package and generated-artifact paths are absent; removal regression passes |
| R-02 | Remove ShardBrowser completely while preserving generic browser analysis on a non-Shard backend | implemented | Source, gitlink, package and generated-artifact paths are absent; generic browser/dependency and removal regressions pass |
| R-03 | Thread explicit callback host through full kill-chain stages | implemented | Wrapper, policy and public orchestrator fail closed before stage side effects; legitimate and malformed callback tests pass |
| R-04 | Correct `ArtifactManager` target binding | implemented | Persistence and cleanup bind with `target_ip=host`; target-isolation regression passes |
| R-05 | Make C2 deployment use protocol-v11-compatible generated implants | implemented | Legacy payload is removed; remote deployment fails closed and points to the canonical protocol-v11 Go generator |
| R-06 | Close plaintext credential persistence/output paths | implemented | Secrets persist as references, provider plaintext is short-lived and cleared, reporting/runtime recursively redact, and raw hash execution is quarantined |
| R-07 | Restrict cleanup to recorded artifacts | implemented | Cleanup accepts only exact current-target artifact records; untracked logs/history remain untouched |
| R-08 | Remove credential-bearing `shell=True` paths from reachable adapters | implemented | The sole shell boundary is policy-gated managed shell; sensitive command material is rejected before execution |
| R-09 | Make Go builds deterministic and offline with locked inputs | implemented; main CI execution pending | Go 1.21.13 and Garble 0.12.1 are pinned; stable seed, empty build ID, readonly/trimmed/VCS-free flags, local toolchain and disabled network/workspace are enforced; no runtime `go mod tidy` |
| R-10 | Make service and wheel assets portable and complete | implemented; main CI install smoke pending | Dynamic-user systemd unit, user-state/OCTOPUS_DATA_DIR builder paths, METADATA-driven isolated smoke and explicit Go TLS binary contract pass focused checks |
| R-11 | Make dependency availability exact | implemented | Python, binary, resource, service and vendor dependency expressions are evaluated fail closed; exact graph tests pass |
| R-12 | Mount existing unregistered capabilities through canonical actions | implemented | Safe providers use canonical runtime; 13 unsafe source-only contracts and pass-the-hash are visible but disabled/quarantined and cannot dispatch |
| R-13 | Make canonical report DTO feed every exporter | implemented | JSON, CSV, HTML and PDF derive from the same validated, secret-sanitized `machine_report`; parity tests pass |
| R-14 | Remove stale application version labels | implemented | `core.version` is the sole application version owner and setuptools reads it dynamically; version contracts pass |
| R-15 | Strengthen coverage, external smoke, SBOM, and vendor gates | implemented; main CI execution pending | 90% diff coverage, Go gates, loopback external smoke, deterministic full SBOM and empty-vendor verification are encoded and helper tests pass |
| R-16 | Resolve the process-group timing regression | verified locally | Repeated isolated process-group termination runs pass; the final supported runner remains the CI authority |
| R-17 | Run complete supported verification matrix | pending main CI | Python 3.10–3.12, native pinned Go and installed-wheel jobs must be green on `main` |

## Final verification record

The code-level remediation is ready for the supported CI matrix. Focused
verification collected on 2026-08-09:

- Repository Ruff and `git diff --check` passed.
- A 368-test targeted suite covering every previously failing regression plus
  callback, credentials, registry/quarantine, dependency, packaging, removal,
  vendor and pipeline contracts passed. The sole warning is the local
  CPython 3.9/LibreSSL warning; Python 3.9 is below the supported floor.
- Isolated `scripts/quality/wheel_smoke.py --help`, dependency-lock validation,
  vendor verification (`0 submodules, 0 artifacts`) and the documentation gate
  all passed.
- Focused packaging verification built clean wheel/sdist archives, validated
  METADATA/resources, and proved that the wheel contains the locked C2
  toolchain contract while the source-only JA3 implementation remains sdist
  material rather than an implicit runtime binary.
- The process-group termination regression passed repeated isolated runs.

Release certification is deliberately not claimed from the local Python 3.9
environment. The remaining gate is the encoded `main` CI matrix on Python
3.10–3.12, pinned native Go/Garble, external loopback smoke and installed wheel.
