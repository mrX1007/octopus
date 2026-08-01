# CI and vendor integrity contract

Effective date: 2026-07-14. Last verified: 2026-08-01.

This document describes the bounded Phase 0.3 quality and supply-chain gates.
It does not change application startup, execution policy, or the automatic C2
lifecycle.

## CI jobs

| Job | Contract |
|---|---|
| `import-smoke` | Validates the lock manifest offline, installs only the hashed `cp310/runtime.txt` lock, runs `pip check`, then imports the main first-party runtime boundaries with isolated Python startup. Optional MySQL and external-tool profiles are not installed. |
| `profile-imports` | Installs and import-smokes each optional `c2`, `reporting`, `osint-browser`, and `mysql` profile from its `cp310` lock. |
| `static-analysis` | Validates all locks offline, installs the hashed `cp310/test.txt` lock, runs Ruff, the 197-file direct mypy ratchet, and the nine-file import-aware mypy ratchet, then compiles first-party Python sources. |
| `fast-tests` | Validates all locks offline, installs the matching `cp310`, `cp311`, or `cp312` test lock, and runs the hermetic selector on Python 3.10–3.12. |
| `full-suite` | Validates all locks offline, installs the hashed `cp310/test.txt` lock, then runs the complete suite with branch coverage over every first-party Python file except the documented non-production trees. |
| `mysql-integration` | Installs both the `cp310/test.txt` and `cp310/mysql.txt` locks, provisions MySQL 8.4, and runs the live database marker with the application's `OCTOPUS_DB_*` environment contract. |
| `dependency-security` | Audits the exact `cp310/full.txt` dependency graph and emits a deterministic CycloneDX SBOM. |
| `c2-go` | Uses Go 1.21, applies `gofmt` validation to every tracked Go source from the repository root, verifies downloaded modules, runs `go test`, `go vet`, and a clean `go build` in `core/c2`, then uploads the module-scoped native coverprofile as non-blocking evidence. |
| `vendor-integrity` | Recursively checks out submodules and verifies parent gitlinks, checked-out commits, clean submodule worktrees, tracked artifact paths, and SHA-256 digests. Vendor code is never imported or executed by the verifier. |

Every job is pinned to Ubuntu 22.04, matching the `manylinux_2_34` lock target,
and checks out submodules recursively with persisted GitHub credentials
disabled. CI has read-only repository permissions. Moving to another Ubuntu
image requires regenerating and validating the corresponding dependency locks
instead of silently following `ubuntu-latest`.

## Python dependency lock enforcement

The Linux CI installation boundary is immutable and fail-closed:

1. `python scripts/lock_requirements.py validate` runs before any dependency
   installation and checks the manifest, source-input digests, target/profile
   matrix, lock-file digests, hash coverage, and lock policy without network
   access;
2. pip installs the job's target-specific file with `--require-hashes`;
3. `pip check` verifies the installed distribution graph.

The import smoke uses only `linux-x86_64/cp310/runtime.txt`. Static analysis and
the complete suite use `linux-x86_64/cp310/test.txt`. The fast matrix maps Python
3.10, 3.11, and 3.12 to `cp310`, `cp311`, and `cp312` respectively.
CI intentionally does not install the `full`, `external-tools`, `mysql`, or
`platform` locks in these hermetic jobs. Range-based requirement profiles remain
human-maintained resolver inputs; they are not used as CI installation inputs.

The separate `ollama-scanner-lab-e2e` workflow is scheduled weekly and is also
available through `workflow_dispatch`. It deliberately uses the full Python
profile plus live Ollama, Nmap, Docker, and a loopback-only vulnerable fixture,
so it is evidence outside the mandatory push/PR quality gate. Its contract is
documented in `docs/integration/ollama-scanner-lab-e2e.md`.

## Coverage regression gate

`quality/coverage-ci.ini` and `scripts/quality/coverage_gate.py` keep the Phase
0.1 denominator honest. The gate explicitly discovers and reports every
first-party Python file, including files that coverage.py cannot discover as an
importable package and therefore measures at zero. Tests, local environments,
generated build outputs, and vendor submodules are the only excluded source
trees. Line and partial-branch exclusion lists are explicitly empty. The global
CI's current regression threshold is **94.00% statement-plus-branch coverage**.
The latest recorded clean CPython 3.12 run measured **94.01%** globally, with
`3979 passed, 2 skipped`. The long-term target remains 100%. The explicit helper
result is the authoritative denominator; display rounding cannot turn a partial
measurement into a passing result.

The same CI step enforces package ratchets against the recorded baseline:
`core/actions` measured 95.41% with a 95% floor, `core/execution` measured
92.59% with a 92% floor, and `core/benchmarks` retains an exact 100% floor. The
changed-line calculation remains enabled and reported, but its temporary
blocking floor is 0% because no post-formatting diff baseline has been
recorded. Branch
exits are attributed to their originating changed line, physical continuation
lines are normalized to coverage.py's canonical statement line, and line-only
coverage data fails closed. Any threshold change must update its focused tests
and this contract in the same logical change.

Tighten any baseline in the same logical change that adds tests and records a
fresh measurement. Never exclude a production module merely to satisfy the
gate. Reaching the 94.00% CI floor is not a claim of complete coverage.

The full-suite job also emits a separate non-blocking coverage table for every
module in `core/killchain`, including the AD and exploit subpackages. This keeps
the lowest-covered risk-heavy modules visible even when the aggregate gate is
green. The report is evidence for selecting the next focused tests; it is not a
substitute for a future per-module ratchet.

`scripts/quality/go_coverage_gate.py` remains available as a strict local audit
that separately discovers every first-party
production `.go` file, requires each source to belong to a checked-in Go module,
maps standard coverprofile module aliases without suffix guessing, and fails on
missing, external, ambiguous, malformed, or overlapping profile data. It sums
Go's `numStmt` weights and defaults to a 100% floor. The current orphan
`core/opsec/ja3_client.go` therefore fails that strict audit instead of being
silently omitted. CI does not block on this audit while the repository has no
Go tests; it preserves the `core/c2` coverprofile as evidence instead.

The native Go coverprofile format measures statements/basic blocks, not branch
edges. Consequently this job can prove Go statement coverage only. A claim of
Go branch coverage additionally requires an approved branch-aware Go
instrumenter; the Python statement-plus-branch gate does not substitute for it.

## Vendor trust manifest

`quality/vendor-manifest.json` is schema version 1. It contains two independent
review controls:

1. the exact commit expected for every parent-repository gitlink;
2. the SHA-256 digest and OS/architecture identity of every prebuilt executable
   that OCTOPUS may select from `vendor/cpanel_sniper`.

The verifier also requires each artifact to exist in the pinned submodule tree,
rejects absolute/non-canonical/traversing paths and symlinks, and fails when a
CI submodule checkout is dirty. `--allow-dirty` exists only for local inspection
of a user-modified checkout; it does not disable commit or artifact hash checks
and must not be used by CI.

To update a submodule or binary intentionally:

1. review the upstream source and release provenance;
2. update the parent gitlink;
3. calculate SHA-256 from the reviewed artifact bytes on a trusted host;
4. update the corresponding commit and artifact entries in the manifest;
5. run the verifier for `all` and the target platform;
6. review the gitlink and manifest diff together.

Local validation which preserves the currently dirty user submodules:

```bash
python -I scripts/quality/verify_vendor.py --platform all --allow-dirty
```

CI deliberately omits `--allow-dirty`.

## Dependency-lock immutability

The Python Linux CI gap is closed by the reviewed target-specific locks,
offline manifest validation, and hash-required installs. The Go checksum gap is
also closed: `core/c2/go.mod` pins direct module versions and the reviewed
`core/c2/go.sum` is committed. Linux CI runs `go mod download` and
`go mod verify` before Go test, vet, and build jobs. Test, vet, and build run
with `-mod=readonly`; a final scoped `git diff --exit-code -- go.mod go.sum`
proves that module resolution and all Go quality commands left both files
unchanged.

## Local commands

```bash
venv/bin/python -m pytest -q tests/test_vendor_verification.py
venv/bin/python -m ruff check scripts/quality tests/test_vendor_verification.py
venv/bin/python -m mypy
venv/bin/python -m mypy --config-file quality/mypy-import-aware.ini
python scripts/lock_requirements.py validate
venv/bin/python scripts/quality/coverage_gate.py \
  --root . --fail-under 94.00 \
  --package-fail-under core/actions=95 \
  --package-fail-under core/execution=92 \
  --package-fail-under core/benchmarks=100
python -I scripts/quality/import_smoke.py
python -I scripts/quality/verify_vendor.py --platform all --allow-dirty
```

Pass `--data-file /absolute/path/to/measurement.coverage` to validate an
isolated measurement without replacing the repository-local `.coverage` file.

The Go commands require Go 1.21 and network-resolved modules. Linux CI generates
`c2-go.coverage.out` with `-covermode=atomic -coverpkg=./...` and uploads it
without a blocking coverage floor. The strict repository-wide helper remains a
manual audit and currently fails on the documented orphan source. These commands
remain CI-only evidence until that toolchain is installed in the macOS
development environment.
