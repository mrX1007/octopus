# CI and vendor integrity contract

Effective date: 2026-07-14.

This document describes the bounded Phase 0.3 quality and supply-chain gates.
It does not change application startup, execution policy, or the automatic C2
lifecycle.

## CI jobs

| Job | Contract |
|---|---|
| `import-smoke` | Fresh Python 3.9 environment installs only `requirements/runtime.txt`, runs `pip check`, then imports the main first-party runtime boundaries with isolated Python startup. Optional MySQL and external-tool profiles are not installed. |
| `static-analysis` | Installs `requirements/test.txt`, then uses the repository's configured Ruff and mypy scopes and compiles first-party Python sources. |
| `fast-tests` | Runs the hermetic unit/contract selector on Python 3.9, 3.10, 3.11, and 3.12. This matrix is the evidence needed to promote the compatibility candidates documented in `environment-matrix.md`. |
| `full-suite` | Runs the complete suite on the certified Python 3.9 baseline with branch coverage over all first-party Python except tests, generated data, the local venv, and vendor submodules. |
| `c2-go` | Uses Go 1.21, rejects non-`gofmt` source, verifies downloaded modules, and runs `go test`, `go vet`, and a clean `go build` in `core/c2`. |
| `vendor-integrity` | Recursively checks out submodules and verifies parent gitlinks, checked-out commits, clean submodule worktrees, tracked artifact paths, and SHA-256 digests. Vendor code is never imported or executed by the verifier. |

Every job is pinned to Ubuntu 22.04, matching the `manylinux_2_34` lock target,
and checks out submodules recursively with persisted GitHub credentials
disabled. CI has read-only repository permissions. Moving to another Ubuntu
image requires regenerating and validating the corresponding dependency locks
instead of silently following `ubuntu-latest`.

## Coverage regression gate

`quality/coverage-ci.ini` and `scripts/quality/coverage_gate.py` keep the Phase
0.1 denominator honest. The gate explicitly discovers and reports every
first-party Python file, including files that coverage.py cannot discover as an
importable package and therefore measured at zero. Tests, generated data, local
environments, and vendor submodules are the only excluded trees. The initial
threshold is **42.70%**, just below the measured 42.71% baseline to avoid
rounding ambiguity. It is a regression floor, not the final target and not a
claim of 100% coverage.

Raise the threshold in the same logical change that adds tests. Never exclude
a production module merely to satisfy the gate. The long-term test wave still
owns critical branch coverage and eventual project-wide improvement.

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

## Known dependency-lock gap

Python requirement profiles still contain version ranges and are not a
transitive hash lock. `core/c2/go.mod` pins direct module versions, but the
repository currently has no reviewed `core/c2/go.sum`. `go mod download` and
`go mod verify` therefore validate the modules obtained by the Linux runner,
but they do not replace a committed checksum lock.

Do not manufacture either lock from incomplete local packages. Generate and
review Python constraints/hashes and `go.sum` on a trusted networked build host,
then switch installs and Go commands to immutable/readonly mode in a separate
logical change.

## Local commands

```bash
venv/bin/python -m pytest -q tests/test_vendor_verification.py
venv/bin/python -m ruff check scripts/quality tests/test_vendor_verification.py
venv/bin/python -m mypy
venv/bin/python scripts/quality/coverage_gate.py --root . --fail-under 42.70
python -I scripts/quality/import_smoke.py
python -I scripts/quality/verify_vendor.py --platform all --allow-dirty
```

The Go commands require Go 1.21 and network-resolved modules. They are evidence
from Linux CI until that toolchain is installed in the macOS development
environment.
