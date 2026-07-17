# Reproducible dependency locks

This directory is the generated, wheel-only dependency boundary for OCTOPUS.
The checked-in `manifest.json` is resolved: every managed lock has a recorded
digest and every requirement has exact artifact hashes. No placeholder
packages or fake hashes are committed.

The matrix contains 24 lock files: the `runtime`, `test`, `mysql`,
`external-tools`, `platform`, and `full` profiles for CPython 3.9, 3.10, 3.11,
and 3.12 on `x86_64-manylinux_2_34`.

## Commands

Use exactly `uv==0.11.28`:

```console
python scripts/lock_requirements.py update
python scripts/lock_requirements.py check
python scripts/lock_requirements.py validate
```

- `update` resolves all artifacts in a temporary directory, validates every
  exact pin and SHA-256 hash, then replaces the managed files. This command is
  allowed to contact the configured package index.
- `check` performs the same resolution in a temporary directory and compares
  bytes without modifying the repository. It therefore also needs index
  access.
- `validate` is offline. It verifies the fixed epoch, current input hashes,
  exact 24-file matrix, manifest metadata, lock digests, exact pins, and hashes.

Resolution uses the fixed cutoff in `EPOCH`, the first-index strategy, the
credential-free `https://pypi.org/simple` default index, and
`--only-binary :all:`. The resolver sanitizes inherited `PIP_*`/`UV_*` index
configuration, accepts no index option from the lock CLI, and does not emit an
index URL into lock files. `--emit-build-options` persists the binary-default
policy inside every generated lock. The current `shodan==1.31.0` distribution
has no usable wheel, so only the `external-tools` and `full` profiles carry the
explicit `--no-binary shodan` exception. Offline validation requires the exact
per-profile allowlist and rejects every other `--no-binary`, index, link, or
installer directive.

The manifest models this without contradiction as an sdist policy whose
default is `deny` and whose allowlist is explicit for every profile.

The Shodan exception executes a trusted source build during installation. Run
that profile only in an isolated builder with pinned build tooling, no package
credentials in the environment, restricted egress, and no reuse of build
artifacts until their provenance is recorded. Core `runtime`, `test`, `mysql`,
and `platform` profiles remain strictly binary-only.
Requirement inputs may not contain installer options, local/VCS paths, or
direct URL references. Resolver calls use an argv list and never a shell.

Install or synchronize a selected generated profile with hash and binary-only
enforcement, for example:

```console
uv pip sync --require-hashes --only-binary :all: \
  requirements/locks/linux-x86_64/cp311/runtime.txt
```

The manifest is canonical JSON. Each artifact records its SHA-256 digest and
the SHA-256 digest of every source profile used to produce it. Do not edit
generated locks or a resolved manifest by hand.
