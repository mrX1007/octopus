# Discovery lab v3

This directory is the thin Docker process boundary for the generated Benchmark
v3 fixture. Generation, validation, routing, ledger, and reveal logic live in
`core.benchmarks.v3`; no generated seed or truth file is committed here. The
supported launcher and `labctl` prepare a separate owner-only run directory for
every system/scenario/repetition and bind only that directory at `/controller`.

Use the campaign launcher for a benchmark run. The low-level equivalent for
fixture development is:

```bash
./venv/bin/python -m core.benchmarks.competitors.labctl reset \
  --lab-definition discovery-lab-v3 \
  --scenario-id deep-navigation-v3 \
  --campaign-id local-v3-check \
  --system-id octopus \
  --repetition 1 \
  --matched-fixture-seed 123456 \
  --state-directory .benchmark-state/lab-v3 \
  --target http://127.0.0.1:8080

./venv/bin/python -m core.benchmarks.competitors.labctl cleanup \
  --lab-definition discovery-lab-v3
```

The numeric seed above is local test data only. A publishable campaign uses the
paired seed frozen in `analysis-plan.json`, derived by the launcher from a
32–64-character hexadecimal `OCTOBENCH_V3_BASE_FIXTURE_SEED`. It also records
the configured batch and host IDs.

Products receive the target base URL and start at `/`. That stable root returns
an in-band handoff to the generated entry route. Do not pass the product-view
file, private manifest, ledger, generated seed, or controller state path to a
product process. The container is read-only, capability-free, launched in its
dedicated Compose project, and receives only its per-run controller bind.

The `clean_negative` family still requires a fixture observation: its response
contains a blinded negative-evidence nonce that the controller can verify from
the hash-chained ledger. A process that never contacts the fixture therefore
does not complete the task merely by reporting no findings.

For fixture development only, a controller can reveal one private manifest
after the campaign is sealed and no product run remains:

```bash
./venv/bin/python benchmarks/competitors/labs/discovery-lab-v3/reveal.py \
  /controller/private-variant.json /publication/fixture-reveal.json \
  --campaign-closed
```

Normal v3 publication performs this reveal automatically for every paired
scenario/repetition variant and checksum-covers the reveal data inside
`campaign-context.json`. No v3 result bundle is currently checked in.
