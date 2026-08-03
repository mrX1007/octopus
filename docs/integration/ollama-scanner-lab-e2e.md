# Ollama, scanner, and vulnerable-lab E2E lane

The `ollama-scanner-lab-e2e` workflow is a separate, non-PR integration lane.
It runs weekly and can also be started with `workflow_dispatch`. It is not part
of the mandatory fast CI suite.

The lane brings up an intentionally vulnerable HTTP fixture on
`127.0.0.1:18080`, proves its path-traversal behavior against synthetic data,
runs the real Nmap executable through Octopus's registered-tool policy boundary,
feeds that scanner output into `AIPipeline`, calls a live Ollama model, and
validates the final canonical machine report. Success requires all of the
following:

- Ollama API version `0.18.3` and model `qwen2.5:0.5b` with model ID prefix
  `a8b0c5157701`;
- a successful live model generation and a successful Octopus Director LLM
  event;
- a real Nmap open-port result for the lab;
- matching `port_open` evidence in the validated machine report; and
- a JSON report that survives an artifact round trip.

The lab image uses the repository's digest-pinned Python Alpine base. It runs as
UID 10001 with all capabilities dropped, a read-only root filesystem, no host
mounts, bounded CPU/memory/PIDs, and a loopback-only published port. The flawed
download handler can therefore disclose only disposable container files. Do not
change the bind address or attach host volumes.

## Run locally

Install Nmap, Docker Compose, Python dependencies, and Ollama `0.18.3`, then pull
the expected small model:

```bash
ollama pull qwen2.5:0.5b
docker compose -f tests/integration/ollama_scanner_lab/compose.yaml up -d --build --wait
```

With `ollama serve` listening on loopback, run the opt-in test:

```bash
export OCTOPUS_RUN_OLLAMA_LAB_E2E=1
export OCTOPUS_OLLAMA_URL=http://127.0.0.1:11434/api/generate
export OCTOPUS_OLLAMA_MODEL=qwen2.5:0.5b
export OCTOPUS_E2E_ARTIFACT_DIR=artifacts/ollama-scanner-lab-e2e
python -m pytest -q tests/integration/test_ollama_scanner_lab_e2e.py
docker compose -f tests/integration/ollama_scanner_lab/compose.yaml down --volumes
```

The workflow uploads `trace-report.json`, raw Nmap output, exact tool versions,
and service logs even when the assertion fails.

Do not add `.benchmark-state/readiness-journal/` to those uploads. When this
runtime is used separately for a full Benchmark v4 campaign, the public source
v3 bundle and v4 companion expose only the exact eight-field readiness
commitment: `campaign_id`, `status` (`ready`), `profile_digest`, `plan_digest`,
`evidence_digest`, `source_run_digest`, `reset_attestation_set_digest`, and
`cleanup_attestation_digest`. The raw readiness journal, calibration runs, and
reset, cleanup, and evidence records remain owner-only and private.

## Scheduled runs and bootstrap failures

The hosted lane is scheduled for Monday at `04:41 UTC`; a notification that
arrives long after the commit therefore does not mean one job ran overnight.
The job itself has a 55-minute timeout. Manual `workflow_dispatch` runs use the
same contract.

Treat a failure in `Install checksum-verified Ollama release` separately from
an E2E assertion failure. Ollama, Nmap, the lab, and pytest have not started if
the log ends before the `sha256sum --check --strict` result.

The workflow pins both Ollama `0.18.3` and the immutable SHA-256 digest of
`ollama-linux-amd64.tar.zst`. It deliberately does not parse the release
`sha256sum.txt`: that manifest records the archive as
`./ollama-linux-amd64.tar.zst`, and a basename-only `grep` previously aborted
the step under `bash -e` after successful downloads. A checksum mismatch now
comes only from `sha256sum` checking the downloaded archive against the pinned
digest.

## Boundaries and limitations

This is a CPU-friendly smoke lane, not a performance benchmark or an exploit
campaign. The model is deliberately small, so only the strict structured
Director response is asserted. Ubuntu's hosted-runner Nmap package is installed
from the runner's signed APT repository rather than frozen in this repository;
the exact resolved Nmap version is captured in every artifact. The Ollama
release is version-pinned and verified with its published release checksum, and
the model ID is attested after pull.
