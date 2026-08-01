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

## Boundaries and limitations

This is a CPU-friendly smoke lane, not a performance benchmark or an exploit
campaign. The model is deliberately small, so only the strict structured
Director response is asserted. Ubuntu's hosted-runner Nmap package is installed
from the runner's signed APT repository rather than frozen in this repository;
the exact resolved Nmap version is captured in every artifact. The Ollama
release is version-pinned and verified with its published release checksum, and
the model ID is attested after pull.
