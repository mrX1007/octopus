"""Resumable, fail-closed competitor campaign lifecycle contracts."""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest

from core.benchmarks.competitors import campaign as campaign_module
from core.benchmarks.competitors import lab as lab_module
from core.benchmarks.competitors.campaign import (
    CampaignAbortedError,
    CampaignConfig,
    _counterbalanced_order,
    _effective_environment,
    run_campaign,
)
from core.benchmarks.competitors.lab import (
    CommandLabController,
    LabCommand,
    LabResetError,
    LabRunContext,
    ResetAttestation,
)
from core.benchmarks.competitors.preflight import CampaignPreflightError
from core.benchmarks.competitors.publication import (
    CampaignPublicationError,
    SecretCanaryDetected,
    publish_campaign_bundle,
    verify_campaign_bundle,
)
from core.benchmarks.competitors.state import (
    CampaignFingerprintMismatch,
    CampaignJournal,
    CampaignLockedError,
    campaign_fingerprint,
    schedule_run_key,
)

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]

SCENARIO_SOURCE = (
    Path(__file__).parents[2]
    / "benchmarks"
    / "scenarios"
    / "01-service-discovery-verification.json"
)
SECRET_VALUE = "campaign-secret-canary-9d831c"


def test_schedule_rotation_balances_every_position_and_reverses_carryover() -> None:
    systems = ("alpha", "beta", "gamma")
    orders = [_counterbalanced_order(systems, repetition) for repetition in range(1, 7)]

    assert orders == [
        ("alpha", "beta", "gamma"),
        ("beta", "gamma", "alpha"),
        ("gamma", "alpha", "beta"),
        ("gamma", "beta", "alpha"),
        ("alpha", "gamma", "beta"),
        ("beta", "alpha", "gamma"),
    ]
    assert all(
        [order[position] for order in orders].count(system) == 2
        for position in range(3)
        for system in systems
    )

    extended = ("alpha", "beta", "gamma", "delta")
    extended_orders = [
        _counterbalanced_order(extended, repetition) for repetition in range(1, 9)
    ]
    directed_pairs = Counter(
        pair
        for order in extended_orders
        for pair in zip(order, order[1:])
    )
    assert set(directed_pairs) == {
        (left, right) for left in extended for right in extended if left != right
    }
    assert set(directed_pairs.values()) == {2}
    assert all(
        [order[position] for order in extended_orders].count(system) == 2
        for position in range(4)
        for system in extended
    )


def test_supplied_runtime_environment_overrides_relative_values_from_env_file(
    tmp_path: Path,
) -> None:
    config, _manifest_paths = _campaign_fixture(tmp_path)
    environment_file = tmp_path / "runtime.env"
    environment_file.write_text(
        "CAMPAIGN_TEST_TOKEN=from-file\nOCTOBENCH_STRIX_BIN=.benchmark-tools/bin/strix\n",
        encoding="utf-8",
    )
    config = replace(config, environment_file=environment_file)

    effective = _effective_environment(
        config,
        {
            "CAMPAIGN_TEST_TOKEN": "from-launcher",
            "OCTOBENCH_STRIX_BIN": "/repo/.benchmark-tools/bin/strix",
        },
    )

    assert effective["CAMPAIGN_TEST_TOKEN"] == "from-launcher"
    assert effective["OCTOBENCH_STRIX_BIN"] == "/repo/.benchmark-tools/bin/strix"


class RecordingLab:
    def __init__(
        self,
        *,
        fail: bool = False,
        cleanup_fail: bool = False,
        observed_at: float = 100.0,
    ) -> None:
        self.fail = fail
        self.cleanup_fail = cleanup_fail
        self.observed_at = observed_at
        self.resets = []
        self.cleanups = []

    def reset_and_health(self, context):
        self.resets.append(context)
        if self.fail:
            raise LabResetError("lab_reset_failed")
        return ResetAttestation(
            context=context,
            reset_duration_seconds=17.0,
            health_duration_seconds=4.0,
            reset_command_sha256="a" * 64,
            health_command_sha256="b" * 64,
            observed_at=self.observed_at,
        )

    def cleanup(self, context):
        self.cleanups.append(context)
        if self.cleanup_fail:
            raise LabResetError("lab_cleanup_failed")


def _manifest_payload(system_id: str, *, executable: str | None = None):
    return {
        "schema_version": "1.0",
        "system_id": system_id,
        "name": system_id.upper(),
        "version": "1.0",
        "source_revision": "a" * 40,
        "execution_mode": "replay",
        "track": "framework_only",
        "fairness_profile": {
            "profile_id": "campaign-test-v1",
            "same_model": True,
            "same_tool_versions": True,
            "same_hardware": True,
            "same_budgets": True,
        },
        "model": {
            "provider": "fixture",
            "name": "shared-model",
            "parameters": {"temperature": 0},
        },
        "tool_versions": {"fixture": "1.0"},
        "adapter": {
            "kind": "command",
            "argv": [
                executable or sys.executable,
                "-c",
                "raise SystemExit(0)",
                "{scenario_path}",
                "{output_path}",
            ],
            "working_directory": ".",
            "environment_passthrough": ["CAMPAIGN_TEST_TOKEN"],
        },
        "metadata": {"purpose": "campaign-test"},
    }


def _campaign_fixture(tmp_path: Path, *, campaign_id: str = "campaign-test"):
    scenario_directory = tmp_path / "scenarios"
    scenario_directory.mkdir()
    (scenario_directory / "service.json").write_text(
        SCENARIO_SOURCE.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    manifest_paths = []
    for system_id in ("alpha", "beta"):
        path = tmp_path / f"{system_id}.json"
        path.write_text(
            json.dumps(_manifest_payload(system_id)),
            encoding="utf-8",
        )
        manifest_paths.append(path)
    payload = {
        "schema_version": "1.0",
        "campaign_id": campaign_id,
        "system_manifests": [path.name for path in manifest_paths],
        "scenario_directory": scenario_directory.name,
        "output_directory": "publication",
        "state_directory": "state",
        "repetitions": 5,
        "required_environment": ["CAMPAIGN_TEST_TOKEN"],
        "secret_environment": ["CAMPAIGN_TEST_TOKEN"],
        "strict_statuses": ["failed", "invalid", "partial", "timeout"],
        "lab": {
            "reset": {
                "argv": [sys.executable, "-c", "raise SystemExit(0)"],
                "working_directory": ".",
            },
            "health": {
                "argv": [sys.executable, "-c", "raise SystemExit(0)"],
                "working_directory": ".",
            },
        },
    }
    config_path = tmp_path / "campaign.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    return CampaignConfig.from_dict(payload, source_path=config_path), manifest_paths


def _successful_runner_factory(calls):
    def factory(manifest):
        def runner(scenario, repetition, seed):
            calls.append((manifest.system_id, scenario.scenario_id, repetition, seed))
            expected = list(scenario.ground_truth["expected_findings"])
            return {
                "status": "succeeded",
                "actions": list(scenario.allowed_actions),
                "reported_findings": expected,
                "verified_findings": expected,
                "coverage_gaps": [],
                "metrics": {
                    "evidence_completeness": 1.0,
                    "api_cost_usd": 0.1,
                },
                "artifact_refs": [],
                "duration_seconds": 0.25,
            }

        return runner

    return factory


def test_campaign_resets_each_run_outside_duration_and_publishes_complete_bundle(
    tmp_path,
    capsys,
):
    config, _manifest_paths = _campaign_fixture(tmp_path)
    calls = []
    lab = RecordingLab()

    clock_ticks = iter(float(value) for value in range(100, 1000))
    outcome = run_campaign(
        config,
        environment={"CAMPAIGN_TEST_TOKEN": SECRET_VALUE},
        runner_factory=_successful_runner_factory(calls),
        lab_controller=lab,
        clock=lambda: next(clock_ticks),
    )

    assert outcome.status == "succeeded"
    assert outcome.exit_code == 0
    assert outcome.executed_runs == 10
    assert outcome.resumed_runs == 0
    assert len(calls) == len(lab.resets) == 10
    assert len(lab.cleanups) == 1
    assert all(item.status_counts == {"succeeded": 5} for item in outcome.matrix.aggregates["alpha"].values())
    assert {
        run.duration_seconds
        for aggregates in outcome.matrix.aggregates.values()
        for aggregate in aggregates.values()
        for run in aggregate.runs
    } == {0.25}
    assert {
        run.finished_at - run.started_at
        for aggregates in outcome.matrix.aggregates.values()
        for aggregate in aggregates.values()
        for run in aggregate.runs
    } == {1.0}

    verification = verify_campaign_bundle(outcome.bundle_path)
    assert verification["status"] == "verified"
    expected = {
        "campaign-status.json",
        "cleanup.json",
        "comparison.json",
        "comparison.md",
        "inputs/campaign.json",
        "inputs/scenarios/service-discovery-verification.json",
        "inputs/systems/alpha.json",
        "inputs/systems/beta.json",
        "preflight.json",
        "provenance.json",
        "schedule.json",
        "SHA256SUMS",
    }
    observed = {
        path.relative_to(outcome.bundle_path).as_posix()
        for path in outcome.bundle_path.rglob("*")
        if path.is_file()
    }
    assert expected.issubset(observed)
    assert len([item for item in observed if item.startswith("attestations/")]) == 10
    cleanup = json.loads((outcome.bundle_path / "cleanup.json").read_text())
    assert cleanup["status"] == "succeeded"
    assert cleanup["fingerprint"] == outcome.fingerprint
    assert SECRET_VALUE not in "".join(
        path.read_text(encoding="utf-8")
        for path in outcome.bundle_path.rglob("*")
        if path.is_file()
    )
    progress_text = capsys.readouterr().err
    progress = [json.loads(line) for line in progress_text.splitlines()]
    assert [item["event"] for item in progress].count("run_started") == 10
    assert [item["event"] for item in progress].count("run_finished") == 10
    assert progress[0] == {
        "campaign_id": config.campaign_id,
        "completed_runs": 0,
        "event": "campaign_started",
        "total_runs": 10,
    }
    assert progress[-1]["event"] == "campaign_published"
    assert progress[-1]["completed_runs"] == 10
    assert SECRET_VALUE not in progress_text


def test_campaign_resumes_only_unfinished_runs_after_interruption(tmp_path):
    config, _manifest_paths = _campaign_fixture(tmp_path)
    first_calls = []
    first_lab = RecordingLab()

    def interrupting_factory(manifest):
        successful = _successful_runner_factory(first_calls)(manifest)

        def runner(*args):
            if len(first_calls) == 3:
                raise KeyboardInterrupt
            return successful(*args)

        return runner

    with pytest.raises(KeyboardInterrupt):
        run_campaign(
            config,
            environment={"CAMPAIGN_TEST_TOKEN": SECRET_VALUE},
            runner_factory=interrupting_factory,
            lab_controller=first_lab,
            clock=lambda: 100.0,
        )
    assert len(first_calls) == 3
    assert not config.output_directory.exists()

    resumed_calls = []
    resumed_lab = RecordingLab(observed_at=200.0)
    outcome = run_campaign(
        config,
        environment={"CAMPAIGN_TEST_TOKEN": SECRET_VALUE},
        runner_factory=_successful_runner_factory(resumed_calls),
        lab_controller=resumed_lab,
        clock=lambda: 100.0,
    )

    assert outcome.executed_runs == 7
    assert outcome.resumed_runs == 3
    assert len(resumed_calls) == len(resumed_lab.resets) == 7
    assert outcome.status == "succeeded"


def test_public_provenance_omits_environment_hash_oracle_while_resume_detects_drift(
    tmp_path: Path,
) -> None:
    config, _manifest_paths = _campaign_fixture(tmp_path)
    low_entropy_environment = {
        "HOME": "/home/benchmark-user",
        "OCTOBENCH_HOST_IP": "192.168.1.29",
        "OCTOBENCH_LAB_PORT": "8080",
        "OCTOBENCH_TARGET_URL": "http://192.168.1.29:8080",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
    }
    config = replace(
        config,
        required_environment=(
            *config.required_environment,
            *low_entropy_environment,
        ),
    )
    environment = {
        "CAMPAIGN_TEST_TOKEN": SECRET_VALUE,
        **low_entropy_environment,
    }

    def interrupting_factory(_manifest):
        def runner(_scenario, _repetition, _seed):
            raise KeyboardInterrupt

        return runner

    with pytest.raises(KeyboardInterrupt):
        run_campaign(
            config,
            environment=environment,
            runner_factory=interrupting_factory,
            lab_controller=RecordingLab(),
            clock=lambda: 100.0,
        )

    journal_campaign = json.loads(
        (
            config.state_directory
            / config.campaign_id
            / "campaign.json"
        ).read_text(encoding="utf-8")
    )
    original_fingerprint = journal_campaign["fingerprint"]
    changed_environment = {**environment, "HOME": "/home/other-user"}
    with pytest.raises(
        CampaignFingerprintMismatch,
        match="campaign_fingerprint_mismatch",
    ):
        run_campaign(
            config,
            environment=changed_environment,
            runner_factory=_successful_runner_factory([]),
            lab_controller=RecordingLab(),
            clock=lambda: 100.0,
        )

    outcome = run_campaign(
        config,
        environment=environment,
        runner_factory=_successful_runner_factory([]),
        lab_controller=RecordingLab(),
        clock=lambda: 100.0,
    )
    assert outcome.fingerprint == original_fingerprint

    provenance_path = outcome.bundle_path / "provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    assert set(provenance["input_sha256"]) == {
        "campaign",
        "scenarios",
        "systems",
    }
    serialized = provenance_path.read_text(encoding="utf-8")
    for value in low_entropy_environment.values():
        assert value not in serialized
        assert hashlib.sha256(value.encode("utf-8")).hexdigest() not in serialized


def test_fully_resumed_campaign_cleans_before_publication(tmp_path, monkeypatch):
    config, _manifest_paths = _campaign_fixture(tmp_path)
    first_lab = RecordingLab()
    real_publish = campaign_module.publish_campaign_bundle

    def fail_publication(**_kwargs):
        raise CampaignPublicationError("forced_publication_failure")

    monkeypatch.setattr(campaign_module, "publish_campaign_bundle", fail_publication)
    with pytest.raises(CampaignPublicationError, match="forced_publication_failure"):
        run_campaign(
            config,
            environment={"CAMPAIGN_TEST_TOKEN": SECRET_VALUE},
            runner_factory=_successful_runner_factory([]),
            lab_controller=first_lab,
            clock=lambda: 100.0,
        )
    assert len(first_lab.cleanups) == 1

    resumed_lab = RecordingLab(observed_at=200.0)
    monkeypatch.setattr(campaign_module, "publish_campaign_bundle", real_publish)
    outcome = run_campaign(
        config,
        environment={"CAMPAIGN_TEST_TOKEN": SECRET_VALUE},
        runner_factory=_successful_runner_factory([]),
        lab_controller=resumed_lab,
        clock=lambda: 200.0,
    )

    assert outcome.executed_runs == 0
    assert outcome.resumed_runs == 10
    assert len(resumed_lab.resets) == 0
    assert len(resumed_lab.cleanups) == 1
    cleanup = json.loads((outcome.bundle_path / "cleanup.json").read_text())
    assert cleanup["observed_at"] == 200.0


def test_cleanup_failure_precedes_publication_and_marks_campaign_partial(
    tmp_path,
    monkeypatch,
):
    config, _manifest_paths = _campaign_fixture(tmp_path)
    lab = RecordingLab(cleanup_fail=True)
    real_publish = campaign_module.publish_campaign_bundle

    def assert_cleanup_then_publish(**kwargs):
        assert len(lab.cleanups) == 1
        assert kwargs["cleanup"]["status"] == "failed"
        return real_publish(**kwargs)

    monkeypatch.setattr(
        campaign_module,
        "publish_campaign_bundle",
        assert_cleanup_then_publish,
    )
    outcome = run_campaign(
        config,
        environment={"CAMPAIGN_TEST_TOKEN": SECRET_VALUE},
        runner_factory=_successful_runner_factory([]),
        lab_controller=lab,
        clock=lambda: 100.0,
    )

    assert outcome.status == "partial"
    assert outcome.exit_code == 1
    cleanup = json.loads((outcome.bundle_path / "cleanup.json").read_text())
    assert cleanup["status"] == "failed"
    assert cleanup["error_class"] == "LabResetError"
    campaign_status = json.loads(
        (outcome.bundle_path / "campaign-status.json").read_text()
    )
    assert campaign_status["status"] == "partial"
    assert campaign_status["cleanup_status"] == "failed"


def test_reset_failure_aborts_before_adapter_and_leaves_resumable_state(tmp_path):
    config, _manifest_paths = _campaign_fixture(tmp_path)
    calls = []
    lab = RecordingLab(fail=True)

    with pytest.raises(CampaignAbortedError, match="lab_reset_failed"):
        run_campaign(
            config,
            environment={"CAMPAIGN_TEST_TOKEN": SECRET_VALUE},
            runner_factory=_successful_runner_factory(calls),
            lab_controller=lab,
        )

    assert calls == []
    assert len(lab.resets) == 1
    assert len(lab.cleanups) == 1
    assert not config.output_directory.exists()
    status = json.loads(
        (config.state_directory / config.campaign_id / "status.json").read_text()
    )
    assert status["status"] == "aborted"


@pytest.mark.parametrize("failure", ["existing_output", "missing_environment"])
def test_preflight_is_fail_closed_and_never_invokes_adapter_or_reset(tmp_path, failure):
    config, _manifest_paths = _campaign_fixture(tmp_path)
    environment = {"CAMPAIGN_TEST_TOKEN": SECRET_VALUE}
    if failure == "existing_output":
        config.output_directory.mkdir()
    else:
        environment = {}
    calls = []
    lab = RecordingLab()

    with pytest.raises(CampaignPreflightError) as exc:
        run_campaign(
            config,
            environment=environment,
            runner_factory=_successful_runner_factory(calls),
            lab_controller=lab,
        )

    assert exc.value.report.passed is False
    assert calls == []
    assert lab.resets == []
    assert SECRET_VALUE not in json.dumps(exc.value.report.to_dict())


def test_preflight_rejects_placeholders_and_unavailable_adapter(tmp_path):
    config, manifest_paths = _campaign_fixture(tmp_path)
    payload = _manifest_payload("alpha", executable="/missing/adapter")
    payload["version"] = "replace-with-version"
    manifest_paths[0].write_text(json.dumps(payload), encoding="utf-8")
    missing_cwd = _manifest_payload("beta")
    missing_cwd["adapter"]["working_directory"] = "missing-directory"
    manifest_paths[1].write_text(json.dumps(missing_cwd), encoding="utf-8")
    calls = []

    with pytest.raises(CampaignPreflightError) as exc:
        run_campaign(
            config,
            environment={"CAMPAIGN_TEST_TOKEN": SECRET_VALUE},
            runner_factory=_successful_runner_factory(calls),
            lab_controller=RecordingLab(),
        )

    failed = {
        item.check_id for item in exc.value.report.checks if not item.passed
    }
    assert "adapter_executable:alpha" in failed
    assert "adapter_cwd:beta" in failed
    assert "completed_placeholders" in failed
    assert calls == []


def test_command_lab_controller_runs_reset_then_health_with_declared_environment(
    tmp_path,
):
    script = tmp_path / "lab_control.py"
    log = tmp_path / "events.log"
    script.write_text(
        """\
import os
import sys

with open(sys.argv[1], "a", encoding="utf-8") as stream:
    stream.write(os.environ["OCTOPUS_BENCHMARK_LAB_PHASE"] + ":")
    stream.write(os.environ["LAB_CONTROL_TOKEN"] + "\\n")
""",
        encoding="utf-8",
    )
    command = LabCommand.from_dict(
        {
            "argv": [sys.executable, str(script), str(log)],
            "working_directory": ".",
            "environment_passthrough": ["LAB_CONTROL_TOKEN"],
        },
        base_directory=tmp_path,
    )
    controller = CommandLabController(
        command,
        command,
        environment={"LAB_CONTROL_TOKEN": "available"},
    )
    context = LabRunContext(
        campaign_id="campaign",
        system_id="alpha",
        scenario_id="scenario",
        repetition=1,
        seed=10,
        lab_version="lab-v1",
        snapshot_ref="snapshot-v1",
    )

    attestation = controller.reset_and_health(context)

    assert log.read_text(encoding="utf-8").splitlines() == [
        "reset:available",
        "health:available",
    ]
    assert attestation.to_dict()["status"] == "healthy"


def test_command_lab_controller_terminates_child_on_operator_interrupt(
    tmp_path,
    monkeypatch,
):
    command = LabCommand.from_dict(
        {
            "argv": [sys.executable, "-c", "pass"],
            "working_directory": ".",
        },
        base_directory=tmp_path,
    )
    controller = CommandLabController(command, command)
    context = LabRunContext(
        campaign_id="campaign",
        system_id="alpha",
        scenario_id="scenario",
        repetition=1,
        seed=10,
        lab_version="lab-v1",
        snapshot_ref="snapshot-v1",
    )

    class InterruptedProcess:
        pid = 12345

        def wait(self, *, timeout):
            raise KeyboardInterrupt

    process = InterruptedProcess()
    terminated = []
    monkeypatch.setattr(lab_module.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        lab_module,
        "_terminate_process",
        lambda observed: terminated.append(observed),
    )

    with pytest.raises(KeyboardInterrupt):
        controller.reset_and_health(context)

    assert terminated == [process]


def test_timeout_status_is_published_but_returns_strict_failure(tmp_path):
    config, _manifest_paths = _campaign_fixture(tmp_path)

    def factory(_manifest):
        def runner(_scenario, _repetition, _seed):
            return {
                "status": "timeout",
                "actions": [],
                "reported_findings": [],
                "verified_findings": [],
                "metrics": {},
                "duration_seconds": 1.0,
                "error_class": "ProductTimeout",
            }

        return runner

    outcome = run_campaign(
        config,
        environment={"CAMPAIGN_TEST_TOKEN": SECRET_VALUE},
        runner_factory=factory,
        lab_controller=RecordingLab(),
        clock=lambda: 100.0,
    )

    assert outcome.status == "completed_with_failures"
    assert outcome.exit_code == 1
    status = json.loads(
        (outcome.bundle_path / "campaign-status.json").read_text(encoding="utf-8")
    )
    assert status["status_counts"] == {"timeout": 10}
    assert {
        run.error_class
        for aggregates in outcome.matrix.aggregates.values()
        for aggregate in aggregates.values()
        for run in aggregate.runs
    } == {"ProductTimeout"}
    assert {
        tuple(run.result_summary["coverage_gaps"])
        for aggregates in outcome.matrix.aggregates.values()
        for aggregate in aggregates.values()
        for run in aggregate.runs
    } == {("ssh_service", "https_service")}


def test_journal_lock_fingerprint_and_immutable_run_contract(tmp_path):
    fingerprint = campaign_fingerprint({"input": "v1"})
    run_key = schedule_run_key("alpha", "scenario", 1, 10)
    schedule = (
        {
            "run_key": run_key,
            "system_id": "alpha",
            "scenario_id": "scenario",
            "repetition": 1,
            "seed": 10,
        },
    )
    first = CampaignJournal(
        tmp_path / "state",
        campaign_id="campaign",
        fingerprint=fingerprint,
    )
    with first.lock():
        first.initialize(schedule)
        with pytest.raises(CampaignLockedError), CampaignJournal(
                tmp_path / "state",
                campaign_id="campaign",
                fingerprint=fingerprint,
            ).lock():
            pass
        record = {"result": {"status": "succeeded"}}
        first.write_run(run_key, record)
        assert first.read_run(run_key)["result"] == {"status": "succeeded"}
        first.write_cleanup_attestation({"status": "succeeded"})
        assert first.read_cleanup_attestation()["status"] == "succeeded"

    changed = CampaignJournal(
        tmp_path / "state",
        campaign_id="campaign",
        fingerprint=campaign_fingerprint({"input": "v2"}),
    )
    with changed.lock(), pytest.raises(CampaignFingerprintMismatch):
        changed.initialize(schedule)


def test_publication_secret_scan_and_verifier_detect_tampering(tmp_path):
    config, _manifest_paths = _campaign_fixture(tmp_path)
    outcome = run_campaign(
        config,
        environment={"CAMPAIGN_TEST_TOKEN": SECRET_VALUE},
        runner_factory=_successful_runner_factory([]),
        lab_controller=RecordingLab(),
        clock=lambda: 100.0,
    )
    unsafe = tmp_path / "unsafe-publication"
    with pytest.raises(SecretCanaryDetected):
        publish_campaign_bundle(
            destination=unsafe,
            matrix=outcome.matrix,
            campaign={"campaign_id": config.campaign_id, "note": SECRET_VALUE},
            fingerprint=outcome.fingerprint,
            manifests=(),
            scenarios=(),
            preflight={"status": "passed"},
            schedule=(),
            attestations=(),
            cleanup={"status": "succeeded"},
            provenance={"revision": "test"},
            campaign_status={"status": "succeeded"},
            secret_canaries=(SECRET_VALUE,),
        )
    assert not unsafe.exists()

    (outcome.bundle_path / "comparison.md").write_text("tampered", encoding="utf-8")
    with pytest.raises(CampaignPublicationError, match="publication_checksum_mismatch"):
        verify_campaign_bundle(outcome.bundle_path)


def test_verifier_accepts_legacy_v1_scenario_metadata(tmp_path):
    config, _manifest_paths = _campaign_fixture(tmp_path)
    outcome = run_campaign(
        config,
        environment={"CAMPAIGN_TEST_TOKEN": SECRET_VALUE},
        runner_factory=_successful_runner_factory([]),
        lab_controller=RecordingLab(),
        clock=lambda: 100.0,
    )
    comparison_path = outcome.bundle_path / "comparison.json"
    comparison = json.loads(comparison_path.read_text(encoding="utf-8"))
    for scenario in comparison["scenarios"]:
        scenario.pop("tags")
        scenario.pop("evaluation_profile")
    comparison_path.write_text(
        json.dumps(comparison, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _rewrite_checksums(outcome.bundle_path)

    assert verify_campaign_bundle(outcome.bundle_path)["status"] == "verified"


def test_verifier_requires_enriched_metadata_for_defined_campaign(tmp_path):
    config, _manifest_paths = _campaign_fixture(tmp_path)
    config = replace(
        config,
        campaign_definition="linux-blackbox-small-model-v1",
    )
    outcome = run_campaign(
        config,
        environment={"CAMPAIGN_TEST_TOKEN": SECRET_VALUE},
        runner_factory=_successful_runner_factory([]),
        lab_controller=RecordingLab(),
        clock=lambda: 100.0,
    )
    comparison_path = outcome.bundle_path / "comparison.json"
    comparison = json.loads(comparison_path.read_text(encoding="utf-8"))
    for scenario in comparison["scenarios"]:
        scenario.pop("tags")
        scenario.pop("evaluation_profile")
    comparison_path.write_text(
        json.dumps(comparison, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _rewrite_checksums(outcome.bundle_path)

    with pytest.raises(
        CampaignPublicationError,
        match="publication_semantic_invalid",
    ):
        verify_campaign_bundle(outcome.bundle_path)


@pytest.mark.parametrize(
    "missing_evidence",
    ("attestation", "aggregate", "system_input"),
)
def test_verifier_rejects_self_checksummed_incomplete_evidence(
    tmp_path,
    missing_evidence,
):
    config, _manifest_paths = _campaign_fixture(tmp_path)
    outcome = run_campaign(
        config,
        environment={"CAMPAIGN_TEST_TOKEN": SECRET_VALUE},
        runner_factory=_successful_runner_factory([]),
        lab_controller=RecordingLab(),
        clock=lambda: 100.0,
    )
    if missing_evidence == "attestation":
        path = next((outcome.bundle_path / "attestations").glob("*.json"))
    elif missing_evidence == "aggregate":
        path = (
            outcome.bundle_path
            / "aggregates"
            / "alpha"
            / "service-discovery-verification.json"
        )
    else:
        path = outcome.bundle_path / "inputs" / "systems" / "alpha.json"
    path.unlink()
    _rewrite_checksums(outcome.bundle_path)

    with pytest.raises(
        CampaignPublicationError,
        match="publication_semantic_incomplete",
    ):
        verify_campaign_bundle(outcome.bundle_path)


@pytest.mark.parametrize(
    "tamper",
    (
        "system_metadata",
        "scenario_metadata",
        "summary",
        "run_metric",
        "run_error_class",
        "run_timing_nonfinite",
        "run_timing_negative",
        "run_timing_order",
        "run_timing_duration",
        "metric_statistics",
        "aggregate_id",
        "matrix_id",
        "provenance_digest",
        "provenance_environment_digest",
        "repetitions",
        "policy_counts",
    ),
)
def test_verifier_rejects_rechecksummed_semantic_tampering(tmp_path, tamper):
    config, _manifest_paths = _campaign_fixture(tmp_path)
    outcome = run_campaign(
        config,
        environment={"CAMPAIGN_TEST_TOKEN": SECRET_VALUE},
        runner_factory=_successful_runner_factory([]),
        lab_controller=RecordingLab(),
        clock=lambda: 100.0,
    )
    aggregate_path = (
        outcome.bundle_path
        / "aggregates"
        / "alpha"
        / "service-discovery-verification.json"
    )
    if tamper in {
        "system_metadata",
        "scenario_metadata",
        "summary",
        "matrix_id",
    }:
        path = outcome.bundle_path / "comparison.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        if tamper == "system_metadata":
            payload["systems"][0]["name"] = "tampered-system-name"
        elif tamper == "scenario_metadata":
            payload["scenarios"][0]["lab_version"] = "tampered-lab-version"
        elif tamper == "summary":
            payload["summaries"][0]["duration_median_seconds"] += 1.0
        else:
            payload["matrix_id"] = "competitor-matrix://sha256/" + "0" * 64
    elif tamper in {
        "run_metric",
        "run_error_class",
        "run_timing_nonfinite",
        "run_timing_negative",
        "run_timing_order",
        "run_timing_duration",
        "metric_statistics",
        "aggregate_id",
    }:
        path = aggregate_path
        payload = json.loads(path.read_text(encoding="utf-8"))
        if tamper == "run_metric":
            payload["runs"][0]["metrics"]["finding_recall"] = 0.125
        elif tamper == "run_error_class":
            payload["runs"][0]["error_class"] = "/home/private/error"
        elif tamper == "run_timing_nonfinite":
            payload["runs"][0]["started_at"] = float("inf")
        elif tamper == "run_timing_negative":
            payload["runs"][0]["started_at"] = -1.0
        elif tamper == "run_timing_order":
            payload["runs"][0]["started_at"] = 101.0
            payload["runs"][0]["finished_at"] = 100.0
        elif tamper == "run_timing_duration":
            payload["runs"][0]["duration_seconds"] = 300.0
            payload["runs"][0]["started_at"] = 100.0
            payload["runs"][0]["finished_at"] = 100.0003
        elif tamper == "metric_statistics":
            payload["metric_statistics"]["finding_recall"]["median"] = 0.125
        else:
            payload["aggregate_id"] = "benchmark-aggregate://sha256/" + "0" * 64
    elif tamper in {"provenance_digest", "provenance_environment_digest"}:
        path = outcome.bundle_path / "provenance.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        if tamper == "provenance_digest":
            payload["input_sha256"]["campaign"] = "0" * 64
        else:
            payload["input_sha256"]["non_secret_environment"] = {
                "HOME": hashlib.sha256(b"/home/user").hexdigest(),
            }
    elif tamper == "repetitions":
        path = outcome.bundle_path / "inputs" / "campaign.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["repetitions"] += 1
    else:
        path = outcome.bundle_path / "campaign-status.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["policy_violations"] += 1
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _rewrite_checksums(outcome.bundle_path)

    with pytest.raises(
        CampaignPublicationError,
        match="publication_semantic_invalid",
    ):
        verify_campaign_bundle(outcome.bundle_path)


def test_verifier_rejects_unreported_expected_finding_without_coverage_gap(
    tmp_path,
):
    config, _manifest_paths = _campaign_fixture(tmp_path)
    outcome = run_campaign(
        config,
        environment={"CAMPAIGN_TEST_TOKEN": SECRET_VALUE},
        runner_factory=_successful_runner_factory([]),
        lab_controller=RecordingLab(),
        clock=lambda: 100.0,
    )
    aggregate_path = (
        outcome.bundle_path
        / "aggregates"
        / "alpha"
        / "service-discovery-verification.json"
    )
    payload = json.loads(aggregate_path.read_text(encoding="utf-8"))
    payload["runs"][0]["result_summary"]["reported_findings"] = ["ssh_service"]
    assert payload["runs"][0]["result_summary"]["coverage_gaps"] == []
    aggregate_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _rewrite_checksums(outcome.bundle_path)

    with pytest.raises(
        CampaignPublicationError,
        match="publication_semantic_invalid",
    ):
        verify_campaign_bundle(outcome.bundle_path)


def _rewrite_checksums(root: Path) -> None:
    checksum_file = root / "SHA256SUMS"
    paths = sorted(
        path for path in root.rglob("*") if path.is_file() and path != checksum_file
    )
    checksum_file.write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
            f"{path.relative_to(root).as_posix()}\n"
            for path in paths
        ),
        encoding="utf-8",
    )
