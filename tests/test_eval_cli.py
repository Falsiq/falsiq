from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import falsiq.evaluation as evaluation_module
from falsiq.benchmark import EvalTask, canonical_task_hash
from falsiq.corpus import HoldoutEntry, HoldoutManifest

RUNNER = Path(__file__).parents[1] / "eval" / "run.py"


def _holdout_task() -> EvalTask:
    return EvalTask.model_validate(
        {
            "schema_version": 1,
            "task_id": "synthetic_01",
            "stratum": "synthetic",
            "vague_prompt": "implement the private behavior",
            "context": {"repo_fixture": "fixtures/synthetic_01"},
            "latent_requirements": [
                {
                    "id": "LR1",
                    "text": "private behavior",
                    "discriminator": "private probe",
                    "severity": "rework",
                }
            ],
            "annoyance_budget": 2,
            "human_curated": True,
        }
    )


def _write_holdout_inputs(
    tmp_path: Path,
    *,
    task_salt: bytes = b"private salt",
    secret_salt: bytes | None = None,
) -> tuple[EvalTask, Path, Path, Path, Path]:
    task = _holdout_task()
    entries = [
        HoldoutEntry(
            task_id=task.task_id,
            stratum="synthetic",
            salted_hash=canonical_task_hash(task, salt=task_salt),
        ),
        HoldoutEntry(task_id="synthetic_02", stratum="synthetic", salted_hash="0" * 64),
        HoldoutEntry(task_id="synthetic_03", stratum="synthetic", salted_hash="1" * 64),
        *(
            HoldoutEntry(
                task_id=f"mined_0{i}",
                stratum="mined",
                salted_hash=f"{i + 1:x}" * 64,
            )
            for i in range(1, 4)
        ),
        *(
            HoldoutEntry(
                task_id=f"control_0{i}",
                stratum="control",
                salted_hash=f"{i + 4:x}" * 64,
            )
            for i in range(1, 5)
        ),
    ]
    manifest = HoldoutManifest(
        corpus_version="v0-approved-1",
        seed_digest=hashlib.sha256(b"seed").hexdigest(),
        split_policy={"synthetic": 3, "mined": 3, "control": 4},
        tasks=entries,
    )
    manifest_path = tmp_path / "public" / "holdout-manifest.json"
    manifest_path.parent.mkdir()
    manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    task_store = tmp_path / "owner-private" / "corpus-v0-holdout" / "tasks"
    task_store.mkdir(parents=True)
    (task_store / f"{task.task_id}.json").write_text(
        task.model_dump_json(indent=2), encoding="utf-8"
    )
    salt_file = tmp_path / "owner-private" / "salt"
    salt_file.write_bytes(task_salt if secret_salt is None else secret_salt)
    os.chmod(salt_file, 0o600)
    access_log = tmp_path / "owner-private" / "access.jsonl"
    return task, manifest_path, task_store, salt_file, access_log


def _holdout_arguments(
    tmp_path: Path,
    *,
    task_id: str,
    manifest: Path,
    task_store: Path,
    salt_file: Path,
    access_log: Path,
) -> list[str]:
    return [
        "--holdout-task-id",
        task_id,
        "--holdout-manifest",
        str(manifest),
        "--private-task-store",
        str(task_store),
        "--holdout-salt-file",
        str(salt_file),
        "--holdout-access-log",
        str(access_log),
        "--holdout-actor",
        "official-runner",
        "--holdout-purpose",
        "official heldout scoring",
        "--recordings",
        str(tmp_path / "recordings"),
        "--private-run-dir",
        str(tmp_path / "private-run"),
        "--reports",
        str(tmp_path / "reports"),
    ]


def test_eval_runner_help_describes_replay_only_inputs() -> None:
    result = subprocess.run(
        [sys.executable, str(RUNNER), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "--recordings" in result.stdout
    assert "--private-run-dir" in result.stdout
    assert "--resume" in result.stdout
    assert "--holdout-task-id" in result.stdout
    assert "--holdout-manifest" in result.stdout
    assert "development-only" in result.stdout
    assert "--live" not in result.stdout
    assert result.stderr == ""


def test_eval_runner_rejects_bad_task_without_echoing_hidden_input(tmp_path: Path) -> None:
    task = tmp_path / "bad.json"
    task.write_text('{"secret":"must-not-appear"}', encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--task",
            str(task),
            "--recordings",
            str(tmp_path / "recordings"),
            "--private-run-dir",
            str(tmp_path / "private"),
            "--reports",
            str(tmp_path / "reports"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "error: evaluation task input is invalid\n"
    assert "must-not-appear" not in result.stderr


def test_heldout_mode_loads_verified_task_and_logs_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    task, manifest, task_store, salt_file, access_log = _write_holdout_inputs(tmp_path)
    observed: list[EvalTask] = []

    def capture_run(tasks, *, runtime):
        observed.extend(tasks)
        return object()

    monkeypatch.setattr(evaluation_module, "run_evaluation", capture_run)
    monkeypatch.setattr(
        evaluation_module,
        "write_reports",
        lambda report, directory: {"json": Path(directory) / "evaluation.json"},
    )

    result = evaluation_module.main(
        _holdout_arguments(
            tmp_path,
            task_id=task.task_id,
            manifest=manifest,
            task_store=task_store,
            salt_file=salt_file,
            access_log=access_log,
        )
    )

    assert result == 0
    assert observed == [task]
    event = json.loads(access_log.read_text(encoding="utf-8"))
    assert event == {
        "actor": "official-runner",
        "corpus_version": "v0-approved-1",
        "purpose": "official heldout scoring",
        "task_id": task.task_id,
        "ts": event["ts"],
    }
    assert event["ts"].endswith("Z")
    assert stat_mode(access_log) == 0o600
    assert "json:" in capsys.readouterr().out


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_heldout_hash_mismatch_is_rejected_after_logged_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    task, manifest, task_store, salt_file, access_log = _write_holdout_inputs(
        tmp_path, secret_salt=b"wrong salt"
    )
    monkeypatch.setattr(
        evaluation_module,
        "run_evaluation",
        lambda *args, **kwargs: pytest.fail("evaluation must not run"),
    )

    result = evaluation_module.main(
        _holdout_arguments(
            tmp_path,
            task_id=task.task_id,
            manifest=manifest,
            task_store=task_store,
            salt_file=salt_file,
            access_log=access_log,
        )
    )

    assert result == 2
    assert len(access_log.read_text(encoding="utf-8").splitlines()) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "hash mismatch" in captured.err
    assert "wrong salt" not in captured.err


def test_unknown_heldout_id_is_rejected_without_logging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, manifest, task_store, salt_file, access_log = _write_holdout_inputs(tmp_path)
    monkeypatch.setattr(
        evaluation_module,
        "run_evaluation",
        lambda *args, **kwargs: pytest.fail("evaluation must not run"),
    )

    result = evaluation_module.main(
        _holdout_arguments(
            tmp_path,
            task_id="synthetic_99",
            manifest=manifest,
            task_store=task_store,
            salt_file=salt_file,
            access_log=access_log,
        )
    )

    assert result == 2
    assert not access_log.exists()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "not in the holdout manifest" in captured.err


def test_heldout_mode_rejects_symlinked_manifest_and_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    task, manifest, task_store, salt_file, access_log = _write_holdout_inputs(tmp_path)
    monkeypatch.setattr(
        evaluation_module,
        "run_evaluation",
        lambda *args, **kwargs: pytest.fail("evaluation must not run"),
    )
    manifest_link = tmp_path / "manifest-link.json"
    manifest_link.symlink_to(manifest)

    manifest_result = evaluation_module.main(
        _holdout_arguments(
            tmp_path,
            task_id=task.task_id,
            manifest=manifest_link,
            task_store=task_store,
            salt_file=salt_file,
            access_log=access_log,
        )
    )

    assert manifest_result == 2
    assert not access_log.exists()
    assert "symbolic link" in capsys.readouterr().err

    store_link = tmp_path / "store-link"
    store_link.symlink_to(task_store, target_is_directory=True)
    store_result = evaluation_module.main(
        _holdout_arguments(
            tmp_path,
            task_id=task.task_id,
            manifest=manifest,
            task_store=store_link,
            salt_file=salt_file,
            access_log=access_log,
        )
    )

    assert store_result == 2
    assert len(access_log.read_text(encoding="utf-8").splitlines()) == 1
    assert "symbolic link" in capsys.readouterr().err

    access_log.unlink()
    actual_log = tmp_path / "actual-access-log"
    actual_log.write_text("untouched\n", encoding="utf-8")
    access_log.symlink_to(actual_log)
    log_result = evaluation_module.main(
        _holdout_arguments(
            tmp_path,
            task_id=task.task_id,
            manifest=manifest,
            task_store=task_store,
            salt_file=salt_file,
            access_log=access_log,
        )
    )

    assert log_result == 2
    assert actual_log.read_text(encoding="utf-8") == "untouched\n"
    assert "regular file" in capsys.readouterr().err

    actual_parent = tmp_path / "actual-log-parent"
    actual_parent.mkdir()
    parent_link = tmp_path / "log-parent-link"
    parent_link.symlink_to(actual_parent, target_is_directory=True)
    parent_result = evaluation_module.main(
        _holdout_arguments(
            tmp_path,
            task_id=task.task_id,
            manifest=manifest,
            task_store=task_store,
            salt_file=salt_file,
            access_log=parent_link / "access.jsonl",
        )
    )

    assert parent_result == 2
    assert not (actual_parent / "access.jsonl").exists()
    assert "symbolic link" in capsys.readouterr().err


@pytest.mark.parametrize(
    "extra",
    [
        [],
        ["--holdout-manifest", "manifest.json"],
    ],
)
def test_cli_rejects_incomplete_or_mixed_task_modes(tmp_path: Path, extra: list[str]) -> None:
    common = [
        "--recordings",
        str(tmp_path / "recordings"),
        "--private-run-dir",
        str(tmp_path / "private"),
        "--reports",
        str(tmp_path / "reports"),
    ]
    if extra:
        source = ["--task", str(tmp_path / "dev.json"), *extra]
        expected = "only with --holdout-task-id"
    else:
        source = ["--holdout-task-id", "synthetic_01"]
        expected = "heldout mode requires"

    result = subprocess.run(
        [sys.executable, str(RUNNER), *source, *common],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert expected in result.stderr


def test_cli_rejects_both_task_source_options(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--task",
            str(tmp_path / "dev.json"),
            "--holdout-task-id",
            "synthetic_01",
            "--recordings",
            str(tmp_path / "recordings"),
            "--private-run-dir",
            str(tmp_path / "private"),
            "--reports",
            str(tmp_path / "reports"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "not allowed with argument" in result.stderr
