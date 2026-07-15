from __future__ import annotations

import subprocess
import sys
from pathlib import Path

RUNNER = Path(__file__).parents[1] / "eval" / "run.py"


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
