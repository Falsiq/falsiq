from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from falsiq.agent_runtime import AgentRequest, AgentResponse, AgentTranscript, write_transcript

FIXTURE_AGENT = Path(__file__).parent / "fixtures" / "fake_agent.py"


def encoded_request() -> str:
    return (
        json.dumps(
            {
                "role": "reviewer.boundary",
                "request_id": "request-1",
                "payload": {"case_id": "case-1"},
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def runtime_command(*args: str) -> list[str]:
    return [sys.executable, "-m", "falsiq.agent_runtime", *args]


def write_allowlist(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "task_ids": [],
                "case_ids": ["case-1"],
                "models": {"reviewer.boundary": "provider/model-2026-07-15"},
            }
        ),
        encoding="utf-8",
    )


def test_run_defaults_to_replay_and_captures_a_fresh_transcript(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture.json"
    captured = tmp_path / "captured.json"
    write_transcript(
        fixture,
        AgentTranscript(
            request=AgentRequest.model_validate_json(encoded_request()),
            response=AgentResponse(request_id="request-1", response={"choice": "A"}),
        ),
    )

    result = subprocess.run(
        runtime_command(
            "run",
            "--replay",
            str(fixture),
            "--transcript",
            str(captured),
        ),
        input=encoded_request(),
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout == '{"request_id":"request-1","response":{"choice":"A"}}\n'
    assert result.stderr == ""
    assert captured.read_bytes() == fixture.read_bytes()


def test_run_requires_explicit_live_mode_before_executing_an_arbitrary_command(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "executed"

    result = subprocess.run(
        runtime_command(
            "run",
            "--transcript",
            str(tmp_path / "captured.json"),
            "--",
            sys.executable,
            "-c",
            f"from pathlib import Path; Path({str(marker)!r}).touch()",
        ),
        input=encoded_request(),
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "--replay or --live" in result.stderr
    assert not marker.exists()


def test_live_run_is_blocked_in_ci_before_the_agent_process_starts(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    allowlist = tmp_path / "allowlist.json"
    write_allowlist(allowlist)
    environment = os.environ.copy()
    environment["CI"] = "true"

    result = subprocess.run(
        runtime_command(
            "run",
            "--live",
            "--allowlist",
            str(allowlist),
            "--case-id",
            "case-1",
            "--model-id",
            "provider/model-2026-07-15",
            "--transcript",
            str(tmp_path / "captured.json"),
            "--",
            sys.executable,
            "-c",
            f"from pathlib import Path; Path({str(marker)!r}).touch()",
        ),
        input=encoded_request(),
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "CI" in result.stderr
    assert not marker.exists()


def test_authorized_live_run_uses_argv_and_passes_the_allowlisted_model_in_env(
    tmp_path: Path,
) -> None:
    allowlist = tmp_path / "allowlist.json"
    transcript = tmp_path / "captured.json"
    write_allowlist(allowlist)
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE"}
    }

    result = subprocess.run(
        runtime_command(
            "run",
            "--live",
            "--allowlist",
            str(allowlist),
            "--case-id",
            "case-1",
            "--model-id",
            "provider/model-2026-07-15",
            "--transcript",
            str(transcript),
            "--",
            sys.executable,
            str(FIXTURE_AGENT),
            "environment",
        ),
        input=encoded_request(),
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )

    assert result.returncode == 0
    assert result.stdout == (
        '{"request_id":"request-1","response":{"model_id":"provider/model-2026-07-15"}}\n'
    )
    assert result.stderr == ""
    assert transcript.exists()


def test_cli_does_not_echo_failed_agent_logs_or_credentials(tmp_path: Path) -> None:
    allowlist = tmp_path / "allowlist.json"
    write_allowlist(allowlist)
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE"}
    }

    result = subprocess.run(
        runtime_command(
            "run",
            "--live",
            "--allowlist",
            str(allowlist),
            "--case-id",
            "case-1",
            "--model-id",
            "provider/model-2026-07-15",
            "--transcript",
            str(tmp_path / "captured.json"),
            "--",
            sys.executable,
            str(FIXTURE_AGENT),
            "fail-with-secret",
        ),
        input=encoded_request(),
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "exit status 9" in result.stderr
    assert "stdout-super-secret" not in result.stderr
    assert "stderr-super-secret" not in result.stderr
    assert not (tmp_path / "captured.json").exists()
