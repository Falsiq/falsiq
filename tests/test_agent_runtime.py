from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

import falsiq.agent_runtime as agent_runtime
from falsiq.agent_runtime import (
    AgentProcessError,
    AgentProtocolError,
    AgentRequest,
    AgentResponse,
    AgentRuntimeError,
    AgentTimeoutError,
    AgentTranscript,
    LiveExecutionDenied,
    authorize_live,
    invoke_agent,
    load_transcript,
    parse_request,
    write_transcript,
)

FIXTURE_AGENT = Path(__file__).parent / "fixtures" / "fake_agent.py"


def request(*, payload: dict[str, object] | None = None) -> AgentRequest:
    return AgentRequest(
        role="reviewer.boundary",
        request_id="request-1",
        payload=payload or {"case_id": "case-1", "round": 1},
    )


def command(mode: str) -> list[str]:
    return [sys.executable, str(FIXTURE_AGENT), mode]


def write_allowlist(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "task_ids": ["task-1"],
                "case_ids": ["case-1"],
                "models": {"reviewer.boundary": "provider/model-2026-07-15"},
            }
        ),
        encoding="utf-8",
    )
    return path


def test_protocol_models_are_strict_and_require_json_values() -> None:
    with pytest.raises(ValidationError):
        AgentRequest(
            role="reviewer.boundary",
            request_id="request-1",
            payload={},
            unrecognized=True,
        )

    with pytest.raises(ValidationError):
        AgentRequest(role="has spaces", request_id="request-1", payload={})

    with pytest.raises(ValidationError):
        AgentResponse(request_id="request-1", response=object())


@pytest.mark.parametrize(
    "document",
    [
        '{"role":"reviewer","role":"selector","request_id":"r1","payload":{}}\n',
        '{"role":"reviewer","request_id":"r1","payload":{"value":NaN}}\n',
        '{"role":"reviewer","request_id":"r1","payload":{},"credential":"secret"}\n',
    ],
)
def test_request_parser_rejects_noncanonical_or_extra_data_without_echoing_it(
    document: str,
) -> None:
    with pytest.raises(AgentProtocolError) as error:
        parse_request(document)

    assert "secret" not in str(error.value)


def test_invoke_agent_round_trips_one_jsonl_request_and_captures_transcript(
    tmp_path: Path,
) -> None:
    transcript_path = tmp_path / "nested" / "transcript.json"

    response = invoke_agent(
        command("echo"),
        request(payload={"unicode": "café", "nested": [True, None, 3]}),
        transcript_path=transcript_path,
    )

    assert response == AgentResponse(
        request_id="request-1",
        response={
            "payload": {"unicode": "café", "nested": [True, None, 3]},
            "role": "reviewer.boundary",
        },
    )
    transcript = load_transcript(transcript_path)
    assert transcript.request.payload == {"unicode": "café", "nested": [True, None, 3]}
    assert transcript.response == response
    assert transcript_path.read_bytes().endswith(b"\n")
    assert stat.S_IMODE(transcript_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(transcript_path.parent.stat().st_mode) == 0o700


def test_transcript_capture_rejects_symlinked_or_public_parent_directories(
    tmp_path: Path,
) -> None:
    transcript = AgentTranscript(
        request=request(),
        response=AgentResponse(request_id="request-1", response={"ok": True}),
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_parent = tmp_path / "linked-private"
    linked_parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises(AgentProtocolError, match="symlink"):
        write_transcript(linked_parent / "capture.json", transcript)

    assert not (outside / "capture.json").exists()
    public_parent = tmp_path / "public"
    public_parent.mkdir(mode=0o755)
    os.chmod(public_parent, 0o755)
    with pytest.raises(AgentProtocolError, match="owner-private"):
        write_transcript(public_parent / "capture.json", transcript)


def test_transcript_capture_and_load_reject_symlinked_targets(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    os.chmod(private, 0o700)
    outside = tmp_path / "outside.json"
    outside.write_text("untouched\n", encoding="utf-8")
    target = private / "capture.json"
    target.symlink_to(outside)
    transcript = AgentTranscript(
        request=request(),
        response=AgentResponse(request_id="request-1", response={"ok": True}),
    )

    with pytest.raises(AgentProtocolError, match="symlink"):
        write_transcript(target, transcript)
    with pytest.raises(AgentProtocolError, match="transcript schema"):
        load_transcript(target)

    assert outside.read_text(encoding="utf-8") == "untouched\n"


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("no-newline", "exactly one JSONL line"),
        ("two-lines", "exactly one JSONL line"),
        ("malformed", "valid JSON"),
        ("invalid-schema", "response schema"),
        ("wrong-id", "request ID"),
    ],
)
def test_invoke_agent_rejects_protocol_violations_without_writing_a_transcript(
    tmp_path: Path, mode: str, message: str
) -> None:
    transcript_path = tmp_path / "transcript.json"

    with pytest.raises(AgentProtocolError, match=message):
        invoke_agent(command(mode), request(), transcript_path=transcript_path)

    assert not transcript_path.exists()


def test_process_failure_does_not_leak_stdout_stderr_or_argv(tmp_path: Path) -> None:
    transcript_path = tmp_path / "transcript.json"
    secret_argv = "argv-super-secret"

    with pytest.raises(AgentProcessError) as error:
        invoke_agent(
            [*command("fail-with-secret"), secret_argv],
            request(),
            transcript_path=transcript_path,
        )

    rendered = str(error.value)
    assert "exit status 9" in rendered
    assert "stdout-super-secret" not in rendered
    assert "stderr-super-secret" not in rendered
    assert secret_argv not in rendered
    assert not transcript_path.exists()


def test_timeout_terminates_agent_without_leaking_or_capturing(tmp_path: Path) -> None:
    transcript_path = tmp_path / "transcript.json"

    with pytest.raises(AgentTimeoutError, match="timed out"):
        invoke_agent(
            command("sleep"),
            request(),
            timeout_seconds=0.05,
            transcript_path=transcript_path,
        )

    assert not transcript_path.exists()


@pytest.mark.parametrize(
    ("mode", "error_type"),
    [
        ("oversized-stdout", AgentProtocolError),
        ("oversized-stderr", AgentProcessError),
    ],
)
def test_output_overflow_kills_agent_without_leaking_or_capturing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    error_type: type[AgentRuntimeError],
) -> None:
    transcript_path = tmp_path / "transcript.json"
    monkeypatch.setattr(agent_runtime, "MAX_AGENT_OUTPUT_BYTES", 512)
    started = time.monotonic()

    with pytest.raises(error_type, match="output limit") as error:
        invoke_agent(
            [*command(mode), "513"],
            request(),
            timeout_seconds=4,
            transcript_path=transcript_path,
        )

    assert time.monotonic() - started < 3
    assert f"{mode}-super-secret" not in str(error.value)
    assert not transcript_path.exists()


def test_response_at_exact_output_limit_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limit = 512
    monkeypatch.setattr(agent_runtime, "MAX_AGENT_OUTPUT_BYTES", limit)

    response = invoke_agent([*command("sized-response"), str(limit)], request())

    assert response.request_id == "request-1"
    assert isinstance(response.response, dict)
    assert len(response.response["padding"]) > 0


def test_command_must_be_an_argv_sequence_not_a_shell_string() -> None:
    with pytest.raises(TypeError, match="argv sequence"):
        invoke_agent("python agent.py", request())


def test_invoke_agent_passes_an_argv_directly_and_writes_one_input_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    real_popen = subprocess.Popen

    class ProcessProxy:
        def __init__(self, process: subprocess.Popen[bytes]) -> None:
            self.process = process

        def communicate(self, *args: object, **kwargs: object) -> tuple[bytes, bytes]:
            observed["input"] = kwargs.get("input")
            return self.process.communicate(*args, **kwargs)

        def __getattr__(self, name: str) -> object:
            return getattr(self.process, name)

    def fake_popen(argv: tuple[str, ...], **kwargs: object) -> ProcessProxy:
        observed["argv"] = argv
        observed.update(kwargs)
        return ProcessProxy(real_popen(argv, **kwargs))

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    argv = [*command("echo"), "argument with spaces", "; touch never-runs"]

    response = invoke_agent(argv, request(), environ={"ONLY_THIS": "environment"})

    assert observed["argv"] == tuple(argv)
    assert observed["shell"] is False
    assert observed["env"] == {"ONLY_THIS": "environment"}
    assert isinstance(observed["input"], bytes)
    assert bytes(observed["input"]).count(b"\n") == 1
    assert response.request_id == "request-1"


def test_process_start_failure_has_a_safe_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_to_start(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        raise OSError("credential=start-super-secret")

    monkeypatch.setattr(subprocess, "Popen", fail_to_start)

    with pytest.raises(AgentProcessError) as error:
        invoke_agent(["missing-agent"], request())

    assert "could not be started" in str(error.value)
    assert "start-super-secret" not in str(error.value)


def test_failed_atomic_replace_preserves_existing_transcript(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "transcript.json"
    target.write_text("original\n", encoding="utf-8")
    transcript = AgentTranscript(
        request=request(),
        response=AgentResponse(request_id="request-1", response={"ok": True}),
    )

    def fail_replace(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(OSError, match="simulated replace failure"):
        write_transcript(target, transcript)

    assert target.read_text(encoding="utf-8") == "original\n"
    assert list(tmp_path.iterdir()) == [target]


def test_transcript_requires_matching_request_and_response_ids(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "request": {
                    "role": "reviewer.boundary",
                    "request_id": "request-1",
                    "payload": {},
                },
                "response": {"request_id": "different", "response": {}},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(AgentProtocolError, match="transcript schema"):
        load_transcript(path)


def test_replay_executable_is_deterministic_and_validates_the_entire_request(
    tmp_path: Path,
) -> None:
    transcript_path = tmp_path / "recording.json"
    transcript = AgentTranscript(
        request=request(),
        response=AgentResponse(request_id="request-1", response={"answer": "A"}),
    )
    write_transcript(transcript_path, transcript)
    encoded_request = (
        json.dumps(
            transcript.request.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        )
        + "\n"
    )
    replay_command = [
        sys.executable,
        "-m",
        "falsiq.agent_runtime",
        "replay",
        str(transcript_path),
    ]

    first = subprocess.run(
        replay_command,
        input=encoded_request,
        capture_output=True,
        text=True,
        check=False,
    )
    second = subprocess.run(
        replay_command,
        input=encoded_request,
        capture_output=True,
        text=True,
        check=False,
    )

    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout == '{"request_id":"request-1","response":{"answer":"A"}}\n'
    assert first.stderr == second.stderr == ""

    mismatched = subprocess.run(
        replay_command,
        input=encoded_request.replace('"round":1', '"round":2'),
        capture_output=True,
        text=True,
        check=False,
    )
    assert mismatched.returncode == 2
    assert mismatched.stdout == ""
    assert "does not match" in mismatched.stderr
    assert "case-1" not in mismatched.stderr


def test_live_authorization_requires_non_ci_allowlisted_subject_and_fixed_model(
    tmp_path: Path,
) -> None:
    allowlist = write_allowlist(tmp_path / "live-allowlist.json")

    authorization = authorize_live(
        request(payload={"task": {"task_id": "task-1"}, "round": 1}),
        allowlist_path=allowlist,
        task_id="task-1",
        model_id="provider/model-2026-07-15",
        environ={},
    )

    assert authorization.subject_kind == "task"
    assert authorization.subject_id == "task-1"
    assert authorization.model_id == "provider/model-2026-07-15"


@pytest.mark.parametrize(
    "payload",
    [
        {"task": {"task_id": "task-denied"}, "round": 1},
        {"task_id": "task-1", "task": {"task_id": "task-denied"}},
        {"round": 1},
    ],
)
def test_live_authorization_binds_allowlisted_subject_to_request_payload(
    tmp_path: Path,
    payload: dict[str, object],
) -> None:
    allowlist = write_allowlist(tmp_path / "live-allowlist.json")

    with pytest.raises(LiveExecutionDenied, match="request payload"):
        authorize_live(
            request(payload=payload),
            allowlist_path=allowlist,
            task_id="task-1",
            model_id="provider/model-2026-07-15",
            environ={},
        )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({}, "exactly one task or case ID"),
        ({"task_id": "task-1", "case_id": "case-1"}, "exactly one task or case ID"),
        ({"task_id": "task-denied"}, "not allowlisted"),
        ({"case_id": "case-denied"}, "not allowlisted"),
        ({"task_id": "task-1", "model_id": "provider/model-latest"}, "fixed model"),
    ],
)
def test_live_authorization_is_fail_closed(
    tmp_path: Path, kwargs: dict[str, str], message: str
) -> None:
    allowlist = write_allowlist(tmp_path / "live-allowlist.json")
    parameters = {
        "allowlist_path": allowlist,
        "model_id": "provider/model-2026-07-15",
        "environ": {},
        **kwargs,
    }

    with pytest.raises(LiveExecutionDenied, match=message):
        authorize_live(request(), **parameters)


@pytest.mark.parametrize("ci_name", ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE"])
def test_live_authorization_rejects_ci_environments(tmp_path: Path, ci_name: str) -> None:
    allowlist = write_allowlist(tmp_path / "live-allowlist.json")

    with pytest.raises(LiveExecutionDenied, match="CI"):
        authorize_live(
            request(),
            allowlist_path=allowlist,
            task_id="task-1",
            model_id="provider/model-2026-07-15",
            environ={ci_name: "true"},
        )


def test_live_authorization_rejects_symlinked_and_malformed_allowlists(tmp_path: Path) -> None:
    real = write_allowlist(tmp_path / "real.json")
    symlink = tmp_path / "link.json"
    symlink.symlink_to(real)

    with pytest.raises(LiveExecutionDenied, match="regular local file"):
        authorize_live(
            request(),
            allowlist_path=symlink,
            task_id="task-1",
            model_id="provider/model-2026-07-15",
            environ={},
        )

    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"credential":"allowlist-super-secret"}', encoding="utf-8")
    with pytest.raises(LiveExecutionDenied) as error:
        authorize_live(
            request(),
            allowlist_path=malformed,
            task_id="task-1",
            model_id="provider/model-2026-07-15",
            environ={},
        )
    assert "allowlist-super-secret" not in str(error.value)


@pytest.mark.parametrize(
    "change",
    [
        {"task_ids": ["task-1", "task-1"]},
        {"case_ids": ["case-1", "case-1"]},
        {"models": {"reviewer.boundary": "provider/model-latest"}},
    ],
)
def test_live_allowlist_rejects_ambiguous_approval_data(
    tmp_path: Path, change: dict[str, object]
) -> None:
    contents: dict[str, object] = {
        "schema_version": 1,
        "task_ids": ["task-1"],
        "case_ids": ["case-1"],
        "models": {"reviewer.boundary": "provider/model-2026-07-15"},
        **change,
    }
    allowlist = tmp_path / "allowlist.json"
    allowlist.write_text(json.dumps(contents), encoding="utf-8")

    with pytest.raises(LiveExecutionDenied, match="missing or invalid"):
        authorize_live(
            request(),
            allowlist_path=allowlist,
            task_id="task-1",
            model_id="provider/model-2026-07-15",
            environ={},
        )
