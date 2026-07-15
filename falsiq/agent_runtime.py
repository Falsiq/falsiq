"""Provider-neutral executable-agent runtime with deterministic replay.

This module is deliberately separate from :mod:`falsiq.cli`.  The Falsiq CLI
never starts a model.  Orchestrators and the evaluation harness may use this
executable at their boundary to either replay an approved transcript or, after
explicit authorization, run a live executable agent.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Thread
from typing import Annotated, Any, BinaryIO, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    ValidationError,
    model_validator,
)

PROTOCOL_SCHEMA_VERSION = 1
DEFAULT_TIMEOUT_SECONDS = 120.0
MAX_ALLOWLIST_BYTES = 64 * 1024
# Each protocol stream is accepted only up to 8 MiB. Disk-backed capture keeps
# a misbehaving process from making the orchestrator buffer unbounded output in
# memory while still leaving room for substantial structured builder responses.
MAX_AGENT_OUTPUT_BYTES = 8 * 1024 * 1024
_OUTPUT_MONITOR_INTERVAL_SECONDS = 0.005

Identifier = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$",
    ),
]
ModelIdentifier = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$",
    ),
]

_CI_VARIABLES = (
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "BUILDKITE",
    "TF_BUILD",
    "CIRCLECI",
    "JENKINS_URL",
)
_FALSE_ENV_VALUES = frozenset({"", "0", "false", "no", "off"})
_UNFIXED_MODEL_MARKERS = re.compile(
    r"(?:^|[._:/@+-])(latest|default|stable|head)(?:$|[._:/@+-])",
    re.I,
)


class AgentRuntimeError(RuntimeError):
    """Base class for errors safe to render without agent output."""


class AgentProtocolError(AgentRuntimeError):
    """The executable did not follow the one-line JSONL protocol."""


class AgentProcessError(AgentRuntimeError):
    """The executable could not start or exited unsuccessfully."""


class AgentTimeoutError(AgentRuntimeError):
    """The executable exceeded its configured deadline."""


class LiveExecutionDenied(AgentRuntimeError):
    """A live execution gate was not satisfied."""


class RuntimeConfigurationError(AgentRuntimeError):
    """The runtime command line selected an unsafe or incomplete mode."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class AgentRequest(_StrictModel):
    """The single JSON object written to a fresh agent process."""

    role: Identifier
    request_id: Identifier
    payload: dict[str, JsonValue]


class AgentResponse(_StrictModel):
    """The single JSON object an agent process must return."""

    request_id: Identifier
    response: JsonValue


class AgentTranscript(_StrictModel):
    """Replayable, provider-neutral protocol data.

    Command arguments, environment variables, and process logs are
    intentionally absent so credentials and provider diagnostics cannot leak
    into checked-in replay fixtures.
    """

    schema_version: Literal[PROTOCOL_SCHEMA_VERSION] = PROTOCOL_SCHEMA_VERSION
    request: AgentRequest
    response: AgentResponse

    @model_validator(mode="after")
    def request_ids_match(self) -> AgentTranscript:
        if self.request.request_id != self.response.request_id:
            raise ValueError("request and response IDs must match")
        return self


class LiveAllowlist(_StrictModel):
    """Local approval data for live executable-agent calls."""

    schema_version: Literal[PROTOCOL_SCHEMA_VERSION]
    task_ids: list[Identifier] = Field(default_factory=list)
    case_ids: list[Identifier] = Field(default_factory=list)
    models: dict[Identifier, ModelIdentifier]

    @model_validator(mode="after")
    def entries_are_unique_and_fixed(self) -> LiveAllowlist:
        if len(self.task_ids) != len(set(self.task_ids)):
            raise ValueError("task IDs must be unique")
        if len(self.case_ids) != len(set(self.case_ids)):
            raise ValueError("case IDs must be unique")
        if any(not _is_fixed_model_id(model_id) for model_id in self.models.values()):
            raise ValueError("model aliases are not fixed identifiers")
        return self


@dataclass(frozen=True)
class LiveAuthorization:
    subject_kind: Literal["task", "case"]
    subject_id: str
    model_id: str


def _is_fixed_model_id(model_id: str) -> bool:
    return "*" not in model_id and _UNFIXED_MODEL_MARKERS.search(model_id) is None


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-standard JSON constant: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _load_json(document: str) -> JsonValue:
    return json.loads(
        document,
        parse_constant=_reject_json_constant,
        object_pairs_hook=_reject_duplicate_keys,
    )


def _json_line(model: BaseModel) -> str:
    return (
        json.dumps(
            model.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def _parse_single_line(document: str, *, source: Literal["request", "response"]) -> JsonValue:
    if not document.endswith("\n") or document.count("\n") != 1:
        raise AgentProtocolError(f"agent {source} must contain exactly one JSONL line")
    try:
        return _load_json(document[:-1])
    except (json.JSONDecodeError, ValueError, TypeError):
        raise AgentProtocolError(f"agent {source} must contain valid JSON") from None


def parse_request(document: str) -> AgentRequest:
    """Parse one strict protocol request without exposing invalid input."""

    value = _parse_single_line(document, source="request")
    try:
        return AgentRequest.model_validate(value)
    except ValidationError:
        raise AgentProtocolError("agent request does not match the request schema") from None


def parse_response(document: str) -> AgentResponse:
    """Parse one strict protocol response without exposing invalid output."""

    value = _parse_single_line(document, source="response")
    try:
        return AgentResponse.model_validate(value)
    except ValidationError:
        raise AgentProtocolError("agent output does not match the response schema") from None


def _normalize_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)):
        raise TypeError("agent command must be an argv sequence, not a shell string")
    try:
        normalized = tuple(argv)
    except TypeError:
        raise TypeError("agent command must be an argv sequence") from None
    if not normalized or any(not isinstance(item, str) or not item for item in normalized):
        raise TypeError("agent command must be a non-empty argv sequence of non-empty strings")
    if any("\x00" in item for item in normalized):
        raise TypeError("agent command arguments cannot contain null bytes")
    return normalized


def _validate_timeout(timeout_seconds: float) -> float:
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise TypeError("agent timeout must be a positive number")
    normalized = float(timeout_seconds)
    if normalized <= 0 or not math.isfinite(normalized):
        raise ValueError("agent timeout must be a positive finite number")
    return normalized


@dataclass(frozen=True)
class _CompletedAgentProcess:
    returncode: int
    stdout: bytes


def _kill_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    # The process may exit between poll() and kill().
    with suppress(OSError):
        process.kill()


def _finish_aborted_process(process: subprocess.Popen[bytes]) -> None:
    """Kill and wait without ever reading provider output into an exception."""

    _kill_process(process)
    try:
        process.communicate()
    except (OSError, ValueError):
        with suppress(OSError):
            process.wait()


def _monitor_output_sizes(
    process: subprocess.Popen[bytes],
    stdout_file: BinaryIO,
    stderr_file: BinaryIO,
    *,
    output_limit: int,
    stopped: Event,
    overflows: set[str],
) -> None:
    """Kill a child whose disk-backed stdout or stderr exceeds the limit."""

    streams = (("stdout", stdout_file), ("stderr", stderr_file))
    while not stopped.wait(_OUTPUT_MONITOR_INTERVAL_SECONDS):
        for name, stream in streams:
            try:
                size = os.fstat(stream.fileno()).st_size
            except OSError:
                continue
            if size > output_limit:
                overflows.add(name)
        if overflows:
            _kill_process(process)
            return


def _run_bounded_agent_process(
    command: tuple[str, ...],
    request_bytes: bytes,
    *,
    timeout: float,
    environ: dict[str, str] | None,
    output_limit: int,
) -> _CompletedAgentProcess:
    """Run one child with bounded, deadlock-free, disk-backed output capture."""

    with (
        tempfile.TemporaryFile(mode="w+b") as stdout_file,
        tempfile.TemporaryFile(mode="w+b") as stderr_file,
    ):
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=stdout_file,
                stderr=stderr_file,
                shell=False,
                env=environ,
            )
        except OSError:
            raise AgentProcessError("agent process could not be started") from None

        stopped = Event()
        overflows: set[str] = set()
        monitor = Thread(
            target=_monitor_output_sizes,
            args=(process, stdout_file, stderr_file),
            kwargs={
                "output_limit": output_limit,
                "stopped": stopped,
                "overflows": overflows,
            },
            name="falsiq-agent-output-monitor",
            daemon=True,
        )
        monitor.start()
        timed_out = False
        execution_failed = False
        try:
            try:
                process.communicate(input=request_bytes, timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                _finish_aborted_process(process)
            except OSError:
                execution_failed = True
                _finish_aborted_process(process)
        finally:
            stopped.set()
            monitor.join()

        if timed_out:
            raise AgentTimeoutError("agent process timed out")

        final_sizes = {
            "stdout": os.fstat(stdout_file.fileno()).st_size,
            "stderr": os.fstat(stderr_file.fileno()).st_size,
        }
        overflows.update(name for name, size in final_sizes.items() if size > output_limit)
        if "stdout" in overflows:
            raise AgentProtocolError("agent stdout exceeded the output limit")
        if "stderr" in overflows:
            raise AgentProcessError("agent stderr exceeded the output limit")
        if execution_failed:
            raise AgentProcessError("agent process failed during execution")
        if process.returncode is None:
            _finish_aborted_process(process)
            raise AgentProcessError("agent process did not terminate cleanly")
        if process.returncode != 0:
            raise AgentProcessError(f"agent process failed with exit status {process.returncode}")

        stdout_file.seek(0)
        stdout = stdout_file.read(output_limit + 1)
        if len(stdout) > output_limit:
            raise AgentProtocolError("agent stdout exceeded the output limit")
        return _CompletedAgentProcess(returncode=process.returncode, stdout=stdout)


def invoke_agent(
    argv: Sequence[str],
    request: AgentRequest,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    transcript_path: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> AgentResponse:
    """Invoke one fresh executable for one request.

    ``argv`` is passed directly to :class:`subprocess.Popen` with ``shell=False``.
    Stdout and stderr use bounded disk-backed capture and are never included in
    exceptions or transcripts.
    """

    command = _normalize_argv(argv)
    timeout = _validate_timeout(timeout_seconds)
    child_environment = None if environ is None else dict(environ)

    completed = _run_bounded_agent_process(
        command,
        _json_line(request).encode("utf-8"),
        timeout=timeout,
        environ=child_environment,
        output_limit=MAX_AGENT_OUTPUT_BYTES,
    )
    try:
        stdout = completed.stdout.decode("utf-8")
    except UnicodeDecodeError:
        raise AgentProtocolError("agent output must contain valid UTF-8") from None
    response = parse_response(stdout)
    if response.request_id != request.request_id:
        raise AgentProtocolError("agent response request ID does not match the request ID")

    if transcript_path is not None:
        write_transcript(
            transcript_path,
            AgentTranscript(request=request, response=response),
        )
    return response


def write_transcript(
    path: str | os.PathLike[str],
    transcript: AgentTranscript,
) -> None:
    """Atomically replace ``path`` with a private replay transcript."""

    target = Path(os.path.abspath(os.fspath(path)))
    parent = prepare_private_directory(target.parent)
    try:
        target_metadata = target.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise AgentProtocolError("private transcript target is unavailable") from exc
    else:
        if stat.S_ISLNK(target_metadata.st_mode):
            raise AgentProtocolError("private transcript target must not be a symlink")
        if not stat.S_ISREG(target_metadata.st_mode):
            raise AgentProtocolError("private transcript target must be a regular file")

    parent_metadata = parent.lstat()
    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        opened_parent = parent.lstat()
        if (parent_metadata.st_dev, parent_metadata.st_ino) != (
            opened_parent.st_dev,
            opened_parent.st_ino,
        ):
            raise AgentProtocolError("private transcript directory changed during capture")
        os.chmod(temporary, 0o600)
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as stream:
            file_descriptor = -1
            stream.write(_json_line(transcript))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        _fsync_directory(target.parent)
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        temporary.unlink(missing_ok=True)


def prepare_private_directory(path: str | os.PathLike[str]) -> Path:
    """Create or validate a real owner-private directory without symlink traversal."""

    target = Path(os.path.abspath(os.fspath(path)))
    if target == Path(target.anchor):
        raise AgentProtocolError("private transcript directory cannot be a filesystem root")
    current = Path(target.anchor)
    parts = target.parts[1:] if target.anchor else target.parts
    for component in parts:
        current /= component
        created = False
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            try:
                os.mkdir(current, 0o700)
                created = True
            except FileExistsError:
                pass
            except OSError as exc:
                raise AgentProtocolError(
                    "private transcript directory could not be created"
                ) from exc
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise AgentProtocolError(
                    "private transcript directory could not be inspected"
                ) from exc
        except OSError as exc:
            raise AgentProtocolError(
                "private transcript directory could not be inspected"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise AgentProtocolError("private transcript directory must not contain a symlink")
        if not stat.S_ISDIR(metadata.st_mode):
            raise AgentProtocolError("private transcript path must contain only directories")
        if created:
            try:
                os.chmod(current, 0o700)
            except OSError as exc:
                raise AgentProtocolError(
                    "private transcript directory permissions could not be set"
                ) from exc

    metadata = target.lstat()
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AgentProtocolError("private transcript directory must be owner-private (mode 0700)")
    return target


def _fsync_directory(path: Path) -> None:
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if directory_flag is None:
        return
    descriptor = os.open(path, os.O_RDONLY | directory_flag)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load_transcript(path: str | os.PathLike[str]) -> AgentTranscript:
    """Load and strictly validate a replay transcript."""

    try:
        transcript_path = Path(path)
        metadata = transcript_path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise OSError("transcript must be a regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(transcript_path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (
                metadata.st_dev,
                metadata.st_ino,
            ) != (opened.st_dev, opened.st_ino):
                raise OSError("transcript changed while opening")
            with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                descriptor = -1
                document = stream.read()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        value = _load_json(document)
        return AgentTranscript.model_validate(value)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError, ValidationError):
        raise AgentProtocolError("recording does not match the transcript schema") from None


def replay_response(request: AgentRequest, transcript: AgentTranscript) -> AgentResponse:
    """Return a recorded response only for the exact recorded request."""

    if request != transcript.request:
        raise AgentProtocolError("replay request does not match the recorded request")
    return transcript.response


def _is_ci_environment(environ: Mapping[str, str]) -> bool:
    return any(
        name in environ and environ[name].strip().lower() not in _FALSE_ENV_VALUES
        for name in _CI_VARIABLES
    )


def _request_subject_ids(request: AgentRequest, subject_kind: str) -> set[str]:
    """Collect every explicitly named subject ID from a JSON request payload."""

    field = f"{subject_kind}_id"
    found: set[str] = set()
    pending: list[JsonValue] = [request.payload]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if field in value:
                subject_id = value[field]
                if not isinstance(subject_id, str):
                    raise LiveExecutionDenied(
                        "live request payload has an invalid subject ID"
                    )
                found.add(subject_id)
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return found


def _require_request_subject(
    request: AgentRequest,
    *,
    subject_kind: Literal["task", "case"],
    subject_id: str,
) -> None:
    if _request_subject_ids(request, subject_kind) != {subject_id}:
        raise LiveExecutionDenied(
            "live request payload must identify only the allowlisted subject"
        )


def _load_allowlist(path: str | os.PathLike[str]) -> LiveAllowlist:
    allowlist_path = Path(path)
    try:
        metadata = allowlist_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or allowlist_path.is_symlink():
            raise LiveExecutionDenied("live allowlist must be a regular local file")
        if metadata.st_size > MAX_ALLOWLIST_BYTES:
            raise LiveExecutionDenied("live allowlist is too large")
        document = allowlist_path.read_text(encoding="utf-8")
        return LiveAllowlist.model_validate(_load_json(document))
    except LiveExecutionDenied:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError, ValidationError):
        raise LiveExecutionDenied("live allowlist is missing or invalid") from None


def authorize_live(
    request: AgentRequest,
    *,
    allowlist_path: str | os.PathLike[str],
    model_id: str,
    task_id: str | None = None,
    case_id: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> LiveAuthorization:
    """Validate every live opt-in gate before an executable can start."""

    process_environment = os.environ if environ is None else environ
    if _is_ci_environment(process_environment):
        raise LiveExecutionDenied("live agent execution is disabled in CI")
    if (task_id is None) == (case_id is None):
        raise LiveExecutionDenied("live execution requires exactly one task or case ID")

    allowlist = _load_allowlist(allowlist_path)
    expected_model = allowlist.models.get(request.role)
    if (
        expected_model is None
        or model_id != expected_model
        or not _is_fixed_model_id(model_id)
    ):
        raise LiveExecutionDenied(
            "live execution requires the fixed model authorized for this role"
        )

    if task_id is not None:
        if task_id not in allowlist.task_ids:
            raise LiveExecutionDenied("task ID is not allowlisted for live execution")
        _require_request_subject(
            request,
            subject_kind="task",
            subject_id=task_id,
        )
        return LiveAuthorization(subject_kind="task", subject_id=task_id, model_id=model_id)

    assert case_id is not None
    if case_id not in allowlist.case_ids:
        raise LiveExecutionDenied("case ID is not allowlisted for live execution")
    _require_request_subject(
        request,
        subject_kind="case",
        subject_id=case_id,
    )
    return LiveAuthorization(subject_kind="case", subject_id=case_id, model_id=model_id)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="falsiq-agent")
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    replay_parser = subparsers.add_parser(
        "replay",
        help="serve one recorded response over the executable-agent protocol",
    )
    replay_parser.add_argument("transcript", type=Path)

    run_parser = subparsers.add_parser(
        "run",
        help="run one replay or explicitly authorized live agent request",
    )
    mode = run_parser.add_mutually_exclusive_group()
    mode.add_argument("--replay", type=Path, metavar="TRANSCRIPT")
    mode.add_argument("--live", action="store_true")
    run_parser.add_argument("--transcript", type=Path, required=True, metavar="PATH")
    run_parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    run_parser.add_argument("--allowlist", type=Path)
    run_parser.add_argument("--task-id")
    run_parser.add_argument("--case-id")
    run_parser.add_argument("--model-id")
    run_parser.add_argument("agent_argv", nargs=argparse.REMAINDER)
    return parser


def _strip_separator(argv: list[str]) -> list[str]:
    if argv and argv[0] == "--":
        return argv[1:]
    return argv


def _run_from_args(arguments: argparse.Namespace, request: AgentRequest) -> AgentResponse:
    agent_argv = _strip_separator(arguments.agent_argv)
    if arguments.replay is not None:
        if agent_argv or any(
            value is not None
            for value in (
                arguments.allowlist,
                arguments.task_id,
                arguments.case_id,
                arguments.model_id,
            )
        ):
            raise RuntimeConfigurationError("replay mode does not accept live agent options")
        command = (
            sys.executable,
            "-m",
            "falsiq.agent_runtime",
            "replay",
            str(arguments.replay),
        )
        return invoke_agent(
            command,
            request,
            timeout_seconds=arguments.timeout,
            transcript_path=arguments.transcript,
        )

    if not arguments.live:
        raise RuntimeConfigurationError("run requires exactly one of --replay or --live")
    if arguments.allowlist is None or arguments.model_id is None:
        raise RuntimeConfigurationError("live mode requires --allowlist and --model-id")
    if not agent_argv:
        raise RuntimeConfigurationError("live mode requires an executable argv after --")

    authorization = authorize_live(
        request,
        allowlist_path=arguments.allowlist,
        task_id=arguments.task_id,
        case_id=arguments.case_id,
        model_id=arguments.model_id,
    )
    child_environment = os.environ.copy()
    child_environment["FALSIQ_MODEL_ID"] = authorization.model_id
    child_environment[f"FALSIQ_{authorization.subject_kind.upper()}_ID"] = (
        authorization.subject_id
    )
    return invoke_agent(
        agent_argv,
        request,
        timeout_seconds=arguments.timeout,
        transcript_path=arguments.transcript,
        environ=child_environment,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the separate ``falsiq-agent`` executable."""

    arguments = _build_parser().parse_args(argv)
    try:
        request = parse_request(sys.stdin.read())
        if arguments.command_name == "replay":
            response = replay_response(request, load_transcript(arguments.transcript))
        else:
            response = _run_from_args(arguments, request)
        sys.stdout.write(_json_line(response))
        sys.stdout.flush()
        return 0
    except AgentRuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("error: unable to capture agent transcript", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
