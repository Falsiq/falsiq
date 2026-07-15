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
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

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


def invoke_agent(
    argv: Sequence[str],
    request: AgentRequest,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    transcript_path: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> AgentResponse:
    """Invoke one fresh executable for one request.

    ``argv`` is passed directly to :func:`subprocess.run` with ``shell=False``.
    stdout and stderr are captured only for protocol handling and are never
    included in exceptions or transcripts.
    """

    command = _normalize_argv(argv)
    timeout = _validate_timeout(timeout_seconds)
    child_environment = None if environ is None else dict(environ)

    try:
        completed = subprocess.run(
            command,
            input=_json_line(request),
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=timeout,
            env=child_environment,
        )
    except subprocess.TimeoutExpired:
        raise AgentTimeoutError("agent process timed out") from None
    except OSError:
        raise AgentProcessError("agent process could not be started") from None

    if completed.returncode != 0:
        raise AgentProcessError(f"agent process failed with exit status {completed.returncode}")

    response = parse_response(completed.stdout)
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

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary = Path(temporary_name)
    try:
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
        document = Path(path).read_text(encoding="utf-8")
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
