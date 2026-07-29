"""Offline, replay-first intent-elicitation evaluation orchestration.

The harness is deliberately provider neutral.  It sends strict role-specific
payloads through :mod:`falsiq.agent_runtime`, captures private transcripts, and
publishes only redacted aggregate metrics.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import os
import random
import re
import shutil
import stat
import sys
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from fractions import Fraction
from itertools import combinations
from pathlib import Path, PurePosixPath, PureWindowsPath
from statistics import fmean
from typing import Annotated, Any, Literal, Protocol, TypeVar, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from .agent_runtime import (
    AgentRequest,
    AgentRuntimeError,
    invoke_agent,
    load_transcript,
    prepare_private_directory,
    replay_response,
)
from .benchmark import EvalTask, PrincipalRuling, PublicTask, detect_principal_leaks, load_task
from .constraints import validate_consequence_artifact
from .corpus import (
    CorpusError,
    load_holdout_manifest,
    read_owner_secret_file,
    read_private_holdout_task,
)
from .score import (
    BootstrapInterval,
    RequirementScore,
    ReviewEvaluation,
    interaction_cost,
    licensed_discretion_rate,
    paired_bootstrap_interval,
    severity_weighted_recall,
    waste_rate,
    weighted_conformance,
)
from .score import LatentRequirement as MetricRequirement

SCHEMA_VERSION = 1
REVIEWER_ROLES = (
    "reviewer.boundary",
    "reviewer.consequence",
    "reviewer.prototype",
    "reviewer.conflict",
    "reviewer.omission",
)
AGENT_ROLES = (
    *REVIEWER_ROLES,
    "selector",
    "principal",
    "scorer",
    "naive_baseline",
    "baseline_principal",
    "builder",
    "judge",
)
MAX_INTERACTIONS_PER_ROUND = 3
_WINDOWS_DEVICE_NAME = re.compile(
    r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$",
    re.IGNORECASE,
)

StableToken = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]*$",
    ),
]
NonblankText = Annotated[str, StringConstraints(strict=True, strip_whitespace=True, min_length=1)]


class EvaluationError(RuntimeError):
    """Base class for safe evaluation failures."""


class EvaluationProtocolError(EvaluationError):
    """An agent returned a valid envelope with invalid role-specific data."""


class EvaluationLeakageError(EvaluationError):
    """A principal disclosed hidden intent outside the implicated interaction."""


class EvaluationRuntimeError(EvaluationError):
    """A replay recording or captured transcript could not be used."""


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ArtifactOption(ContractModel):
    key: StableToken
    body: NonblankText


class EvaluationArtifact(ContractModel):
    type: Literal["transcript", "scenario", "diff", "rivals", "input"]
    body: NonblankText
    options: list[ArtifactOption] = Field(min_length=2)

    @model_validator(mode="after")
    def option_keys_are_unique(self) -> EvaluationArtifact:
        keys = [option.key for option in self.options]
        if len(keys) != len(set(keys)):
            raise ValueError("artifact option keys must be unique")
        return self


class ReviewCandidate(ContractModel):
    review_id: StableToken
    klass: Literal["boundary", "consequence", "prototype", "conflict", "omission"]
    artifact: EvaluationArtifact
    settles: list[NonblankText] = Field(min_length=1)
    silent_settles: list[NonblankText] = Field(default_factory=list)
    risk_scenario: NonblankText
    render_cost: Literal["trivial", "cheap", "expensive"]

    @model_validator(mode="after")
    def decision_lists_are_sets(self) -> ReviewCandidate:
        validate_consequence_artifact(
            klass=self.klass,
            artifact_type=self.artifact.type,
            body=self.artifact.body,
        )
        if len(self.settles) != len(set(self.settles)):
            raise ValueError("settles entries must be unique")
        if len(self.silent_settles) != len(set(self.silent_settles)):
            raise ValueError("silent_settles entries must be unique")
        if not set(self.silent_settles).issubset(self.settles):
            raise ValueError("silent_settles must be a subset of settles")
        return self


class PublicRuling(ContractModel):
    review_id: StableToken
    round: int = Field(ge=1, le=2)
    verdict: Literal["intended", "forbidden", "dont_care", "amend"]
    choice: StableToken | None = None
    amendment_text: NonblankText | None = None

    @model_validator(mode="after")
    def ruling_shape_matches_verdict(self) -> PublicRuling:
        if self.verdict in {"intended", "forbidden"}:
            if self.choice is None or self.amendment_text is not None:
                raise ValueError("intended and forbidden rulings require only a choice")
        elif self.verdict == "amend":
            if self.choice is not None or self.amendment_text is None:
                raise ValueError("amend rulings require only amendment_text")
        elif self.choice is not None or self.amendment_text is not None:
            raise ValueError("dont_care accepts neither choice nor amendment_text")
        return self


class ReviewerPayload(ContractModel):
    task: PublicTask
    round: int = Field(ge=1, le=2)
    prior_rulings: list[PublicRuling]


class SelectorPayload(ContractModel):
    task: PublicTask
    round: int = Field(ge=1, le=2)
    candidates: list[ReviewCandidate]


class PrincipalPayload(ContractModel):
    task: EvalTask
    round: int = Field(ge=1, le=2)
    review: ReviewCandidate
    interactions_used: int = Field(ge=0)
    interaction_limit: int = Field(ge=1)


class Question(ContractModel):
    question_id: StableToken
    text: NonblankText


class BaselineExchange(ContractModel):
    question: Question
    answer: NonblankText
    implicated_requirement_ids: list[StableToken]
    round: int = Field(ge=1, le=2)


class BaselinePayload(ContractModel):
    task: PublicTask
    round: int = Field(ge=1, le=2)
    prior_exchanges: list[BaselineExchange]


class BaselinePrincipalPayload(ContractModel):
    task: EvalTask
    round: int = Field(ge=1, le=2)
    question: Question
    interactions_used: int = Field(ge=0)
    interaction_limit: int = Field(ge=1)


class ScoringInteraction(ContractModel):
    interaction_id: StableToken
    round: int = Field(ge=1, le=2)
    artifact: EvaluationArtifact | None = None
    question: NonblankText | None = None
    ruling: PublicRuling | None = None
    answer: NonblankText | None = None

    @model_validator(mode="after")
    def condition_shape_is_unambiguous(self) -> ScoringInteraction:
        is_falsiq = self.artifact is not None or self.ruling is not None
        is_baseline = self.question is not None or self.answer is not None
        if is_falsiq == is_baseline:
            raise ValueError("scoring interaction must describe exactly one condition")
        if is_falsiq and (self.artifact is None or self.ruling is None):
            raise ValueError("Falsiq scoring interactions require artifact and ruling")
        if is_baseline and (self.question is None or self.answer is None):
            raise ValueError("baseline scoring interactions require question and answer")
        return self


class ScorerPayload(ContractModel):
    task: EvalTask
    condition: Literal["falsiq", "baseline"]
    interactions: list[ScoringInteraction]

    @model_validator(mode="after")
    def interaction_shapes_match_condition(self) -> ScorerPayload:
        for interaction in self.interactions:
            if self.condition == "falsiq" and interaction.artifact is None:
                raise ValueError("Falsiq scorer payload contains a baseline interaction")
            if self.condition == "baseline" and interaction.question is None:
                raise ValueError("baseline scorer payload contains a Falsiq interaction")
        return self


def _safe_relative_file(value: str) -> str:
    if not value or "\0" in value or "\\" in value:
        raise ValueError("changed path must be a POSIX relative file")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if posix.is_absolute() or windows.is_absolute() or windows.drive:
        raise ValueError("changed path must be relative")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("changed path must be normalized without traversal")
    if parts[0].casefold() in {".git", ".falsiq"}:
        raise ValueError("builder cannot modify repository or Falsiq control data")
    if any(
        ":" in part or part.endswith((" ", ".")) or _WINDOWS_DEVICE_NAME.fullmatch(part) is not None
        for part in parts
    ):
        raise ValueError("changed path is ambiguous or reserved on Windows")
    return value


class TestResult(ContractModel):
    status: Literal["passed", "failed", "not_run"]
    summary: Annotated[
        str,
        StringConstraints(strict=True, strip_whitespace=True, min_length=1, max_length=4096),
    ]


class FileUpdate(ContractModel):
    path: str
    content: Annotated[str, StringConstraints(strict=True, max_length=1_000_000)]
    executable: bool = False

    @field_validator("path")
    @classmethod
    def path_is_safe(cls, value: str) -> str:
        return _safe_relative_file(value)


class BuilderPayload(ContractModel):
    task: PublicTask
    candidate_id: StableToken
    workspace: NonblankText
    instructions: NonblankText


class BuilderResponse(ContractModel):
    request_id: StableToken
    summary: NonblankText
    changed_paths: list[str] = Field(max_length=1000)
    files: list[FileUpdate] = Field(max_length=1000)
    deleted_paths: list[str] = Field(max_length=1000)
    visible_test_result: TestResult

    @field_validator("changed_paths", "deleted_paths")
    @classmethod
    def changed_paths_are_safe(cls, values: list[str]) -> list[str]:
        return [_safe_relative_file(value) for value in values]

    @model_validator(mode="after")
    def changed_paths_match_materialized_updates(self) -> BuilderResponse:
        file_paths = [file.path for file in self.files]
        if len(file_paths) != len(set(file_paths)):
            raise ValueError("builder file update paths must be unique")
        if len(self.deleted_paths) != len(set(self.deleted_paths)):
            raise ValueError("builder deleted paths must be unique")
        if set(file_paths).intersection(self.deleted_paths):
            raise ValueError("builder cannot update and delete the same path")
        casefolded_paths = [path.casefold() for path in [*file_paths, *self.deleted_paths]]
        if len(casefolded_paths) != len(set(casefolded_paths)):
            raise ValueError("builder paths must remain unique on case-insensitive filesystems")
        expected = sorted([*file_paths, *self.deleted_paths])
        if self.changed_paths != expected:
            raise ValueError("changed_paths must be the sorted materialized path list")
        return self


class JudgePayload(ContractModel):
    task: EvalTask
    candidate_id: StableToken
    changed_files: list[FileUpdate]
    deleted_paths: list[str]
    visible_test_result: TestResult
    hidden_test_result: TestResult

    @field_validator("deleted_paths")
    @classmethod
    def deleted_paths_are_safe(cls, values: list[str]) -> list[str]:
        return [_safe_relative_file(value) for value in values]


class RequirementAssessment(ContractModel):
    requirement_id: StableToken
    score: Literal[0.0, 0.5, 1.0]
    rationale: NonblankText


class JudgeResponse(ContractModel):
    request_id: StableToken
    requirement_scores: list[RequirementAssessment]
    overall_rationale: NonblankText
    evidence_gaps: list[NonblankText]

    @model_validator(mode="after")
    def requirement_scores_are_unique(self) -> JudgeResponse:
        ids = [score.requirement_id for score in self.requirement_scores]
        if len(ids) != len(set(ids)):
            raise ValueError("judge requirement scores must be unique")
        return self


class ReviewerResponse(ContractModel):
    request_id: StableToken
    reviews: list[ReviewCandidate] = Field(max_length=4)


class SelectorResponse(ContractModel):
    request_id: StableToken
    selected_review_ids: list[StableToken] = Field(max_length=MAX_INTERACTIONS_PER_ROUND)
    rationale: NonblankText

    @model_validator(mode="after")
    def selections_are_unique(self) -> SelectorResponse:
        if len(self.selected_review_ids) != len(set(self.selected_review_ids)):
            raise ValueError("selected review IDs must be unique")
        return self


class BaselineResponse(ContractModel):
    request_id: StableToken
    questions: list[Question] = Field(max_length=MAX_INTERACTIONS_PER_ROUND)

    @model_validator(mode="after")
    def question_ids_are_unique(self) -> BaselineResponse:
        ids = [question.question_id for question in self.questions]
        if len(ids) != len(set(ids)):
            raise ValueError("question IDs must be unique")
        return self


class BaselinePrincipalResponse(ContractModel):
    request_id: StableToken
    answer: NonblankText
    implicated_requirement_ids: list[StableToken]

    @model_validator(mode="after")
    def implicated_ids_are_unique(self) -> BaselinePrincipalResponse:
        if len(self.implicated_requirement_ids) != len(set(self.implicated_requirement_ids)):
            raise ValueError("implicated requirement IDs must be unique")
        return self


class ScoreMapping(ContractModel):
    interaction_id: StableToken
    requirement_ids: list[StableToken]
    rationale: NonblankText

    @model_validator(mode="after")
    def requirement_ids_are_unique(self) -> ScoreMapping:
        if len(self.requirement_ids) != len(set(self.requirement_ids)):
            raise ValueError("mapped requirement IDs must be unique")
        return self


class ScorerResponse(ContractModel):
    request_id: StableToken
    mappings: list[ScoreMapping]
    waste_interaction_ids: list[StableToken]
    leaked_requirement_ids: list[StableToken]
    rationale: NonblankText

    @model_validator(mode="after")
    def response_lists_are_unique(self) -> ScorerResponse:
        mapping_ids = [mapping.interaction_id for mapping in self.mappings]
        for name, values in (
            ("mapping interaction IDs", mapping_ids),
            ("waste interaction IDs", self.waste_interaction_ids),
            ("leaked requirement IDs", self.leaked_requirement_ids),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{name} must be unique")
        return self


PayloadModel = (
    ReviewerPayload
    | SelectorPayload
    | PrincipalPayload
    | ScorerPayload
    | BaselinePayload
    | BaselinePrincipalPayload
    | BuilderPayload
    | JudgePayload
)
ResponseModel = (
    ReviewerResponse
    | SelectorResponse
    | PrincipalRuling
    | ScorerResponse
    | BaselineResponse
    | BaselinePrincipalResponse
    | BuilderResponse
    | JudgeResponse
)

_PAYLOAD_MODELS: dict[str, type[ContractModel]] = {
    **{role: ReviewerPayload for role in REVIEWER_ROLES},
    "selector": SelectorPayload,
    "principal": PrincipalPayload,
    "scorer": ScorerPayload,
    "naive_baseline": BaselinePayload,
    "baseline_principal": BaselinePrincipalPayload,
    "builder": BuilderPayload,
    "judge": JudgePayload,
}
_RESPONSE_MODELS: dict[str, type[BaseModel]] = {
    **{role: ReviewerResponse for role in REVIEWER_ROLES},
    "selector": SelectorResponse,
    "principal": PrincipalRuling,
    "scorer": ScorerResponse,
    "naive_baseline": BaselineResponse,
    "baseline_principal": BaselinePrincipalResponse,
    "builder": BuilderResponse,
    "judge": JudgeResponse,
}


def _known_role(role: str) -> None:
    if role not in _PAYLOAD_MODELS:
        raise ValueError(f"unknown evaluation agent role: {role}")


def validate_role_payload(role: str, value: Mapping[str, JsonValue]) -> PayloadModel:
    """Strictly validate a payload against the allowlist for ``role``."""

    _known_role(role)
    return cast(PayloadModel, _PAYLOAD_MODELS[role].model_validate(value))


def validate_role_response(
    role: str,
    request_id: str,
    value: JsonValue,
) -> ResponseModel:
    """Strictly validate a nested response and its redundant request ID."""

    _known_role(role)
    try:
        parsed = _RESPONSE_MODELS[role].model_validate(value)
    except ValidationError:
        raise EvaluationProtocolError(
            f"{role} response does not match its role-specific schema"
        ) from None
    if parsed.request_id != request_id:
        raise EvaluationProtocolError(f"{role} nested request ID does not match the request")
    return cast(ResponseModel, parsed)


class EvaluationAgentRuntime(Protocol):
    def invoke(self, role: str, request_id: str, payload: BaseModel) -> BaseModel:
        """Invoke one validated role request and return its validated response."""


class AgentRuntime:
    """Replay-only executable-agent runtime with resumable private captures."""

    def __init__(
        self,
        recordings_dir: str | os.PathLike[str],
        transcript_dir: str | os.PathLike[str],
        *,
        resume: bool = False,
        timeout_seconds: float = 120.0,
    ) -> None:
        self.recordings_dir = Path(recordings_dir)
        self.transcript_dir = Path(transcript_dir)
        self.resume = resume
        self.timeout_seconds = timeout_seconds
        try:
            self.transcript_dir = prepare_private_directory(self.transcript_dir)
        except AgentRuntimeError as error:
            raise EvaluationRuntimeError("private transcript directory is unsafe") from error

    def invoke(self, role: str, request_id: str, payload: BaseModel) -> BaseModel:
        try:
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", request_id) is None:
                raise ValueError("evaluation request ID must be a safe stable token")
            validated = validate_role_payload(role, payload.model_dump(mode="json"))
            request = AgentRequest(
                role=role,
                request_id=request_id,
                payload=validated.model_dump(mode="json"),
            )
            transcript_path = self.transcript_dir / f"{request_id}.json"
            if self.resume and transcript_path.is_file():
                response = replay_response(request, load_transcript(transcript_path))
            else:
                recording = self.recordings_dir / f"{request_id}.json"
                command = (
                    sys.executable,
                    "-m",
                    "falsiq.agent_runtime",
                    "replay",
                    str(recording),
                )
                response = invoke_agent(
                    command,
                    request,
                    timeout_seconds=self.timeout_seconds,
                    transcript_path=transcript_path,
                )
            return validate_role_response(role, request_id, response.response)
        except EvaluationProtocolError:
            raise
        except (AgentRuntimeError, OSError) as error:
            raise EvaluationRuntimeError(f"unable to replay {role} request {request_id}") from error


class ConditionMetrics(ContractModel):
    recall_at_round_1: float | None
    recall_at_round_2: float | None
    waste_rate: float
    licensed_discretion_rate: float
    interaction_cost: int = Field(ge=0)
    all_intended_round_rate: float | None


class TaskMetrics(ContractModel):
    task_id: StableToken
    stratum: Literal["synthetic", "mined", "control"]
    falsiq: ConditionMetrics
    baseline: ConditionMetrics


class AggregateConditionMetrics(ConditionMetrics):
    average_interaction_cost: float = Field(ge=0)
    control_interaction_average: float = Field(ge=0)


class AggregateMetrics(ContractModel):
    falsiq: AggregateConditionMetrics
    baseline: AggregateConditionMetrics


class EvaluationReport(ContractModel):
    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    task_count: int = Field(ge=1)
    aggregate: AggregateMetrics
    tasks: list[TaskMetrics] = Field(min_length=1)


class ConformanceTaskMetrics(ContractModel):
    task_id: StableToken
    stratum: Literal["synthetic", "mined", "control"]
    vague_conformance: float | None
    baseline_conformance: float | None
    falsiq_conformance: float | None


class ConformanceAverages(ContractModel):
    vague: float | None
    baseline: float | None
    falsiq: float | None


class BootstrapResult(ContractModel):
    mean_delta: float
    low: float
    high: float
    confidence: float
    samples: int
    seed: int
    statistically_visible: bool

    @classmethod
    def from_interval(cls, interval: BootstrapInterval) -> BootstrapResult:
        return cls(
            mean_delta=interval.mean_delta,
            low=interval.low,
            high=interval.high,
            confidence=interval.confidence,
            samples=interval.samples,
            seed=interval.seed,
            statistically_visible=interval.low > 0.0,
        )


class ConformanceReport(ContractModel):
    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    seed: int
    bootstrap_samples: int = Field(ge=1)
    elicitation: EvaluationReport
    averages: ConformanceAverages
    falsiq_vs_vague: BootstrapResult | None
    falsiq_vs_baseline: BootstrapResult | None
    tasks: list[ConformanceTaskMetrics] = Field(min_length=1)


class HiddenTestRunner(Protocol):
    def __call__(self, task: EvalTask, workspace: Path) -> TestResult:
        """Run hidden tests only after every builder process has exited."""


@dataclass(frozen=True, slots=True)
class _ConditionOutcome:
    evaluations: tuple[ReviewEvaluation, ...]
    handoff: str = ""


@dataclass(frozen=True, slots=True)
class _TaskOutcome:
    task: EvalTask
    falsiq: _ConditionOutcome
    baseline: _ConditionOutcome


@dataclass(frozen=True, slots=True)
class _FalsiqDecision:
    review: ReviewCandidate
    ruling: PublicRuling


def _request_id(task_id: str, condition: str, role: str, suffix: str) -> str:
    role_token = role.replace(".", "-").replace("_", "-")
    value = f"{task_id}-{condition}-{role_token}-{suffix}"
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", value) is None:
        raise ValueError("generated evaluation request ID is invalid")
    return value


TResponse = TypeVar("TResponse", bound=BaseModel)


def _invoke(
    runtime: EvaluationAgentRuntime,
    role: str,
    request_id: str,
    payload: BaseModel,
    expected: type[TResponse],
) -> TResponse:
    response = runtime.invoke(role, request_id, payload)
    if not isinstance(response, expected):
        raise EvaluationProtocolError(f"{role} runtime returned the wrong response type")
    return response


def _verify_known_requirements(task: EvalTask, ids: Iterable[str], *, source: str) -> None:
    known = {requirement.id for requirement in task.latent_requirements}
    unknown = set(ids).difference(known)
    if unknown:
        raise EvaluationProtocolError(
            f"{source} referenced unknown requirement {sorted(unknown)[0]}"
        )


def _normalized_text(value: str) -> str:
    return " ".join(value.casefold().split())


def _detect_answer_leaks(
    task: EvalTask,
    answer: str,
    implicated_requirement_ids: Iterable[str],
) -> tuple[str, ...]:
    implicated = set(implicated_requirement_ids)
    _verify_known_requirements(task, implicated, source="baseline principal")
    rendered = _normalized_text(answer)
    return tuple(
        requirement.id
        for requirement in task.latent_requirements
        if requirement.id not in implicated
        and (
            _normalized_text(requirement.text) in rendered
            or _normalized_text(requirement.discriminator) in rendered
        )
    )


def _select_reviews(
    candidates: tuple[ReviewCandidate, ...],
    selection: SelectorResponse,
) -> tuple[ReviewCandidate, ...]:
    by_id = {candidate.review_id: candidate for candidate in candidates}
    if len(by_id) != len(candidates):
        raise EvaluationProtocolError("reviewers returned duplicate review IDs")
    unknown = set(selection.selected_review_ids).difference(by_id)
    if unknown:
        raise EvaluationProtocolError(f"selector referenced unknown review {sorted(unknown)[0]}")

    def valid(values: tuple[ReviewCandidate, ...]) -> bool:
        classes = [candidate.klass for candidate in values]
        return (
            (len(values) <= 1 or len(set(classes)) >= 2)
            and classes.count("prototype") <= 1
            and classes.count("omission") <= 2
        )

    def score(candidate: ReviewCandidate) -> Fraction:
        costs = {"trivial": 1, "cheap": 3, "expensive": 9}
        return Fraction(
            len(candidate.settles) + len(candidate.silent_settles),
            costs[candidate.render_cost],
        )

    def digest(candidate: ReviewCandidate) -> str:
        content = candidate.model_dump(mode="json")
        del content["review_id"]
        canonical = json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return hashlib.sha256(canonical).hexdigest()

    digests = {candidate.review_id: digest(candidate) for candidate in candidates}
    if len(set(digests.values())) != len(candidates):
        raise EvaluationProtocolError("reviewers returned duplicate candidate content")
    feasible: list[tuple[ReviewCandidate, ...]] = []
    for size in range(1, min(MAX_INTERACTIONS_PER_ROUND, len(candidates)) + 1):
        feasible.extend(values for values in combinations(candidates, size) if valid(values))
    if not feasible:
        expected: tuple[ReviewCandidate, ...] = ()
    else:
        maximum_size = max(len(values) for values in feasible)
        largest = [values for values in feasible if len(values) == maximum_size]
        maximum_score = max(sum((score(item) for item in values), Fraction()) for values in largest)
        highest = [
            values
            for values in largest
            if sum((score(item) for item in values), Fraction()) == maximum_score
        ]
        chosen = min(
            highest,
            key=lambda values: tuple(sorted(digests[item.review_id] for item in values)),
        )
        expected = tuple(sorted(chosen, key=lambda item: (-score(item), digests[item.review_id])))
    expected_ids = [candidate.review_id for candidate in expected]
    if selection.selected_review_ids != expected_ids:
        raise EvaluationProtocolError(
            "selector output does not match the deterministic selection policy"
        )
    return expected


def _score_interactions(
    task: EvalTask,
    runtime: EvaluationAgentRuntime,
    *,
    condition: Literal["falsiq", "baseline"],
    interactions: tuple[ScoringInteraction, ...],
    verdicts: Mapping[str, str | None],
) -> _ConditionOutcome:
    if not interactions:
        return _ConditionOutcome(())
    request_id = _request_id(task.task_id, condition, "scorer", "final")
    response = _invoke(
        runtime,
        "scorer",
        request_id,
        ScorerPayload(task=task, condition=condition, interactions=list(interactions)),
        ScorerResponse,
    )
    interaction_ids = {interaction.interaction_id for interaction in interactions}
    mapped_ids = {mapping.interaction_id for mapping in response.mappings}
    if mapped_ids != interaction_ids:
        raise EvaluationProtocolError("scorer must map every interaction exactly once")
    unknown_waste = set(response.waste_interaction_ids).difference(interaction_ids)
    if unknown_waste:
        raise EvaluationProtocolError("scorer marked an unknown interaction as waste")
    all_requirement_ids = [
        requirement_id
        for mapping in response.mappings
        for requirement_id in mapping.requirement_ids
    ]
    _verify_known_requirements(task, all_requirement_ids, source="scorer")
    _verify_known_requirements(task, response.leaked_requirement_ids, source="scorer leakage")
    if response.leaked_requirement_ids:
        leaked = sorted(response.leaked_requirement_ids)[0]
        raise EvaluationLeakageError(
            f"scorer detected principal leak of hidden requirement {leaked}"
        )
    by_mapping = {mapping.interaction_id: mapping for mapping in response.mappings}
    expected_waste = {
        interaction.interaction_id
        for interaction in interactions
        if not by_mapping[interaction.interaction_id].requirement_ids
        and verdicts.get(interaction.interaction_id) != "amend"
    }
    if set(response.waste_interaction_ids) != expected_waste:
        raise EvaluationProtocolError("scorer waste list disagrees with its mappings")
    evaluations = tuple(
        ReviewEvaluation(
            interaction.interaction_id,
            round=interaction.round,
            requirement_ids=frozenset(by_mapping[interaction.interaction_id].requirement_ids),
            amended=verdicts.get(interaction.interaction_id) == "amend",
            verdict=cast(Any, verdicts.get(interaction.interaction_id)),
        )
        for interaction in interactions
    )
    return _ConditionOutcome(evaluations)


def _verbatim_block(value: str) -> list[str]:
    runs = [len(match.group()) for match in re.finditer(r"`+", value)]
    fence = "`" * max(3, (max(runs) + 1) if runs else 3)
    return [f"{fence}text", value, fence]


def _inline_code(value: str) -> str:
    escaped = html.escape(value, quote=True).replace("\n", "&#10;")
    return f"<code>{escaped}</code>"


def _render_eval_ruling_evidence(decision: _FalsiqDecision) -> list[str]:
    review = decision.review
    ruling = decision.ruling
    choice = f"`{ruling.choice}`" if ruling.choice is not None else "—"
    lines = [
        f"### Review `{review.review_id}`",
        "",
        f"- Round: {ruling.round}",
        f"- Class: `{review.klass}`",
        f"- Verdict: `{ruling.verdict}`",
        f"- Choice: {choice}",
        "- Settles:",
        *[f"  - {_inline_code(item)}" for item in review.settles],
        "",
        f"#### Artifact (`{review.artifact.type}`)",
        "",
        *_verbatim_block(review.artifact.body),
        "",
    ]
    for option in review.artifact.options:
        lines.extend(
            [
                f"##### Choice `{option.key}`",
                "",
                *_verbatim_block(option.body),
                "",
            ]
        )
    lines.extend(
        [
            "#### Risk scenario",
            "",
            *_verbatim_block(review.risk_scenario),
            "",
        ]
    )
    return lines


def _render_falsiq_handoff(
    task: PublicTask,
    decisions: Sequence[_FalsiqDecision],
) -> str:
    amendments = [decision for decision in decisions if decision.ruling.verdict == "amend"]
    lines = [
        "# Falsiq implementation brief",
        "",
        "## Original request context (verbatim)",
        "",
        *_verbatim_block(task.vague_prompt),
        "",
        "## Intent (verbatim)",
        "",
    ]
    if amendments:
        active = amendments[-1]
        assert active.ruling.amendment_text is not None
        lines.extend(
            [
                f"### Active amendment from review `{active.review.review_id}`",
                "",
                *_verbatim_block(active.ruling.amendment_text),
                "",
            ]
        )
    else:
        lines.extend(
            [
                "### Active initial intent",
                "",
                *_verbatim_block(task.vague_prompt),
                "",
            ]
        )

    lines.extend(
        [
            "## Rulings",
            "",
            "| Review | Round | Class | Verdict | Choice |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    if not decisions:
        lines.extend(["", "- No collisions were selected.", ""])
    else:
        for decision in decisions:
            review = decision.review
            ruling = decision.ruling
            choice = f"`{ruling.choice}`" if ruling.choice is not None else "—"
            lines.append(
                f"| `{review.review_id}` | {ruling.round} | {review.klass} | "
                f"{ruling.verdict} | {choice} |"
            )
        lines.append("")

    for index, decision in enumerate(amendments):
        amendment = decision.ruling.amendment_text
        assert amendment is not None
        status = "active" if index == len(amendments) - 1 else "superseded"
        lines.extend(
            [
                f"### Amendment ruling for review `{decision.review.review_id}` "
                f"(verbatim; {status})",
                "",
                *_verbatim_block(amendment),
                "",
            ]
        )

    lines.extend(["## Ruling evidence (elicited)", ""])
    if not decisions:
        lines.extend(["- No active rulings.", ""])
    else:
        for decision in decisions:
            lines.extend(_render_eval_ruling_evidence(decision))

    forbidden = [decision for decision in decisions if decision.ruling.verdict == "forbidden"]
    lines.extend(["## Forbidden acceptance-test obligations", ""])
    if not forbidden:
        lines.extend(["- No active forbidden rulings.", ""])
    else:
        for decision in forbidden:
            choice = decision.ruling.choice
            assert choice is not None
            option = next(
                option for option in decision.review.artifact.options if option.key == choice
            )
            lines.extend(
                [
                    f"### Review `{decision.review.review_id}`",
                    "",
                    f"- Acceptance tests must reject choice `{choice}` when "
                    "repository-level tests can express this observable behavior; "
                    "otherwise record the limitation in the builder summary.",
                    "- Forbidden behavior (verbatim):",
                    "",
                    *_verbatim_block(option.body),
                    "",
                ]
            )

    discretion = [decision for decision in decisions if decision.ruling.verdict == "dont_care"]
    lines.extend(["## Agent discretion", ""])
    if not discretion:
        lines.extend(["- None recorded.", ""])
    else:
        for decision in discretion:
            for settled in decision.review.settles:
                lines.append(
                    f"- {_inline_code(settled)} — licensed by `dont_care` ruling "
                    f"for review `{decision.review.review_id}`."
                )
        lines.append("")
    return "\n".join(lines) + "\n"


def _render_baseline_handoff(
    task: EvalTask,
    exchanges: Sequence[BaselineExchange],
) -> str:
    lines = [
        "# Clarification transcript",
        "",
        "## Intent",
        "",
        task.vague_prompt,
        "",
        "## Questions and answers",
    ]
    if not exchanges:
        lines.extend(["", "No clarification questions were asked."])
    for exchange in exchanges:
        lines.extend(
            [
                "",
                f"- Q: {exchange.question.text}",
                f"- A: {exchange.answer}",
            ]
        )
    return "\n".join(lines) + "\n"


def _run_falsiq(task: EvalTask, runtime: EvaluationAgentRuntime) -> _ConditionOutcome:
    prior_rulings: list[PublicRuling] = []
    interactions: list[ScoringInteraction] = []
    decisions: list[_FalsiqDecision] = []
    seen_review_ids: set[str] = set()
    interaction_limit = task.annoyance_budget * MAX_INTERACTIONS_PER_ROUND
    for round_number in range(1, task.annoyance_budget + 1):
        payload = ReviewerPayload(
            task=task.public_projection(),
            round=round_number,
            prior_rulings=prior_rulings,
        )
        with ThreadPoolExecutor(max_workers=len(REVIEWER_ROLES)) as executor:
            futures = [
                executor.submit(
                    _invoke,
                    runtime,
                    role,
                    _request_id(task.task_id, "f", role, f"r{round_number}"),
                    payload,
                    ReviewerResponse,
                )
                for role in REVIEWER_ROLES
            ]
            reviewer_responses = [future.result() for future in futures]
        candidates: list[ReviewCandidate] = []
        for role, response in zip(REVIEWER_ROLES, reviewer_responses, strict=True):
            expected_class = role.removeprefix("reviewer.")
            for review in response.reviews:
                if review.klass != expected_class:
                    raise EvaluationProtocolError(f"{role} returned review class {review.klass}")
                if review.review_id in seen_review_ids:
                    raise EvaluationProtocolError("review IDs must be unique across rounds")
                seen_review_ids.add(review.review_id)
                candidates.append(review)
        if not candidates:
            break
        selector_id = _request_id(task.task_id, "f", "selector", f"r{round_number}")
        selection = _invoke(
            runtime,
            "selector",
            selector_id,
            SelectorPayload(
                task=task.public_projection(),
                round=round_number,
                candidates=candidates,
            ),
            SelectorResponse,
        )
        selected = _select_reviews(tuple(candidates), selection)
        round_verdicts: list[str] = []
        for review in selected:
            principal_id = _request_id(
                task.task_id,
                "f",
                "principal",
                f"r{round_number}-{len(interactions) + 1}",
            )
            ruling = _invoke(
                runtime,
                "principal",
                principal_id,
                PrincipalPayload(
                    task=task,
                    round=round_number,
                    review=review,
                    interactions_used=len(interactions),
                    interaction_limit=interaction_limit,
                ),
                PrincipalRuling,
            )
            _verify_known_requirements(
                task,
                ruling.implicated_requirement_ids,
                source="principal",
            )
            leaks = detect_principal_leaks(task, ruling)
            if leaks:
                raise EvaluationLeakageError(f"principal leaked hidden requirement {leaks[0]}")
            option_keys = {option.key for option in review.artifact.options}
            if ruling.choice is not None and ruling.choice not in option_keys:
                raise EvaluationProtocolError("principal chose an option absent from the review")
            public_ruling = PublicRuling(
                review_id=review.review_id,
                round=round_number,
                verdict=ruling.verdict,
                choice=ruling.choice,
                amendment_text=ruling.amendment_text,
            )
            prior_rulings.append(public_ruling)
            decisions.append(_FalsiqDecision(review=review, ruling=public_ruling))
            interactions.append(
                ScoringInteraction(
                    interaction_id=review.review_id,
                    round=round_number,
                    artifact=review.artifact,
                    ruling=public_ruling,
                )
            )
            round_verdicts.append(ruling.verdict)
        if round_number == 1 and not set(round_verdicts).intersection({"amend", "forbidden"}):
            break
    verdicts = {
        interaction.interaction_id: interaction.ruling.verdict
        for interaction in interactions
        if interaction.ruling is not None
    }
    scored = _score_interactions(
        task,
        runtime,
        condition="falsiq",
        interactions=tuple(interactions),
        verdicts=verdicts,
    )
    return _ConditionOutcome(
        evaluations=scored.evaluations,
        handoff=_render_falsiq_handoff(task.public_projection(), decisions),
    )


def _run_baseline(task: EvalTask, runtime: EvaluationAgentRuntime) -> _ConditionOutcome:
    exchanges: list[BaselineExchange] = []
    interactions: list[ScoringInteraction] = []
    question_ids: set[str] = set()
    interaction_limit = task.annoyance_budget * MAX_INTERACTIONS_PER_ROUND
    for round_number in range(1, task.annoyance_budget + 1):
        baseline_id = _request_id(task.task_id, "b", "naive_baseline", f"r{round_number}")
        questions = _invoke(
            runtime,
            "naive_baseline",
            baseline_id,
            BaselinePayload(
                task=task.public_projection(),
                round=round_number,
                prior_exchanges=exchanges,
            ),
            BaselineResponse,
        )
        for question in questions.questions:
            if question.question_id in question_ids:
                raise EvaluationProtocolError("baseline question IDs must be unique across rounds")
            question_ids.add(question.question_id)
            principal_id = _request_id(
                task.task_id,
                "b",
                "baseline_principal",
                f"r{round_number}-{len(interactions) + 1}",
            )
            answer = _invoke(
                runtime,
                "baseline_principal",
                principal_id,
                BaselinePrincipalPayload(
                    task=task,
                    round=round_number,
                    question=question,
                    interactions_used=len(interactions),
                    interaction_limit=interaction_limit,
                ),
                BaselinePrincipalResponse,
            )
            _verify_known_requirements(
                task,
                answer.implicated_requirement_ids,
                source="baseline principal",
            )
            leaks = _detect_answer_leaks(
                task,
                answer.answer,
                answer.implicated_requirement_ids,
            )
            if leaks:
                raise EvaluationLeakageError(
                    f"baseline principal leaked hidden requirement {leaks[0]}"
                )
            exchange = BaselineExchange(
                question=question,
                answer=answer.answer,
                implicated_requirement_ids=answer.implicated_requirement_ids,
                round=round_number,
            )
            exchanges.append(exchange)
            interactions.append(
                ScoringInteraction(
                    interaction_id=question.question_id,
                    round=round_number,
                    question=question.text,
                    answer=answer.answer,
                )
            )
    scored = _score_interactions(
        task,
        runtime,
        condition="baseline",
        interactions=tuple(interactions),
        verdicts={},
    )
    return _ConditionOutcome(
        evaluations=scored.evaluations,
        handoff=_render_baseline_handoff(task, exchanges),
    )


def _metric_requirements(task: EvalTask) -> tuple[MetricRequirement, ...]:
    return tuple(
        MetricRequirement(requirement.id, requirement.severity)
        for requirement in task.latent_requirements
    )


def _condition_metrics(
    task: EvalTask,
    outcome: _ConditionOutcome,
    *,
    condition: Literal["falsiq", "baseline"],
) -> ConditionMetrics:
    requirements = _metric_requirements(task)
    return ConditionMetrics(
        recall_at_round_1=severity_weighted_recall(
            requirements,
            outcome.evaluations,
            through_round=1,
        ),
        recall_at_round_2=severity_weighted_recall(
            requirements,
            outcome.evaluations,
            through_round=2,
        ),
        waste_rate=waste_rate(outcome.evaluations),
        licensed_discretion_rate=licensed_discretion_rate(outcome.evaluations),
        interaction_cost=interaction_cost(outcome.evaluations),
        all_intended_round_rate=(
            _all_intended_round_rate(outcome.evaluations) if condition == "falsiq" else None
        ),
    )


def _all_intended_round_rate(
    evaluations: tuple[ReviewEvaluation, ...],
) -> float:
    """Flag sycophantic Falsiq rounds; baseline interactions have no verdicts."""

    flags = _all_intended_round_flags(evaluations)
    if not flags:
        return 0.0
    return sum(flags) / len(flags)


def _all_intended_round_flags(
    evaluations: tuple[ReviewEvaluation, ...],
) -> tuple[bool, ...]:
    rounds = sorted({evaluation.round for evaluation in evaluations})
    return tuple(
        all(
            evaluation.verdict == "intended"
            for evaluation in evaluations
            if evaluation.round == round_number
        )
        for round_number in rounds
    )


def _aggregate_condition(
    outcomes: tuple[_TaskOutcome, ...],
    condition: Literal["falsiq", "baseline"],
) -> AggregateConditionMetrics:
    pairs = [(outcome.task, getattr(outcome, condition)) for outcome in outcomes]

    def aggregate_recall(round_number: int) -> float | None:
        total_weight = 0
        elicited_weight = 0
        for task, result in pairs:
            requirements = _metric_requirements(task)
            weights = {
                requirement.id: 3 if requirement.severity == "rework" else 1
                for requirement in requirements
            }
            total_weight += sum(weights.values())
            elicited = {
                requirement_id
                for review in result.evaluations
                if review.round <= round_number
                for requirement_id in review.requirement_ids
            }
            elicited_weight += sum(weights[requirement_id] for requirement_id in elicited)
        return None if total_weight == 0 else elicited_weight / total_weight

    evaluations = tuple(evaluation for _, result in pairs for evaluation in result.evaluations)
    costs = [interaction_cost(result.evaluations) for _, result in pairs]
    control_costs = [
        interaction_cost(result.evaluations) for task, result in pairs if task.stratum == "control"
    ]
    return AggregateConditionMetrics(
        recall_at_round_1=aggregate_recall(1),
        recall_at_round_2=aggregate_recall(2),
        waste_rate=waste_rate(evaluations),
        licensed_discretion_rate=licensed_discretion_rate(evaluations),
        interaction_cost=sum(costs),
        all_intended_round_rate=(
            (
                sum(
                    flag
                    for _, result in pairs
                    for flag in _all_intended_round_flags(result.evaluations)
                )
                / sum(len(_all_intended_round_flags(result.evaluations)) for _, result in pairs)
            )
            if condition == "falsiq" and any(result.evaluations for _, result in pairs)
            else (0.0 if condition == "falsiq" else None)
        ),
        average_interaction_cost=fmean(costs),
        control_interaction_average=fmean(control_costs) if control_costs else 0.0,
    )


def _run_task_outcomes(
    tasks: Sequence[EvalTask],
    runtime: EvaluationAgentRuntime,
) -> tuple[_TaskOutcome, ...]:
    task_tuple = tuple(tasks)
    if not task_tuple:
        raise ValueError("evaluation requires at least one task")
    task_ids = [task.task_id for task in task_tuple]
    if len(task_ids) != len(set(task_ids)):
        raise ValueError("duplicate task ID in evaluation input")
    return tuple(
        _TaskOutcome(
            task=task,
            falsiq=_run_falsiq(task, runtime),
            baseline=_run_baseline(task, runtime),
        )
        for task in task_tuple
    )


def _evaluation_report(outcomes: tuple[_TaskOutcome, ...]) -> EvaluationReport:
    task_metrics = [
        TaskMetrics(
            task_id=outcome.task.task_id,
            stratum=outcome.task.stratum,
            falsiq=_condition_metrics(
                outcome.task,
                outcome.falsiq,
                condition="falsiq",
            ),
            baseline=_condition_metrics(
                outcome.task,
                outcome.baseline,
                condition="baseline",
            ),
        )
        for outcome in outcomes
    ]
    return EvaluationReport(
        task_count=len(outcomes),
        aggregate=AggregateMetrics(
            falsiq=_aggregate_condition(outcomes, "falsiq"),
            baseline=_aggregate_condition(outcomes, "baseline"),
        ),
        tasks=task_metrics,
    )


def run_evaluation(
    tasks: Sequence[EvalTask],
    *,
    runtime: EvaluationAgentRuntime,
) -> EvaluationReport:
    """Run Falsiq and a same-maximum-budget naive baseline for each task."""

    return _evaluation_report(_run_task_outcomes(tasks, runtime))


_CONDITIONS = ("vague", "baseline", "falsiq")
_WORKSPACE_MARKER = ".falsiq-eval-workspaces"
Condition = Literal["vague", "baseline", "falsiq"]


@dataclass(frozen=True, slots=True)
class _BuildRecord:
    task: EvalTask
    condition: Condition
    candidate_id: str
    workspace: Path
    response: BuilderResponse


@dataclass(frozen=True, slots=True)
class _JudgingRecord:
    build: _BuildRecord
    hidden_test_result: TestResult


def _seeded_order(task_id: str, *, seed: int, namespace: str) -> tuple[Condition, ...]:
    digest = hashlib.sha256(f"{seed}:{namespace}:{task_id}".encode()).digest()
    generator = random.Random(int.from_bytes(digest[:8], "big"))
    values = list(cast(tuple[Condition, ...], _CONDITIONS))
    generator.shuffle(values)
    return tuple(values)


def _fixture_source(task: EvalTask, visible_fixture_root: Path) -> Path:
    try:
        root = visible_fixture_root.resolve(strict=True)
    except OSError:
        raise EvaluationRuntimeError("visible fixture root is missing") from None
    unresolved = root / task.context.repo_fixture
    try:
        source_metadata = unresolved.lstat()
    except OSError:
        raise EvaluationRuntimeError(
            f"visible fixture for task {task.task_id} is missing"
        ) from None
    if stat.S_ISLNK(source_metadata.st_mode) or not stat.S_ISDIR(source_metadata.st_mode):
        raise EvaluationRuntimeError("visible fixture must be a real directory")
    try:
        source = unresolved.resolve(strict=True)
    except OSError:
        raise EvaluationRuntimeError("visible fixture cannot be resolved") from None
    if not source.is_relative_to(root):
        raise EvaluationRuntimeError("visible fixture escapes its configured root")
    for item in source.rglob("*"):
        metadata = item.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise EvaluationRuntimeError("visible fixture cannot contain symbolic links")
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
            raise EvaluationRuntimeError("visible fixture contains a special filesystem entry")
    return source


def _prepare_task_workspace_root(root: Path, task_id: str) -> Path:
    if root.is_symlink():
        raise EvaluationRuntimeError("workspace root cannot be a symbolic link")
    marker = root / _WORKSPACE_MARKER
    if root.exists():
        if not root.is_dir() or marker.is_symlink() or not marker.is_file():
            raise EvaluationRuntimeError(
                "workspace root must be a dedicated Falsiq evaluation directory"
            )
        try:
            marker_contents = marker.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise EvaluationRuntimeError("workspace root marker is invalid") from None
        if marker_contents != "falsiq-evaluation-workspaces-v1\n":
            raise EvaluationRuntimeError("workspace root marker is invalid")
    else:
        root.mkdir(parents=True, mode=0o700)
        _atomic_write(marker, "falsiq-evaluation-workspaces-v1\n")
    os.chmod(root, 0o700)
    task_root = root / task_id
    if task_root.is_symlink():
        raise EvaluationRuntimeError("task workspace root cannot be a symbolic link")
    if task_root.exists():
        if not task_root.is_dir():
            raise EvaluationRuntimeError("task workspace root is not a directory")
        shutil.rmtree(task_root)
    task_root.mkdir(mode=0o700)
    return task_root


def _copy_visible_workspace(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise EvaluationRuntimeError("candidate workspace already exists")
    try:
        shutil.copytree(source, destination, symlinks=True)
        os.chmod(destination, 0o700)
    except OSError:
        raise EvaluationRuntimeError("unable to copy visible fixture workspace") from None


def _checked_workspace_target(workspace: Path, relative_path: str) -> Path:
    safe_path = _safe_relative_file(relative_path)
    root = workspace.resolve(strict=True)
    candidate = workspace / safe_path
    current = workspace
    for part in PurePosixPath(safe_path).parts[:-1]:
        current /= part
        if current.is_symlink():
            raise EvaluationProtocolError("builder update traverses a symbolic link")
    resolved = candidate.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise EvaluationProtocolError("builder update escapes its isolated workspace")
    return candidate


def _materialize_builder_response(workspace: Path, response: BuilderResponse) -> None:
    for relative_path in response.deleted_paths:
        target = _checked_workspace_target(workspace, relative_path)
        if target.is_symlink() or not target.is_file():
            raise EvaluationProtocolError("builder can delete only existing regular files")
        target.unlink()
    for update in response.files:
        target = _checked_workspace_target(workspace, update.path)
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise EvaluationProtocolError("builder can update only regular files")
        if update.executable:
            mode = 0o755
        elif target.exists():
            mode = stat.S_IMODE(target.stat().st_mode)
        else:
            mode = 0o644
        _atomic_write(target, update.content)
        os.chmod(target, mode)


def _builder_instructions(outcome: _TaskOutcome, condition: Condition) -> str:
    if condition == "vague":
        return outcome.task.vague_prompt
    if condition == "baseline":
        return outcome.baseline.handoff
    return outcome.falsiq.handoff


def _build_all_conditions(
    outcomes: tuple[_TaskOutcome, ...],
    *,
    runtime: EvaluationAgentRuntime,
    visible_fixture_root: Path,
    workspace_root: Path,
    seed: int,
) -> tuple[_BuildRecord, ...]:
    records: list[_BuildRecord] = []
    for outcome in outcomes:
        source = _fixture_source(outcome.task, visible_fixture_root)
        task_root = _prepare_task_workspace_root(workspace_root, outcome.task.task_id)
        condition_order = _seeded_order(
            outcome.task.task_id,
            seed=seed,
            namespace="candidate-labels",
        )
        by_condition = {
            condition: f"candidate-{index}"
            for index, condition in enumerate(condition_order, start=1)
        }
        for condition in condition_order:
            candidate_id = by_condition[condition]
            workspace = (task_root / candidate_id).resolve(strict=False)
            _copy_visible_workspace(source, workspace)
            request_id = _request_id(
                outcome.task.task_id,
                "e2e",
                "builder",
                candidate_id,
            )
            response = _invoke(
                runtime,
                "builder",
                request_id,
                BuilderPayload(
                    task=outcome.task.public_projection(),
                    candidate_id=candidate_id,
                    workspace=str(workspace),
                    instructions=_builder_instructions(outcome, condition),
                ),
                BuilderResponse,
            )
            _materialize_builder_response(workspace, response)
            records.append(
                _BuildRecord(
                    task=outcome.task,
                    condition=condition,
                    candidate_id=candidate_id,
                    workspace=workspace,
                    response=response,
                )
            )
    return tuple(records)


def _run_hidden_tests(
    builds: tuple[_BuildRecord, ...],
    hidden_test_runner: HiddenTestRunner,
) -> tuple[_JudgingRecord, ...]:
    records: list[_JudgingRecord] = []
    for build in builds:
        try:
            result = TestResult.model_validate(hidden_test_runner(build.task, build.workspace))
        except (ValidationError, TypeError, ValueError):
            raise EvaluationProtocolError("hidden test runner returned an invalid result") from None
        records.append(_JudgingRecord(build=build, hidden_test_result=result))
    return tuple(records)


def _judge_all_conditions(
    records: tuple[_JudgingRecord, ...],
    *,
    runtime: EvaluationAgentRuntime,
    seed: int,
) -> dict[tuple[str, Condition], float | None]:
    by_task: dict[str, list[_JudgingRecord]] = {}
    for record in records:
        by_task.setdefault(record.build.task.task_id, []).append(record)
    scores: dict[tuple[str, Condition], float | None] = {}
    for task_id, task_records in by_task.items():
        judge_order = _seeded_order(task_id, seed=seed, namespace="judge-order")
        by_condition = {record.build.condition: record for record in task_records}
        for condition in judge_order:
            record = by_condition[condition]
            build = record.build
            request_id = _request_id(task_id, "e2e", "judge", build.candidate_id)
            response = _invoke(
                runtime,
                "judge",
                request_id,
                JudgePayload(
                    task=build.task,
                    candidate_id=build.candidate_id,
                    changed_files=build.response.files,
                    deleted_paths=build.response.deleted_paths,
                    visible_test_result=build.response.visible_test_result,
                    hidden_test_result=record.hidden_test_result,
                ),
                JudgeResponse,
            )
            expected_ids = {requirement.id for requirement in build.task.latent_requirements}
            observed_ids = {assessment.requirement_id for assessment in response.requirement_scores}
            if observed_ids != expected_ids:
                raise EvaluationProtocolError(
                    "judge must score every latent requirement exactly once"
                )
            metric_scores = tuple(
                RequirementScore(assessment.requirement_id, assessment.score)
                for assessment in response.requirement_scores
            )
            scores[(task_id, condition)] = weighted_conformance(
                _metric_requirements(build.task),
                metric_scores,
            )
    return scores


def _average(values: Iterable[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return fmean(present) if present else None


def _bootstrap_result(
    tasks: Sequence[EvalTask],
    scores: Mapping[tuple[str, Condition], float | None],
    *,
    candidate: Condition,
    baseline: Condition,
    seed: int,
    samples: int,
) -> BootstrapResult | None:
    pairs = [
        (scores[(task.task_id, candidate)], scores[(task.task_id, baseline)])
        for task in tasks
        if scores[(task.task_id, candidate)] is not None
        and scores[(task.task_id, baseline)] is not None
    ]
    if not pairs:
        return None
    interval = paired_bootstrap_interval(
        tuple(cast(float, pair[0]) for pair in pairs),
        tuple(cast(float, pair[1]) for pair in pairs),
        seed=seed,
        samples=samples,
    )
    return BootstrapResult.from_interval(interval)


def run_conformance_evaluation(
    tasks: Sequence[EvalTask],
    *,
    runtime: EvaluationAgentRuntime,
    visible_fixture_root: str | os.PathLike[str],
    workspace_root: str | os.PathLike[str],
    hidden_test_runner: HiddenTestRunner,
    seed: int,
    bootstrap_samples: int = 10_000,
) -> ConformanceReport:
    """Run three isolated builders and condition-blind judges per task."""

    if isinstance(seed, bool) or not isinstance(seed, int):
        raise TypeError("conformance seed must be an integer")
    if (
        isinstance(bootstrap_samples, bool)
        or not isinstance(bootstrap_samples, int)
        or bootstrap_samples < 1
    ):
        raise ValueError("bootstrap_samples must be positive")
    outcomes = _run_task_outcomes(tasks, runtime)
    builds = _build_all_conditions(
        outcomes,
        runtime=runtime,
        visible_fixture_root=Path(visible_fixture_root),
        workspace_root=Path(workspace_root),
        seed=seed,
    )
    judging_records = _run_hidden_tests(builds, hidden_test_runner)
    scores = _judge_all_conditions(judging_records, runtime=runtime, seed=seed)
    task_metrics = [
        ConformanceTaskMetrics(
            task_id=outcome.task.task_id,
            stratum=outcome.task.stratum,
            vague_conformance=scores[(outcome.task.task_id, "vague")],
            baseline_conformance=scores[(outcome.task.task_id, "baseline")],
            falsiq_conformance=scores[(outcome.task.task_id, "falsiq")],
        )
        for outcome in outcomes
    ]
    task_tuple = tuple(outcome.task for outcome in outcomes)
    return ConformanceReport(
        seed=seed,
        bootstrap_samples=bootstrap_samples,
        elicitation=_evaluation_report(outcomes),
        averages=ConformanceAverages(
            vague=_average(task.vague_conformance for task in task_metrics),
            baseline=_average(task.baseline_conformance for task in task_metrics),
            falsiq=_average(task.falsiq_conformance for task in task_metrics),
        ),
        falsiq_vs_vague=_bootstrap_result(
            task_tuple,
            scores,
            candidate="falsiq",
            baseline="vague",
            seed=seed,
            samples=bootstrap_samples,
        ),
        falsiq_vs_baseline=_bootstrap_result(
            task_tuple,
            scores,
            candidate="falsiq",
            baseline="baseline",
            seed=seed,
            samples=bootstrap_samples,
        ),
        tasks=task_metrics,
    )


def _format_number(value: float | int | None) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, int):
        return str(value)
    return f"{value:.6f}"


def _render_csv(report: EvaluationReport) -> str:
    output = io.StringIO(newline="")
    fields = [
        "task_id",
        "stratum",
        "falsiq_recall_at_round_1",
        "falsiq_recall_at_round_2",
        "falsiq_waste_rate",
        "falsiq_licensed_discretion_rate",
        "falsiq_all_intended_round_rate",
        "falsiq_interaction_cost",
        "baseline_recall_at_round_1",
        "baseline_recall_at_round_2",
        "baseline_waste_rate",
        "baseline_licensed_discretion_rate",
        "baseline_all_intended_round_rate",
        "baseline_interaction_cost",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for task in report.tasks:
        writer.writerow(
            {
                "task_id": task.task_id,
                "stratum": task.stratum,
                "falsiq_recall_at_round_1": _format_number(task.falsiq.recall_at_round_1),
                "falsiq_recall_at_round_2": _format_number(task.falsiq.recall_at_round_2),
                "falsiq_waste_rate": _format_number(task.falsiq.waste_rate),
                "falsiq_licensed_discretion_rate": _format_number(
                    task.falsiq.licensed_discretion_rate
                ),
                "falsiq_all_intended_round_rate": _format_number(
                    task.falsiq.all_intended_round_rate
                ),
                "falsiq_interaction_cost": task.falsiq.interaction_cost,
                "baseline_recall_at_round_1": _format_number(task.baseline.recall_at_round_1),
                "baseline_recall_at_round_2": _format_number(task.baseline.recall_at_round_2),
                "baseline_waste_rate": _format_number(task.baseline.waste_rate),
                "baseline_licensed_discretion_rate": _format_number(
                    task.baseline.licensed_discretion_rate
                ),
                "baseline_all_intended_round_rate": _format_number(
                    task.baseline.all_intended_round_rate
                ),
                "baseline_interaction_cost": task.baseline.interaction_cost,
            }
        )
    return output.getvalue()


def _render_markdown(report: EvaluationReport) -> str:
    falsiq = report.aggregate.falsiq
    baseline = report.aggregate.baseline
    lines = [
        "# Falsiq offline evaluation",
        "",
        f"Tasks: {report.task_count}",
        "",
        (
            "| Condition | Recall@1 | Recall@2 | Waste | All-intended rounds | "
            "Avg. interactions | Control avg. |"
        ),
        "|---|---:|---:|---:|---:|---:|---:|",
        (
            f"| Falsiq | {_format_number(falsiq.recall_at_round_1)} | "
            f"{_format_number(falsiq.recall_at_round_2)} | "
            f"{_format_number(falsiq.waste_rate)} | "
            f"{_format_number(falsiq.all_intended_round_rate)} | "
            f"{_format_number(falsiq.average_interaction_cost)} | "
            f"{_format_number(falsiq.control_interaction_average)} |"
        ),
        (
            f"| Naive baseline | {_format_number(baseline.recall_at_round_1)} | "
            f"{_format_number(baseline.recall_at_round_2)} | "
            f"{_format_number(baseline.waste_rate)} | "
            f"{_format_number(baseline.all_intended_round_rate)} | "
            f"{_format_number(baseline.average_interaction_cost)} | "
            f"{_format_number(baseline.control_interaction_average)} |"
        ),
        "",
        "## Per-task metrics",
        "",
        "| Task | Stratum | Falsiq R@2 | Baseline R@2 | Falsiq cost | Baseline cost |",
        "|---|---|---:|---:|---:|---:|",
    ]
    lines.extend(
        (
            f"| {task.task_id} | {task.stratum} | "
            f"{_format_number(task.falsiq.recall_at_round_2)} | "
            f"{_format_number(task.baseline.recall_at_round_2)} | "
            f"{task.falsiq.interaction_cost} | {task.baseline.interaction_cost} |"
        )
        for task in report.tasks
    )
    return "\n".join(lines) + "\n"


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def write_reports(
    report: EvaluationReport,
    directory: str | os.PathLike[str],
) -> dict[str, Path]:
    """Write deterministic redacted JSON, CSV, and Markdown reports."""

    root = Path(directory)
    paths = {
        "json": root / "evaluation.json",
        "csv": root / "evaluation.csv",
        "markdown": root / "evaluation.md",
    }
    documents = {
        "json": json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        "csv": _render_csv(report),
        "markdown": _render_markdown(report),
    }
    for name, path in paths.items():
        _atomic_write(path, documents[name])
    return paths


def _render_conformance_csv(report: ConformanceReport) -> str:
    output = io.StringIO(newline="")
    fields = [
        "task_id",
        "stratum",
        "vague_conformance",
        "baseline_conformance",
        "falsiq_conformance",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for task in report.tasks:
        writer.writerow(
            {
                "task_id": task.task_id,
                "stratum": task.stratum,
                "vague_conformance": _format_number(task.vague_conformance),
                "baseline_conformance": _format_number(task.baseline_conformance),
                "falsiq_conformance": _format_number(task.falsiq_conformance),
            }
        )
    return output.getvalue()


def _render_interval(interval: BootstrapResult | None) -> str:
    if interval is None:
        return "n/a"
    visible = "yes" if interval.statistically_visible else "no"
    return (
        f"delta {_format_number(interval.mean_delta)}, "
        f"CI [{_format_number(interval.low)}, {_format_number(interval.high)}], "
        f"positive interval: {visible}"
    )


def _render_conformance_markdown(report: ConformanceReport) -> str:
    lines = [
        "# Falsiq end-to-end conformance",
        "",
        f"Fixed seed: {report.seed}; bootstrap samples: {report.bootstrap_samples}.",
        "",
        f"- Falsiq vs vague: {_render_interval(report.falsiq_vs_vague)}",
        f"- Falsiq vs naive baseline: {_render_interval(report.falsiq_vs_baseline)}",
        "",
        "| Task | Stratum | Vague | Naive baseline | Falsiq |",
        "|---|---|---:|---:|---:|",
    ]
    lines.extend(
        (
            f"| {task.task_id} | {task.stratum} | "
            f"{_format_number(task.vague_conformance)} | "
            f"{_format_number(task.baseline_conformance)} | "
            f"{_format_number(task.falsiq_conformance)} |"
        )
        for task in report.tasks
    )
    return "\n".join(lines) + "\n"


def write_conformance_reports(
    report: ConformanceReport,
    directory: str | os.PathLike[str],
) -> dict[str, Path]:
    """Write redacted end-to-end JSON, CSV, and Markdown reports."""

    root = Path(directory)
    paths = {
        "json": root / "conformance.json",
        "csv": root / "conformance.csv",
        "markdown": root / "conformance.md",
    }
    documents = {
        "json": json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        "csv": _render_conformance_csv(report),
        "markdown": _render_conformance_markdown(report),
    }
    for name, path in paths.items():
        _atomic_write(path, documents[name])
    return paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="falsiq-eval",
        description="Run the replay-only Falsiq elicitation evaluation.",
    )
    task_source = parser.add_mutually_exclusive_group(required=True)
    task_source.add_argument(
        "--task",
        dest="tasks",
        action="append",
        type=Path,
        metavar="PATH",
        help="development-only task JSON path; never use for private holdout tasks",
    )
    task_source.add_argument(
        "--holdout-task-id",
        dest="holdout_task_ids",
        action="append",
        metavar="ID",
        help="manifest-listed private holdout task ID; repeat for multiple tasks",
    )
    parser.add_argument(
        "--holdout-manifest",
        type=Path,
        metavar="PATH",
        help="public salted holdout manifest (heldout mode only)",
    )
    parser.add_argument(
        "--private-task-store",
        type=Path,
        metavar="DIR",
        help="owner-private release tasks directory (heldout mode only)",
    )
    parser.add_argument(
        "--holdout-salt-file",
        type=Path,
        metavar="PATH",
        help="owner-only holdout salt file (heldout mode only)",
    )
    parser.add_argument(
        "--holdout-access-log",
        type=Path,
        metavar="PATH",
        help="owner-private append-only access log (heldout mode only)",
    )
    parser.add_argument(
        "--holdout-actor",
        metavar="TEXT",
        help="operator identity recorded for holdout access (heldout mode only)",
    )
    parser.add_argument(
        "--holdout-purpose",
        metavar="TEXT",
        help="access purpose recorded for holdout access (heldout mode only)",
    )
    parser.add_argument("--recordings", required=True, type=Path, metavar="DIR")
    parser.add_argument("--private-run-dir", required=True, type=Path, metavar="DIR")
    parser.add_argument("--reports", required=True, type=Path, metavar="DIR")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--timeout", type=float, default=120.0, metavar="SECONDS")
    return parser


def _validate_task_mode(
    parser: argparse.ArgumentParser,
    arguments: argparse.Namespace,
) -> None:
    holdout_options = {
        "--holdout-manifest": arguments.holdout_manifest,
        "--private-task-store": arguments.private_task_store,
        "--holdout-salt-file": arguments.holdout_salt_file,
        "--holdout-access-log": arguments.holdout_access_log,
        "--holdout-actor": arguments.holdout_actor,
        "--holdout-purpose": arguments.holdout_purpose,
    }
    if arguments.holdout_task_ids is None:
        mixed = [option for option, value in holdout_options.items() if value is not None]
        if mixed:
            parser.error(f"{', '.join(mixed)} may be used only with --holdout-task-id")
        return
    missing = [option for option, value in holdout_options.items() if value is None]
    if missing:
        parser.error(f"heldout mode requires {', '.join(missing)}")
    if len(arguments.holdout_task_ids) != len(set(arguments.holdout_task_ids)):
        parser.error("heldout task IDs must be unique")


def _load_cli_tasks(arguments: argparse.Namespace) -> tuple[EvalTask, ...]:
    if arguments.tasks is not None:
        return tuple(load_task(path) for path in arguments.tasks)

    manifest = load_holdout_manifest(arguments.holdout_manifest)
    salt = read_owner_secret_file(arguments.holdout_salt_file, label="holdout salt")
    return tuple(
        read_private_holdout_task(
            task_id,
            manifest=manifest,
            store=arguments.private_task_store,
            salt=salt,
            access_log=arguments.holdout_access_log,
            actor=arguments.holdout_actor,
            purpose=arguments.holdout_purpose,
        )
        for task_id in arguments.holdout_task_ids
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    _validate_task_mode(parser, arguments)
    try:
        tasks = _load_cli_tasks(arguments)
        runtime = AgentRuntime(
            arguments.recordings,
            arguments.private_run_dir / "transcripts",
            resume=arguments.resume,
            timeout_seconds=arguments.timeout,
        )
        paths = write_reports(
            run_evaluation(tasks, runtime=runtime),
            arguments.reports,
        )
    except ValidationError:
        print("error: evaluation task input is invalid", file=sys.stderr)
        return 2
    except CorpusError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except EvaluationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, ValueError):
        print("error: unable to read tasks or write evaluation output", file=sys.stderr)
        return 2
    for name, path in paths.items():
        print(f"{name}: {path}")
    return 0


__all__ = [
    "AGENT_ROLES",
    "AgentRuntime",
    "EvaluationError",
    "EvaluationLeakageError",
    "EvaluationProtocolError",
    "EvaluationReport",
    "EvaluationRuntimeError",
    "ConformanceReport",
    "TestResult",
    "build_parser",
    "main",
    "run_conformance_evaluation",
    "run_evaluation",
    "validate_role_payload",
    "validate_role_response",
    "write_conformance_reports",
    "write_reports",
]
