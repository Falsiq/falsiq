"""Offline, replay-first intent-elicitation evaluation orchestration.

The harness is deliberately provider neutral.  It sends strict role-specific
payloads through :mod:`falsiq.agent_runtime`, captures private transcripts, and
publishes only redacted aggregate metrics.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from fractions import Fraction
from itertools import combinations
from pathlib import Path
from statistics import fmean
from typing import Annotated, Any, Literal, Protocol, TypeVar, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    ValidationError,
    model_validator,
)

from .agent_runtime import (
    AgentRequest,
    AgentRuntimeError,
    invoke_agent,
    load_transcript,
    replay_response,
)
from .benchmark import EvalTask, PrincipalRuling, PublicTask, detect_principal_leaks, load_task
from .score import (
    AttackEvaluation,
    interaction_cost,
    licensed_discretion_rate,
    severity_weighted_recall,
    waste_rate,
)
from .score import LatentRequirement as MetricRequirement

SCHEMA_VERSION = 1
ATTACKER_ROLES = (
    "attacker.boundary",
    "attacker.consequence",
    "attacker.prototype",
    "attacker.conflict",
    "attacker.omission",
)
AGENT_ROLES = (
    *ATTACKER_ROLES,
    "selector",
    "principal",
    "scorer",
    "naive_baseline",
    "baseline_principal",
)
MAX_INTERACTIONS_PER_ROUND = 3

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


class AttackCandidate(ContractModel):
    attack_id: StableToken
    klass: Literal["boundary", "consequence", "prototype", "conflict", "omission"]
    artifact: EvaluationArtifact
    settles: list[NonblankText] = Field(min_length=1)
    silent_settles: list[NonblankText] = Field(default_factory=list)
    hate_scenario: NonblankText
    render_cost: Literal["trivial", "cheap", "expensive"]

    @model_validator(mode="after")
    def decision_lists_are_sets(self) -> AttackCandidate:
        if len(self.settles) != len(set(self.settles)):
            raise ValueError("settles entries must be unique")
        if len(self.silent_settles) != len(set(self.silent_settles)):
            raise ValueError("silent_settles entries must be unique")
        if not set(self.silent_settles).issubset(self.settles):
            raise ValueError("silent_settles must be a subset of settles")
        return self


class PublicRuling(ContractModel):
    attack_id: StableToken
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


class AttackerPayload(ContractModel):
    task: PublicTask
    round: int = Field(ge=1, le=2)
    prior_rulings: list[PublicRuling]


class SelectorPayload(ContractModel):
    task: PublicTask
    round: int = Field(ge=1, le=2)
    candidates: list[AttackCandidate]


class PrincipalPayload(ContractModel):
    task: EvalTask
    round: int = Field(ge=1, le=2)
    attack: AttackCandidate
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


class AttackerResponse(ContractModel):
    request_id: StableToken
    attacks: list[AttackCandidate] = Field(max_length=4)


class SelectorResponse(ContractModel):
    request_id: StableToken
    selected_attack_ids: list[StableToken] = Field(max_length=MAX_INTERACTIONS_PER_ROUND)
    rationale: NonblankText

    @model_validator(mode="after")
    def selections_are_unique(self) -> SelectorResponse:
        if len(self.selected_attack_ids) != len(set(self.selected_attack_ids)):
            raise ValueError("selected attack IDs must be unique")
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
    AttackerPayload
    | SelectorPayload
    | PrincipalPayload
    | ScorerPayload
    | BaselinePayload
    | BaselinePrincipalPayload
)
ResponseModel = (
    AttackerResponse
    | SelectorResponse
    | PrincipalRuling
    | ScorerResponse
    | BaselineResponse
    | BaselinePrincipalResponse
)

_PAYLOAD_MODELS: dict[str, type[ContractModel]] = {
    **{role: AttackerPayload for role in ATTACKER_ROLES},
    "selector": SelectorPayload,
    "principal": PrincipalPayload,
    "scorer": ScorerPayload,
    "naive_baseline": BaselinePayload,
    "baseline_principal": BaselinePrincipalPayload,
}
_RESPONSE_MODELS: dict[str, type[BaseModel]] = {
    **{role: AttackerResponse for role in ATTACKER_ROLES},
    "selector": SelectorResponse,
    "principal": PrincipalRuling,
    "scorer": ScorerResponse,
    "naive_baseline": BaselineResponse,
    "baseline_principal": BaselinePrincipalResponse,
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
        self.transcript_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.transcript_dir, 0o700)

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
            raise EvaluationRuntimeError(
                f"unable to replay {role} request {request_id}"
            ) from error


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


@dataclass(frozen=True, slots=True)
class _ConditionOutcome:
    evaluations: tuple[AttackEvaluation, ...]


@dataclass(frozen=True, slots=True)
class _TaskOutcome:
    task: EvalTask
    falsiq: _ConditionOutcome
    baseline: _ConditionOutcome


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


def _select_attacks(
    candidates: tuple[AttackCandidate, ...],
    selection: SelectorResponse,
) -> tuple[AttackCandidate, ...]:
    by_id = {candidate.attack_id: candidate for candidate in candidates}
    if len(by_id) != len(candidates):
        raise EvaluationProtocolError("attackers returned duplicate attack IDs")
    unknown = set(selection.selected_attack_ids).difference(by_id)
    if unknown:
        raise EvaluationProtocolError(f"selector referenced unknown attack {sorted(unknown)[0]}")

    def valid(values: tuple[AttackCandidate, ...]) -> bool:
        classes = [candidate.klass for candidate in values]
        return (
            (len(values) <= 1 or len(set(classes)) >= 2)
            and classes.count("prototype") <= 1
            and classes.count("omission") <= 2
        )

    def score(candidate: AttackCandidate) -> Fraction:
        costs = {"trivial": 1, "cheap": 3, "expensive": 9}
        return Fraction(
            len(candidate.settles) + len(candidate.silent_settles),
            costs[candidate.render_cost],
        )

    def digest(candidate: AttackCandidate) -> str:
        content = candidate.model_dump(mode="json")
        del content["attack_id"]
        canonical = json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return hashlib.sha256(canonical).hexdigest()

    digests = {candidate.attack_id: digest(candidate) for candidate in candidates}
    if len(set(digests.values())) != len(candidates):
        raise EvaluationProtocolError("attackers returned duplicate candidate content")
    feasible: list[tuple[AttackCandidate, ...]] = []
    for size in range(1, min(MAX_INTERACTIONS_PER_ROUND, len(candidates)) + 1):
        feasible.extend(values for values in combinations(candidates, size) if valid(values))
    if not feasible:
        expected: tuple[AttackCandidate, ...] = ()
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
            key=lambda values: tuple(sorted(digests[item.attack_id] for item in values)),
        )
        expected = tuple(
            sorted(chosen, key=lambda item: (-score(item), digests[item.attack_id]))
        )
    expected_ids = [candidate.attack_id for candidate in expected]
    if selection.selected_attack_ids != expected_ids:
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
        AttackEvaluation(
            interaction.interaction_id,
            round=interaction.round,
            requirement_ids=frozenset(by_mapping[interaction.interaction_id].requirement_ids),
            amended=verdicts.get(interaction.interaction_id) == "amend",
            verdict=cast(Any, verdicts.get(interaction.interaction_id)),
        )
        for interaction in interactions
    )
    return _ConditionOutcome(evaluations)


def _run_falsiq(task: EvalTask, runtime: EvaluationAgentRuntime) -> _ConditionOutcome:
    prior_rulings: list[PublicRuling] = []
    interactions: list[ScoringInteraction] = []
    seen_attack_ids: set[str] = set()
    interaction_limit = task.annoyance_budget * MAX_INTERACTIONS_PER_ROUND
    for round_number in range(1, task.annoyance_budget + 1):
        payload = AttackerPayload(
            task=task.public_projection(),
            round=round_number,
            prior_rulings=prior_rulings,
        )
        with ThreadPoolExecutor(max_workers=len(ATTACKER_ROLES)) as executor:
            futures = [
                executor.submit(
                    _invoke,
                    runtime,
                    role,
                    _request_id(task.task_id, "f", role, f"r{round_number}"),
                    payload,
                    AttackerResponse,
                )
                for role in ATTACKER_ROLES
            ]
            attacker_responses = [future.result() for future in futures]
        candidates: list[AttackCandidate] = []
        for role, response in zip(ATTACKER_ROLES, attacker_responses, strict=True):
            expected_class = role.removeprefix("attacker.")
            for attack in response.attacks:
                if attack.klass != expected_class:
                    raise EvaluationProtocolError(
                        f"{role} returned attack class {attack.klass}"
                    )
                if attack.attack_id in seen_attack_ids:
                    raise EvaluationProtocolError("attack IDs must be unique across rounds")
                seen_attack_ids.add(attack.attack_id)
                candidates.append(attack)
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
        selected = _select_attacks(tuple(candidates), selection)
        round_verdicts: list[str] = []
        for attack in selected:
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
                    attack=attack,
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
                raise EvaluationLeakageError(
                    f"principal leaked hidden requirement {leaks[0]}"
                )
            option_keys = {option.key for option in attack.artifact.options}
            if ruling.choice is not None and ruling.choice not in option_keys:
                raise EvaluationProtocolError("principal chose an option absent from the attack")
            public_ruling = PublicRuling(
                attack_id=attack.attack_id,
                round=round_number,
                verdict=ruling.verdict,
                choice=ruling.choice,
                amendment_text=ruling.amendment_text,
            )
            prior_rulings.append(public_ruling)
            interactions.append(
                ScoringInteraction(
                    interaction_id=attack.attack_id,
                    round=round_number,
                    artifact=attack.artifact,
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
    return _score_interactions(
        task,
        runtime,
        condition="falsiq",
        interactions=tuple(interactions),
        verdicts=verdicts,
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
    return _score_interactions(
        task,
        runtime,
        condition="baseline",
        interactions=tuple(interactions),
        verdicts={},
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
            _all_intended_round_rate(outcome.evaluations)
            if condition == "falsiq"
            else None
        ),
    )


def _all_intended_round_rate(
    evaluations: tuple[AttackEvaluation, ...],
) -> float:
    """Flag sycophantic Falsiq rounds; baseline interactions have no verdicts."""

    flags = _all_intended_round_flags(evaluations)
    if not flags:
        return 0.0
    return sum(flags) / len(flags)


def _all_intended_round_flags(
    evaluations: tuple[AttackEvaluation, ...],
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
                for attack in result.evaluations
                if attack.round <= round_number
                for requirement_id in attack.requirement_ids
            }
            elicited_weight += sum(weights[requirement_id] for requirement_id in elicited)
        return None if total_weight == 0 else elicited_weight / total_weight

    evaluations = tuple(
        evaluation for _, result in pairs for evaluation in result.evaluations
    )
    costs = [interaction_cost(result.evaluations) for _, result in pairs]
    control_costs = [
        interaction_cost(result.evaluations)
        for task, result in pairs
        if task.stratum == "control"
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
                / sum(
                    len(_all_intended_round_flags(result.evaluations))
                    for _, result in pairs
                )
            )
            if condition == "falsiq" and any(result.evaluations for _, result in pairs)
            else (0.0 if condition == "falsiq" else None)
        ),
        average_interaction_cost=fmean(costs),
        control_interaction_average=fmean(control_costs) if control_costs else 0.0,
    )


def run_evaluation(
    tasks: Sequence[EvalTask],
    *,
    runtime: EvaluationAgentRuntime,
) -> EvaluationReport:
    """Run Falsiq and a same-maximum-budget naive baseline for each task."""

    task_tuple = tuple(tasks)
    if not task_tuple:
        raise ValueError("evaluation requires at least one task")
    task_ids = [task.task_id for task in task_tuple]
    if len(task_ids) != len(set(task_ids)):
        raise ValueError("duplicate task ID in evaluation input")
    outcomes = tuple(
        _TaskOutcome(
            task=task,
            falsiq=_run_falsiq(task, runtime),
            baseline=_run_baseline(task, runtime),
        )
        for task in task_tuple
    )
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
                "baseline_recall_at_round_1": _format_number(
                    task.baseline.recall_at_round_1
                ),
                "baseline_recall_at_round_2": _format_number(
                    task.baseline.recall_at_round_2
                ),
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="falsiq-eval",
        description="Run the replay-only Falsiq elicitation evaluation.",
    )
    parser.add_argument(
        "--task",
        dest="tasks",
        action="append",
        required=True,
        type=Path,
        metavar="PATH",
        help="strict hidden-intent task JSON; repeat for multiple tasks",
    )
    parser.add_argument("--recordings", required=True, type=Path, metavar="DIR")
    parser.add_argument("--private-run-dir", required=True, type=Path, metavar="DIR")
    parser.add_argument("--reports", required=True, type=Path, metavar="DIR")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--timeout", type=float, default=120.0, metavar="SECONDS")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        tasks = tuple(load_task(path) for path in arguments.tasks)
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
    "build_parser",
    "main",
    "run_evaluation",
    "validate_role_payload",
    "validate_role_response",
    "write_reports",
]
