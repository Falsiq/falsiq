from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from falsiq.agent_runtime import AgentRequest, AgentResponse, AgentTranscript, write_transcript
from falsiq.benchmark import EvalTask, load_task
from falsiq.evaluation import (
    AGENT_ROLES,
    AgentRuntime,
    EvaluationLeakageError,
    EvaluationProtocolError,
    run_evaluation,
    validate_role_payload,
    validate_role_response,
    write_reports,
)

FIXTURES = Path(__file__).parent / "fixtures" / "eval"
ATTACKER_ROLES = tuple(role for role in AGENT_ROLES if role.startswith("attacker."))


class ScriptedRuntime:
    """Deterministic fixture agent that can also emit replay recordings."""

    def __init__(self, *, recording_dir: Path | None = None, leak: bool = False) -> None:
        self.recording_dir = recording_dir
        self.leak = leak
        self.calls: list[AgentRequest] = []

    def invoke(self, role: str, request_id: str, payload: BaseModel) -> BaseModel:
        validated = validate_role_payload(role, payload.model_dump(mode="json"))
        request = AgentRequest(
            role=role,
            request_id=request_id,
            payload=validated.model_dump(mode="json"),
        )
        self.calls.append(request)
        response = self._response(request)
        if self.recording_dir is not None:
            write_transcript(
                self.recording_dir / f"{request_id}.json",
                AgentTranscript(
                    request=request,
                    response=AgentResponse(
                        request_id=request_id,
                        response=response,
                    ),
                ),
            )
        from falsiq.evaluation import validate_role_response

        return validate_role_response(role, request_id, response)

    def _response(self, request: AgentRequest) -> dict[str, Any]:
        role = request.role
        payload = request.payload
        round_number = int(payload.get("round", 0))
        task_id = str(payload["task"]["task_id"])
        response: dict[str, Any]
        if role in ATTACKER_ROLES:
            attacks: list[dict[str, Any]] = []
            if task_id == "smoke_retry" and role == "attacker.boundary":
                attack_id = "a404" if round_number == 1 else "acap"
                attacks = [
                    {
                        "attack_id": attack_id,
                        "klass": "boundary",
                        "artifact": {
                            "type": "transcript",
                            "body": (
                                "404 is retried"
                                if round_number == 1
                                else "four requests occur"
                            ),
                            "options": [
                                {"key": "A", "body": "allow the rendered behavior"},
                                {"key": "B", "body": "reject the rendered behavior"},
                            ],
                        },
                        "settles": ["retry status" if round_number == 1 else "attempt cap"],
                        "silent_settles": [],
                        "hate_scenario": "duplicate traffic hides a persistent failure",
                        "render_cost": "trivial",
                    }
                ]
            elif task_id == "smoke_retry" and role == "attacker.omission" and round_number == 1:
                attacks = [
                    {
                        "attack_id": "alog",
                        "klass": "omission",
                        "artifact": {
                            "type": "scenario",
                            "body": "retry logging is absent",
                            "options": [
                                {"key": "A", "body": "log retries"},
                                {"key": "B", "body": "do not log retries"},
                            ],
                        },
                        "settles": ["retry logging"],
                        "silent_settles": ["retry logging"],
                        "hate_scenario": "operators cannot diagnose latency",
                        "render_cost": "trivial",
                    }
                ]
            response = {"request_id": request.request_id, "attacks": attacks}
        elif role == "selector":
            selected = sorted(
                payload["candidates"],
                key=lambda item: -(
                    len(item["settles"]) + len(item["silent_settles"])
                ),
            )
            response = {
                "request_id": request.request_id,
                "selected_attack_ids": [item["attack_id"] for item in selected],
                "rationale": "select every bounded smoke candidate",
            }
        elif role == "principal":
            attack_id = str(payload["attack"]["attack_id"])
            if attack_id == "a404":
                amendment = (
                    "stop after three total attempts"
                    if self.leak
                    else None
                )
                response = {
                    "request_id": request.request_id,
                    "verdict": "amend" if self.leak else "forbidden",
                    "choice": None if self.leak else "A",
                    "amendment_text": amendment,
                    "implicated_requirement_ids": ["LR1"],
                }
            elif attack_id == "acap":
                response = {
                    "request_id": request.request_id,
                    "verdict": "amend",
                    "choice": None,
                    "amendment_text": "stop after three total attempts",
                    "implicated_requirement_ids": ["LR2"],
                }
            else:
                response = {
                    "request_id": request.request_id,
                    "verdict": "dont_care",
                    "choice": None,
                    "amendment_text": None,
                    "implicated_requirement_ids": [],
                }
        elif role == "naive_baseline":
            questions = []
            if task_id == "smoke_retry":
                questions = [
                    {"question_id": f"q{round_number}a", "text": "Which errors should retry?"},
                    {"question_id": f"q{round_number}b", "text": "Anything else?"},
                    {"question_id": f"q{round_number}c", "text": "Any preferences?"},
                ]
            response = {"request_id": request.request_id, "questions": questions}
        elif role == "baseline_principal":
            question_id = str(payload["question"]["question_id"])
            targeted = question_id == "q1a"
            response = {
                "request_id": request.request_id,
                "answer": (
                    "retry server failures but never client errors"
                    if targeted
                    else "Please ask about a specific behavior."
                ),
                "implicated_requirement_ids": ["LR1"] if targeted else [],
            }
        elif role == "scorer":
            mappings = []
            waste_ids = []
            for interaction in payload["interactions"]:
                interaction_id = str(interaction["interaction_id"])
                requirement_ids: list[str] = []
                if interaction_id in {"a404", "q1a"}:
                    requirement_ids = ["LR1"]
                elif interaction_id == "acap":
                    requirement_ids = ["LR2"]
                else:
                    waste_ids.append(interaction_id)
                mappings.append(
                    {
                        "interaction_id": interaction_id,
                        "requirement_ids": requirement_ids,
                        "rationale": "deterministic smoke mapping",
                    }
                )
            response = {
                "request_id": request.request_id,
                "mappings": mappings,
                "waste_interaction_ids": waste_ids,
                "leaked_requirement_ids": [],
                "rationale": "offline fixture scorer",
            }
        else:  # pragma: no cover - catches an incomplete fixture immediately
            raise AssertionError(f"unexpected role: {role}")
        return response


@pytest.fixture
def smoke_task() -> EvalTask:
    return load_task(FIXTURES / "smoke_task.json")


def test_role_payload_allowlists_keep_hidden_data_out_of_public_agents(
    smoke_task: EvalTask,
) -> None:
    runtime = ScriptedRuntime()

    run_evaluation((smoke_task,), runtime=runtime)

    hidden_roles = {"principal", "baseline_principal", "scorer"}
    for request in runtime.calls:
        rendered = json.dumps(request.payload, sort_keys=True)
        if request.role in hidden_roles:
            assert "latent_requirements" in rendered
        else:
            assert "latent_requirements" not in rendered

    public_payload = next(
        request.payload for request in runtime.calls if request.role == "attacker.boundary"
    )
    with pytest.raises(ValidationError):
        validate_role_payload("attacker.boundary", {**public_payload, "hidden_spec": []})


def test_evaluation_runs_both_conditions_with_equal_round_budget_and_metrics(
    smoke_task: EvalTask,
) -> None:
    runtime = ScriptedRuntime()

    report = run_evaluation((smoke_task,), runtime=runtime)

    task = report.tasks[0]
    assert task.task_id == "smoke_retry"
    assert task.falsiq.recall_at_round_1 == pytest.approx(0.5)
    assert task.falsiq.recall_at_round_2 == pytest.approx(1.0)
    assert task.falsiq.interaction_cost == 3
    assert task.falsiq.waste_rate == pytest.approx(1 / 3)
    assert task.falsiq.licensed_discretion_rate == pytest.approx(1 / 3)
    assert task.baseline.recall_at_round_1 == pytest.approx(0.5)
    assert task.baseline.recall_at_round_2 == pytest.approx(0.5)
    assert task.baseline.interaction_cost == 6
    assert task.falsiq.all_intended_round_rate == 0.0
    assert task.baseline.all_intended_round_rate is None
    assert report.aggregate.falsiq.recall_at_round_2 == pytest.approx(1.0)
    assert report.aggregate.baseline.recall_at_round_2 == pytest.approx(0.5)

    falsiq_rounds = {
        int(request.payload["round"])
        for request in runtime.calls
        if request.role.startswith("attacker.")
    }
    baseline_rounds = {
        int(request.payload["round"])
        for request in runtime.calls
        if request.role == "naive_baseline"
    }
    assert falsiq_rounds == baseline_rounds == {1, 2}


def test_principal_leak_aborts_before_a_public_report_can_be_created(
    smoke_task: EvalTask,
) -> None:
    runtime = ScriptedRuntime(leak=True)

    with pytest.raises(EvaluationLeakageError, match="principal leaked hidden requirement LR2"):
        run_evaluation((smoke_task,), runtime=runtime)


def test_scorer_seeded_leak_fails_the_run(smoke_task: EvalTask) -> None:
    class LeakingScorerRuntime(ScriptedRuntime):
        def _response(self, request: AgentRequest) -> dict[str, Any]:
            response = super()._response(request)
            if request.role == "scorer" and request.payload["condition"] == "falsiq":
                response["leaked_requirement_ids"] = ["LR2"]
            return response

    with pytest.raises(EvaluationLeakageError, match="scorer detected principal leak"):
        run_evaluation((smoke_task,), runtime=LeakingScorerRuntime())


def test_reports_are_deterministic_machine_readable_and_redacted(
    tmp_path: Path, smoke_task: EvalTask
) -> None:
    report = run_evaluation((smoke_task,), runtime=ScriptedRuntime())

    paths = write_reports(report, tmp_path / "reports")
    first = {name: path.read_bytes() for name, path in paths.items()}
    paths = write_reports(report, tmp_path / "reports")
    second = {name: path.read_bytes() for name, path in paths.items()}

    assert first == second
    parsed = json.loads(first["json"])
    assert parsed["tasks"][0]["task_id"] == "smoke_retry"
    rows = list(csv.DictReader(first["csv"].decode().splitlines()))
    assert rows[0]["task_id"] == "smoke_retry"
    assert "Falsiq offline evaluation" in first["markdown"].decode()
    rendered = b"\n".join(first.values()).decode()
    assert smoke_task.vague_prompt not in rendered
    for requirement in smoke_task.latent_requirements:
        assert requirement.text not in rendered
        assert requirement.discriminator not in rendered


def test_replay_runtime_captures_private_transcripts_and_resumes_without_recordings(
    tmp_path: Path, smoke_task: EvalTask
) -> None:
    recordings = tmp_path / "recordings"
    expected = run_evaluation(
        (smoke_task,), runtime=ScriptedRuntime(recording_dir=recordings)
    )
    transcripts = tmp_path / "private" / "transcripts"
    runtime = AgentRuntime(recordings, transcripts)

    replayed = run_evaluation((smoke_task,), runtime=runtime)

    assert replayed == expected
    captured = sorted(transcripts.glob("*.json"))
    assert captured
    assert all(path.stat().st_mode & 0o077 == 0 for path in captured)

    for recording in recordings.glob("*.json"):
        recording.unlink()
    resumed = run_evaluation(
        (smoke_task,),
        runtime=AgentRuntime(recordings, transcripts, resume=True),
    )
    assert resumed == replayed


def test_selector_cannot_reference_an_unknown_candidate(smoke_task: EvalTask) -> None:
    class BadSelectorRuntime(ScriptedRuntime):
        def _response(self, request: AgentRequest) -> dict[str, Any]:
            if request.role == "selector":
                return {
                    "request_id": request.request_id,
                    "selected_attack_ids": ["unknown"],
                    "rationale": "invalid selection",
                }
            return super()._response(request)

    with pytest.raises(EvaluationProtocolError, match="unknown attack"):
        run_evaluation((smoke_task,), runtime=BadSelectorRuntime())


def test_round_two_is_gated_when_round_one_does_not_move_intent(
    smoke_task: EvalTask,
) -> None:
    class SettledRuntime(ScriptedRuntime):
        def _response(self, request: AgentRequest) -> dict[str, Any]:
            response = super()._response(request)
            if request.role == "principal" and request.payload["attack"]["attack_id"] == "a404":
                response = {
                    "request_id": request.request_id,
                    "verdict": "intended",
                    "choice": "B",
                    "amendment_text": None,
                    "implicated_requirement_ids": ["LR1"],
                }
            return response

    runtime = SettledRuntime()

    report = run_evaluation((smoke_task,), runtime=runtime)

    assert report.tasks[0].falsiq.recall_at_round_2 == pytest.approx(0.5)
    falsiq_rounds = {
        int(request.payload["round"])
        for request in runtime.calls
        if request.role.startswith("attacker.")
    }
    assert falsiq_rounds == {1}


def test_all_intended_rounds_are_flagged_as_a_sycophancy_signal(
    smoke_task: EvalTask,
) -> None:
    class AllIntendedRuntime(ScriptedRuntime):
        def _response(self, request: AgentRequest) -> dict[str, Any]:
            response = super()._response(request)
            if request.role == "principal":
                response = {
                    "request_id": request.request_id,
                    "verdict": "intended",
                    "choice": "B",
                    "amendment_text": None,
                    "implicated_requirement_ids": (
                        ["LR1"]
                        if request.payload["attack"]["attack_id"] == "a404"
                        else []
                    ),
                }
            return response

    report = run_evaluation((smoke_task,), runtime=AllIntendedRuntime())

    assert report.tasks[0].falsiq.all_intended_round_rate == 1.0
    assert report.aggregate.falsiq.all_intended_round_rate == 1.0


def test_unambiguous_control_skips_collision_and_reports_zero_control_cost(
    smoke_task: EvalTask,
) -> None:
    payload = smoke_task.model_dump(mode="python")
    payload.update(
        task_id="control_clear",
        stratum="control",
        latent_requirements=[],
    )
    control = EvalTask.model_validate(payload)
    runtime = ScriptedRuntime()

    report = run_evaluation((control,), runtime=runtime)

    task = report.tasks[0]
    assert task.falsiq.interaction_cost == 0
    assert task.falsiq.recall_at_round_2 is None
    assert task.baseline.interaction_cost == 0
    assert report.aggregate.falsiq.control_interaction_average == 0.0
    assert not any(request.role in {"selector", "principal", "scorer"} for request in runtime.calls)


def test_duplicate_task_ids_are_rejected_before_agents_run(smoke_task: EvalTask) -> None:
    runtime = ScriptedRuntime()

    with pytest.raises(ValueError, match="duplicate task ID"):
        run_evaluation((smoke_task, smoke_task), runtime=runtime)

    assert runtime.calls == []


def test_role_response_contract_rejects_unknown_fields() -> None:
    with pytest.raises(EvaluationProtocolError, match="role-specific schema"):
        validate_role_response(
            "naive_baseline",
            "request-1",
            {"request_id": "request-1", "questions": [], "hidden": "not allowed"},
        )


def test_replay_runtime_rejects_pathlike_request_ids_before_filesystem_access(
    tmp_path: Path, smoke_task: EvalTask
) -> None:
    payload = validate_role_payload(
        "attacker.boundary",
        {
            "task": smoke_task.public_projection().model_dump(mode="json"),
            "round": 1,
            "prior_rulings": [],
        },
    )
    runtime = AgentRuntime(tmp_path / "recordings", tmp_path / "transcripts")

    with pytest.raises(ValueError, match="safe stable token"):
        runtime.invoke("attacker.boundary", "../escape", payload)

    assert not (tmp_path / "escape.json").exists()
