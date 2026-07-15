from __future__ import annotations

import csv
import json
import stat
from pathlib import Path
from typing import Any, Literal

import pytest
from pydantic import BaseModel, ValidationError

import falsiq.evaluation as evaluation_module
from falsiq.agent_runtime import AgentRequest, AgentResponse, AgentTranscript, write_transcript
from falsiq.benchmark import EvalTask, load_task
from falsiq.evaluation import (
    AGENT_ROLES,
    AgentRuntime,
    EvaluationArtifact,
    EvaluationLeakageError,
    EvaluationProtocolError,
    EvaluationRuntimeError,
    run_conformance_evaluation,
    run_evaluation,
    validate_role_payload,
    validate_role_response,
    write_conformance_reports,
    write_reports,
)
from falsiq.evaluation import (
    ArtifactOption as EvaluationArtifactOption,
)
from falsiq.evaluation import (
    AttackCandidate as EvaluationAttackCandidate,
)
from falsiq.evaluation import TestResult as EvaluationTestResult

FIXTURES = Path(__file__).parent / "fixtures" / "eval"
ATTACKER_ROLES = tuple(role for role in AGENT_ROLES if role.startswith("attacker."))


def evaluation_artifact(
    *, artifact_type: Literal["scenario", "transcript"] = "scenario", words: int = 1
) -> EvaluationArtifact:
    return EvaluationArtifact(
        type=artifact_type,
        body="word " * words,
        options=[
            EvaluationArtifactOption(key="A", body="accept it"),
            EvaluationArtifactOption(key="B", body="reject it"),
        ],
    )


def test_evaluation_consequence_contract_enforces_the_narrative_budget() -> None:
    candidate = EvaluationAttackCandidate(
        attack_id="downstream",
        klass="consequence",
        artifact=evaluation_artifact(words=150),
        settles=["operational consequence"],
        hate_scenario="month-later maintenance becomes unsafe",
        render_cost="trivial",
    )
    assert len(candidate.artifact.body.split()) == 150

    with pytest.raises(ValidationError, match="consequence"):
        EvaluationAttackCandidate(
            attack_id="too-long",
            klass="consequence",
            artifact=evaluation_artifact(words=151),
            settles=["operational consequence"],
            hate_scenario="month-later maintenance becomes unsafe",
            render_cost="trivial",
        )
    with pytest.raises(ValidationError, match="consequence"):
        EvaluationAttackCandidate(
            attack_id="wrong-kind",
            klass="consequence",
            artifact=evaluation_artifact(artifact_type="transcript"),
            settles=["operational consequence"],
            hate_scenario="month-later maintenance becomes unsafe",
            render_cost="trivial",
        )


def test_replay_runtime_rejects_a_symlinked_private_transcript_directory(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o755)
    outside.chmod(0o755)
    transcript_link = tmp_path / "transcripts"
    transcript_link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(EvaluationRuntimeError, match="transcript directory"):
        AgentRuntime(tmp_path / "recordings", transcript_link)

    assert stat.S_IMODE(outside.stat().st_mode) != 0o700


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
                                "404 is retried" if round_number == 1 else "four requests occur"
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
                key=lambda item: -(len(item["settles"]) + len(item["silent_settles"])),
            )
            response = {
                "request_id": request.request_id,
                "selected_attack_ids": [item["attack_id"] for item in selected],
                "rationale": "select every bounded smoke candidate",
            }
        elif role == "principal":
            attack_id = str(payload["attack"]["attack_id"])
            if attack_id == "a404":
                amendment = "stop after three total attempts" if self.leak else None
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
        elif role == "builder":
            instructions = str(payload["instructions"])
            if "# Falsiq implementation brief" in instructions:
                implementation = "falsiq"
            elif "# Clarification transcript" in instructions:
                implementation = "baseline"
            else:
                implementation = "vague"
            response = {
                "request_id": request.request_id,
                "summary": "materialize the deterministic smoke implementation",
                "changed_paths": ["implementation.txt"],
                "files": [{"path": "implementation.txt", "content": implementation + "\n"}],
                "deleted_paths": [],
                "visible_test_result": {
                    "status": "passed",
                    "summary": "visible smoke checks passed",
                },
            }
        elif role == "judge":
            changed = payload["changed_files"]
            implementation = str(changed[0]["content"]).strip()
            scores = {"vague": (0.0, 0.0), "baseline": (1.0, 0.0), "falsiq": (1.0, 1.0)}
            lr1, lr2 = scores[implementation]
            response = {
                "request_id": request.request_id,
                "requirement_scores": [
                    {"requirement_id": "LR1", "score": lr1, "rationale": "fixture evidence"},
                    {"requirement_id": "LR2", "score": lr2, "rationale": "fixture evidence"},
                ],
                "overall_rationale": "condition-blind fixture judgment",
                "evidence_gaps": [],
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
    expected = run_evaluation((smoke_task,), runtime=ScriptedRuntime(recording_dir=recordings))
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
                        ["LR1"] if request.payload["attack"]["attack_id"] == "a404" else []
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


@pytest.mark.parametrize(
    "path",
    [
        ".Git/config",
        ".FALSIQ/ledger.jsonl",
        "NUL",
        "reports/con.txt",
        "output.txt:secret",
        "trailing.",
        "trailing ",
    ],
)
def test_builder_response_rejects_cross_platform_reserved_paths(path: str) -> None:
    response = {
        "request_id": "request-1",
        "summary": "attempted update",
        "changed_paths": [path],
        "files": [{"path": path, "content": "unsafe"}],
        "deleted_paths": [],
        "visible_test_result": {"status": "not_run", "summary": "not reached"},
    }

    with pytest.raises(EvaluationProtocolError, match="role-specific schema"):
        validate_role_response("builder", "request-1", response)


def test_builder_response_rejects_case_colliding_paths() -> None:
    response = {
        "request_id": "request-1",
        "summary": "attempted updates",
        "changed_paths": ["README.md", "readme.md"],
        "files": [
            {"path": "README.md", "content": "first"},
            {"path": "readme.md", "content": "second"},
        ],
        "deleted_paths": [],
        "visible_test_result": {"status": "not_run", "summary": "not reached"},
    }

    with pytest.raises(EvaluationProtocolError, match="role-specific schema"):
        validate_role_response("builder", "request-1", response)


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


def test_three_condition_builds_are_isolated_and_judged_blindly(
    tmp_path: Path, smoke_task: EvalTask
) -> None:
    runtime = ScriptedRuntime()
    hidden_events: list[str] = []

    def hidden_tests(task: EvalTask, workspace: Path) -> EvaluationTestResult:
        assert task.task_id == "smoke_retry"
        assert sum(request.role == "builder" for request in runtime.calls) == 3
        implementation = (workspace / "implementation.txt").read_text().strip()
        hidden_events.append(implementation)
        return EvaluationTestResult(
            status="passed" if implementation == "falsiq" else "failed",
            summary="redacted hidden smoke result",
        )

    report = run_conformance_evaluation(
        (smoke_task,),
        runtime=runtime,
        visible_fixture_root=Path(__file__).parents[1],
        workspace_root=tmp_path / "workspaces",
        hidden_test_runner=hidden_tests,
        seed=17,
        bootstrap_samples=500,
    )

    task = report.tasks[0]
    assert task.vague_conformance == 0.0
    assert task.baseline_conformance == 50.0
    assert task.falsiq_conformance == 100.0
    assert report.falsiq_vs_vague.mean_delta == 100.0
    assert report.falsiq_vs_baseline.mean_delta == 50.0
    assert report.falsiq_vs_baseline.statistically_visible is True
    assert sorted(hidden_events) == ["baseline", "falsiq", "vague"]

    builder_calls = [request for request in runtime.calls if request.role == "builder"]
    assert len({request.payload["workspace"] for request in builder_calls}) == 3
    assert all("latent_requirements" not in request.payload for request in builder_calls)
    judge_calls = [request for request in runtime.calls if request.role == "judge"]
    assert len(judge_calls) == 3
    assert [request.payload["candidate_id"] for request in judge_calls] == [
        "candidate-1",
        "candidate-3",
        "candidate-2",
    ]
    assert all("condition" not in request.payload for request in judge_calls)
    assert all(
        str(request.payload["candidate_id"]).startswith("candidate-") for request in judge_calls
    )
    assert not (FIXTURES / "workspace" / "implementation.txt").exists()


def test_falsiq_builder_handoff_preserves_active_decision_evidence(
    tmp_path: Path, smoke_task: EvalTask
) -> None:
    def capture_handoff(workspace_root: Path) -> str:
        runtime = ScriptedRuntime()
        run_conformance_evaluation(
            (smoke_task,),
            runtime=runtime,
            visible_fixture_root=Path(__file__).parents[1],
            workspace_root=workspace_root,
            hidden_test_runner=lambda task, workspace: EvaluationTestResult(
                status="passed", summary="redacted hidden result"
            ),
            seed=17,
            bootstrap_samples=10,
        )
        handoffs = [
            str(request.payload["instructions"])
            for request in runtime.calls
            if request.role == "builder"
            and str(request.payload["instructions"]).startswith("# Falsiq implementation brief")
        ]
        assert len(handoffs) == 1
        return handoffs[0]

    handoff = capture_handoff(tmp_path / "first-workspaces")

    assert handoff == capture_handoff(tmp_path / "second-workspaces")
    assert "## Original request context (verbatim)" in handoff
    assert smoke_task.vague_prompt in handoff
    assert "## Intent (verbatim)" in handoff
    assert "### Active amendment from attack `acap`" in handoff
    assert "stop after three total attempts" in handoff
    assert "### Superseded initial intent" not in handoff

    assert "| `a404` | 1 | boundary | forbidden | `A` |" in handoff
    assert "| `alog` | 1 | omission | dont_care | — |" in handoff
    assert "| `acap` | 2 | boundary | amend | — |" in handoff
    assert "### Attack `a404`" in handoff
    assert "- Settles:" in handoff
    assert "retry status" in handoff
    assert "#### Artifact (`transcript`)" in handoff
    assert "404 is retried" in handoff
    assert "##### Choice `A`" in handoff
    assert "allow the rendered behavior" in handoff
    assert "##### Choice `B`" in handoff
    assert "reject the rendered behavior" in handoff
    assert "#### Hate scenario" in handoff
    assert "duplicate traffic hides a persistent failure" in handoff
    assert "- Verdict: `forbidden`" in handoff
    assert "- Choice: `A`" in handoff
    assert "retry logging is absent" in handoff
    assert "operators cannot diagnose latency" in handoff
    assert "- Verdict: `dont_care`" in handoff
    assert "four requests occur" in handoff
    assert "attempt cap" in handoff
    assert "- Verdict: `amend`" in handoff

    assert "## Forbidden acceptance-test obligations" in handoff
    forbidden_section = handoff.split("## Forbidden acceptance-test obligations\n", 1)[1].split(
        "## Agent discretion\n", 1
    )[0]
    assert "Acceptance tests must reject choice `A`" in forbidden_section
    assert "allow the rendered behavior" in forbidden_section
    assert "`alog`" not in forbidden_section
    assert "## Agent discretion" in handoff
    discretion_section = handoff.split("## Agent discretion\n", 1)[1]
    assert "retry logging" in discretion_section
    assert "licensed by `dont_care` ruling for attack `alog`" in discretion_section
    assert "retry status" not in discretion_section
    assert "attempt cap" not in discretion_section

    assert "latent_requirements" not in handoff
    assert "LR1" not in handoff
    for requirement in smoke_task.latent_requirements:
        assert requirement.discriminator not in handoff


def test_falsiq_handoff_marks_only_the_latest_amendment_as_active(
    smoke_task: EvalTask,
) -> None:
    def amendment(attack_id: str, text: str, round_number: int) -> Any:
        attack = EvaluationAttackCandidate(
            attack_id=attack_id,
            klass="boundary",
            artifact=evaluation_artifact(artifact_type="transcript"),
            settles=["retry policy"],
            hate_scenario="the retry behavior surprises an operator",
            render_cost="trivial",
        )
        ruling = evaluation_module.PublicRuling(
            attack_id=attack_id,
            round=round_number,
            verdict="amend",
            amendment_text=text,
        )
        return evaluation_module._FalsiqDecision(attack=attack, ruling=ruling)

    handoff = evaluation_module._render_falsiq_handoff(
        smoke_task.public_projection(),
        [
            amendment("first-amendment", "first verbatim amendment", 1),
            amendment("latest-amendment", "latest verbatim amendment", 2),
        ],
    )

    active_intent = handoff.split("## Intent (verbatim)\n", 1)[1].split("## Rulings\n", 1)[0]
    assert "### Active amendment from attack `latest-amendment`" in active_intent
    assert "latest verbatim amendment" in active_intent
    assert "first verbatim amendment" not in active_intent
    assert smoke_task.vague_prompt not in active_intent
    assert "### Amendment ruling for attack `first-amendment` (verbatim; superseded)" in handoff
    assert "### Amendment ruling for attack `latest-amendment` (verbatim; active)" in handoff


def test_conformance_reports_are_redacted_and_reproducible(
    tmp_path: Path, smoke_task: EvalTask
) -> None:
    def hidden_tests(task: EvalTask, workspace: Path) -> EvaluationTestResult:
        return EvaluationTestResult(status="passed", summary="hidden detail")

    first = run_conformance_evaluation(
        (smoke_task,),
        runtime=ScriptedRuntime(),
        visible_fixture_root=Path(__file__).parents[1],
        workspace_root=tmp_path / "workspaces",
        hidden_test_runner=hidden_tests,
        seed=23,
        bootstrap_samples=250,
    )
    second = run_conformance_evaluation(
        (smoke_task,),
        runtime=ScriptedRuntime(),
        visible_fixture_root=Path(__file__).parents[1],
        workspace_root=tmp_path / "workspaces",
        hidden_test_runner=hidden_tests,
        seed=23,
        bootstrap_samples=250,
    )

    assert first == second
    paths = write_conformance_reports(first, tmp_path / "reports")
    rendered = b"\n".join(path.read_bytes() for path in paths.values()).decode()
    assert "smoke_retry" in rendered
    assert smoke_task.vague_prompt not in rendered
    assert all(requirement.text not in rendered for requirement in smoke_task.latent_requirements)
    assert "hidden detail" not in rendered


def test_builder_and_judge_replay_is_resumable(tmp_path: Path, smoke_task: EvalTask) -> None:
    recordings = tmp_path / "recordings"

    def hidden_tests(task: EvalTask, workspace: Path) -> EvaluationTestResult:
        implementation = (workspace / "implementation.txt").read_text().strip()
        return EvaluationTestResult(status="passed", summary=implementation)

    expected = run_conformance_evaluation(
        (smoke_task,),
        runtime=ScriptedRuntime(recording_dir=recordings),
        visible_fixture_root=Path(__file__).parents[1],
        workspace_root=tmp_path / "workspaces",
        hidden_test_runner=hidden_tests,
        seed=31,
        bootstrap_samples=100,
    )
    transcripts = tmp_path / "private" / "transcripts"
    replayed = run_conformance_evaluation(
        (smoke_task,),
        runtime=AgentRuntime(recordings, transcripts),
        visible_fixture_root=Path(__file__).parents[1],
        workspace_root=tmp_path / "workspaces",
        hidden_test_runner=hidden_tests,
        seed=31,
        bootstrap_samples=100,
    )
    assert replayed == expected

    for recording in recordings.glob("*.json"):
        recording.unlink()
    resumed = run_conformance_evaluation(
        (smoke_task,),
        runtime=AgentRuntime(recordings, transcripts, resume=True),
        visible_fixture_root=Path(__file__).parents[1],
        workspace_root=tmp_path / "workspaces",
        hidden_test_runner=hidden_tests,
        seed=31,
        bootstrap_samples=100,
    )
    assert resumed == expected


def test_visible_fixture_symlinks_are_rejected_before_any_builder_runs(
    tmp_path: Path, smoke_task: EvalTask
) -> None:
    visible_root = tmp_path / "visible"
    fixture = visible_root / "fixture"
    fixture.mkdir(parents=True)
    secret = tmp_path / "hidden-corpus"
    secret.mkdir()
    (secret / "requirements.json").write_text("hidden", encoding="utf-8")
    (fixture / "hidden-link").symlink_to(secret, target_is_directory=True)
    payload = smoke_task.model_dump(mode="python")
    payload["context"] = {"repo_fixture": "fixture", "notes": "visible only"}
    task = EvalTask.model_validate(payload)
    runtime = ScriptedRuntime()

    with pytest.raises(EvaluationRuntimeError, match="symbolic links"):
        run_conformance_evaluation(
            (task,),
            runtime=runtime,
            visible_fixture_root=visible_root,
            workspace_root=tmp_path / "workspaces",
            hidden_test_runner=lambda task, workspace: EvaluationTestResult(
                status="not_run", summary="not reached"
            ),
            seed=1,
            bootstrap_samples=10,
        )

    assert not any(request.role == "builder" for request in runtime.calls)


def test_preexisting_unmarked_workspace_root_is_never_deleted(
    tmp_path: Path, smoke_task: EvalTask
) -> None:
    workspace_root = tmp_path / "not-dedicated"
    workspace_root.mkdir()
    sentinel = workspace_root / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(EvaluationRuntimeError, match="dedicated"):
        run_conformance_evaluation(
            (smoke_task,),
            runtime=ScriptedRuntime(),
            visible_fixture_root=Path(__file__).parents[1],
            workspace_root=workspace_root,
            hidden_test_runner=lambda task, workspace: EvaluationTestResult(
                status="not_run", summary="not reached"
            ),
            seed=1,
            bootstrap_samples=10,
        )

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_builder_path_traversal_is_rejected_without_writing_outside_workspace(
    tmp_path: Path, smoke_task: EvalTask
) -> None:
    class EscapingBuilderRuntime(ScriptedRuntime):
        def _response(self, request: AgentRequest) -> dict[str, Any]:
            response = super()._response(request)
            if request.role == "builder":
                response["changed_paths"] = ["../escape.txt"]
                response["files"] = [{"path": "../escape.txt", "content": "bad"}]
            return response

    with pytest.raises(EvaluationProtocolError, match="role-specific schema"):
        run_conformance_evaluation(
            (smoke_task,),
            runtime=EscapingBuilderRuntime(),
            visible_fixture_root=Path(__file__).parents[1],
            workspace_root=tmp_path / "workspaces",
            hidden_test_runner=lambda task, workspace: EvaluationTestResult(
                status="not_run", summary="not reached"
            ),
            seed=1,
            bootstrap_samples=10,
        )

    assert not (tmp_path / "workspaces" / "smoke_retry" / "escape.txt").exists()


def test_judge_must_score_every_hidden_requirement(tmp_path: Path, smoke_task: EvalTask) -> None:
    class IncompleteJudgeRuntime(ScriptedRuntime):
        def _response(self, request: AgentRequest) -> dict[str, Any]:
            response = super()._response(request)
            if request.role == "judge":
                response["requirement_scores"] = response["requirement_scores"][:1]
            return response

    with pytest.raises(EvaluationProtocolError, match="every latent requirement"):
        run_conformance_evaluation(
            (smoke_task,),
            runtime=IncompleteJudgeRuntime(),
            visible_fixture_root=Path(__file__).parents[1],
            workspace_root=tmp_path / "workspaces",
            hidden_test_runner=lambda task, workspace: EvaluationTestResult(
                status="passed", summary="fixture hidden tests"
            ),
            seed=1,
            bootstrap_samples=10,
        )
