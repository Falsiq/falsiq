from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from falsiq.benchmark import (
    EvalTask,
    PrincipalRuling,
    canonical_task_hash,
    detect_principal_leaks,
    load_task,
)


def task_payload(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": 1,
        "task_id": "t017",
        "stratum": "synthetic",
        "vague_prompt": "add retry logic to the fetcher",
        "context": {"repo_fixture": "fixtures/fetcher", "notes": "HTTP client"},
        "latent_requirements": [
            {
                "id": "LR1",
                "text": "retry only network errors and 5xx responses",
                "discriminator": "a 404 response must not be retried",
                "severity": "rework",
            },
            {
                "id": "LR2",
                "text": "use at most three attempts",
                "discriminator": "a fourth request reveals the bug",
                "severity": "cosmetic",
            },
        ],
        "annoyance_budget": 2,
        "human_curated": True,
    }
    payload.update(updates)
    return payload


def test_task_schema_preserves_hidden_and_public_projections() -> None:
    task = EvalTask.model_validate(task_payload())

    assert [requirement.id for requirement in task.latent_requirements] == ["LR1", "LR2"]
    public = task.public_projection()
    assert public.task_id == "t017"
    assert "latent_requirements" not in public.model_dump()
    assert public.context.repo_fixture == "fixtures/fetcher"


@pytest.mark.parametrize(
    "updates",
    [
        {"task_id": "../escape"},
        {"vague_prompt": " "},
        {"annoyance_budget": 0},
        {"annoyance_budget": 3},
        {"context": {"repo_fixture": "../secret"}},
        {
            "latent_requirements": [
                {
                    "id": "LR1",
                    "text": "one",
                    "discriminator": "one probe",
                    "severity": "rework",
                },
                {
                    "id": "LR1",
                    "text": "two",
                    "discriminator": "two probe",
                    "severity": "cosmetic",
                },
            ]
        },
    ],
)
def test_task_rejects_invalid_or_unsafe_contracts(updates: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        EvalTask.model_validate(task_payload(**updates))


def test_controls_have_at_most_one_latent_requirement() -> None:
    with pytest.raises(ValidationError, match="control tasks"):
        EvalTask.model_validate(task_payload(stratum="control"))

    payload = task_payload(stratum="control", latent_requirements=[])
    assert EvalTask.model_validate(payload).latent_requirements == []


def test_mined_tasks_require_source_provenance() -> None:
    with pytest.raises(ValidationError, match="mined tasks require provenance"):
        EvalTask.model_validate(task_payload(stratum="mined"))

    task = EvalTask.model_validate(
        task_payload(
            stratum="mined",
            provenance={
                "source_urls": ["https://github.com/example/project/issues/1"],
                "source_revision": "abc123",
                "license": "MIT",
                "curator_notes": "Review and follow-up established the hidden behavior.",
            },
        )
    )
    assert task.provenance is not None


def test_load_task_forbids_unknown_fields(tmp_path) -> None:
    path = tmp_path / "task.json"
    path.write_text(json.dumps(task_payload(unexpected=True)))

    with pytest.raises(ValidationError):
        load_task(path)


def test_canonical_task_hash_is_salted_stable_and_content_sensitive() -> None:
    task = EvalTask.model_validate(task_payload())

    first = canonical_task_hash(task, salt=b"private salt")
    assert first == canonical_task_hash(task, salt=b"private salt")
    assert first != canonical_task_hash(task, salt=b"different salt")
    changed = EvalTask.model_validate(task_payload(vague_prompt="a changed prompt"))
    assert first != canonical_task_hash(changed, salt=b"private salt")

    with pytest.raises(ValueError, match="salt must not be empty"):
        canonical_task_hash(task, salt=b"")


def test_principal_ruling_is_forced_choice_only() -> None:
    ruling = PrincipalRuling(
        request_id="req-1",
        verdict="intended",
        choice="A",
        implicated_requirement_ids=["LR1"],
    )
    assert ruling.choice == "A"

    with pytest.raises(ValidationError):
        PrincipalRuling(request_id="req-1", verdict="intended")
    with pytest.raises(ValidationError):
        PrincipalRuling(
            request_id="req-1",
            verdict="amend",
            choice="A",
            amendment_text="change it",
        )
    with pytest.raises(ValidationError):
        PrincipalRuling(request_id="req-1", verdict="amend")


def test_principal_leak_filter_flags_unimplicated_hidden_text() -> None:
    task = EvalTask.model_validate(task_payload())
    safe = PrincipalRuling(
        request_id="req-1",
        verdict="amend",
        amendment_text="retry only network errors and 5xx responses",
        implicated_requirement_ids=["LR1"],
    )
    leaking = PrincipalRuling(
        request_id="req-2",
        verdict="amend",
        amendment_text="Also use at most three attempts",
        implicated_requirement_ids=["LR1"],
    )

    assert detect_principal_leaks(task, safe) == ()
    assert detect_principal_leaks(task, leaking) == ("LR2",)


def test_principal_leak_filter_rejects_unknown_implicated_ids() -> None:
    task = EvalTask.model_validate(task_payload())
    response = PrincipalRuling(
        request_id="req-1",
        verdict="forbidden",
        choice="B",
        implicated_requirement_ids=["LR404"],
    )

    with pytest.raises(ValueError, match="unknown latent requirement"):
        detect_principal_leaks(task, response)
