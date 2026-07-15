from __future__ import annotations

from pathlib import Path

import pytest

AGENTS = Path(__file__).parents[1] / "agents"


@pytest.mark.parametrize(
    "name",
    [
        "principal",
        "scorer",
        "naive_baseline",
        "baseline_principal",
        "builder",
        "judge",
    ],
)
def test_eval_prompt_has_versioned_json_contract(name: str) -> None:
    prompt = (AGENTS / f"{name}.md").read_text(encoding="utf-8")

    assert prompt.startswith("---\n")
    assert "contract-version: 1" in prompt
    assert "Return only one JSON object" in prompt
    assert "Do not wrap it in Markdown" in prompt


def test_principal_only_rules_forced_choice_collisions() -> None:
    prompt = (AGENTS / "principal.md").read_text(encoding="utf-8")

    assert "give me something concrete to react to" in prompt
    assert "Never volunteer" in prompt
    assert "implicated_requirement_ids" in prompt


def test_baseline_is_specific_but_not_artificially_silenced() -> None:
    baseline = (AGENTS / "naive_baseline.md").read_text(encoding="utf-8")
    principal = (AGENTS / "baseline_principal.md").read_text(encoding="utf-8")

    assert "maximum of three" in baseline
    assert "what else" in principal
    assert "specifically implicates" in principal


def test_builder_never_receives_or_seeks_hidden_requirements() -> None:
    prompt = (AGENTS / "builder.md").read_text(encoding="utf-8")

    assert "latent_requirements" in prompt
    assert "Do not search parent directories" in prompt
    assert "condition label" in prompt


def test_judge_is_condition_blind_and_scores_each_requirement() -> None:
    prompt = (AGENTS / "judge.md").read_text(encoding="utf-8")

    assert "condition-blind" in prompt
    assert "0, 0.5, or 1" in prompt
    assert "requirement_scores" in prompt
