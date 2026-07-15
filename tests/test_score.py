from __future__ import annotations

import pytest

from falsiq.score import (
    AttackEvaluation,
    LatentRequirement,
    RequirementScore,
    interaction_cost,
    licensed_discretion_rate,
    paired_bootstrap_interval,
    severity_weighted_recall,
    waste_rate,
    weighted_conformance,
)

REQUIREMENTS = (
    LatentRequirement(id="LR1", severity="rework"),
    LatentRequirement(id="LR2", severity="rework"),
    LatentRequirement(id="LR3", severity="cosmetic"),
)


def test_recall_is_severity_weighted_and_cumulative_by_round() -> None:
    attacks = (
        AttackEvaluation("A1", round=1, requirement_ids=frozenset({"LR1"})),
        AttackEvaluation("A2", round=1),
        AttackEvaluation("A3", round=2, requirement_ids=frozenset({"LR3"})),
    )

    assert severity_weighted_recall(REQUIREMENTS, attacks, through_round=1) == pytest.approx(3 / 7)
    assert severity_weighted_recall(REQUIREMENTS, attacks, through_round=2) == pytest.approx(4 / 7)


def test_duplicate_mappings_count_each_requirement_once() -> None:
    attacks = (
        AttackEvaluation("A1", round=1, requirement_ids=frozenset({"LR1"})),
        AttackEvaluation("A2", round=2, requirement_ids=frozenset({"LR1"})),
    )

    assert severity_weighted_recall(REQUIREMENTS, attacks, through_round=2) == pytest.approx(3 / 7)


def test_controls_have_no_recall_denominator() -> None:
    assert severity_weighted_recall((), (), through_round=2) is None


def test_unknown_requirement_mapping_is_rejected() -> None:
    attacks = (AttackEvaluation("A1", round=1, requirement_ids=frozenset({"LR404"})),)

    with pytest.raises(ValueError, match="unknown latent requirement"):
        severity_weighted_recall(REQUIREMENTS, attacks, through_round=1)


def test_waste_discretion_and_interaction_metrics() -> None:
    attacks = (
        AttackEvaluation("A1", round=1, requirement_ids=frozenset({"LR1"})),
        AttackEvaluation("A2", round=1),
        AttackEvaluation("A3", round=1, amended=True),
        AttackEvaluation("A4", round=2, verdict="dont_care"),
    )

    assert waste_rate(attacks) == pytest.approx(0.5)
    assert licensed_discretion_rate(attacks) == pytest.approx(0.25)
    assert interaction_cost(attacks) == 4
    assert waste_rate(()) == 0.0
    assert licensed_discretion_rate(()) == 0.0


def test_conformance_is_severity_weighted_on_a_100_point_scale() -> None:
    scores = (
        RequirementScore("LR1", 1.0),
        RequirementScore("LR2", 0.5),
        RequirementScore("LR3", 0.0),
    )

    assert weighted_conformance(REQUIREMENTS, scores) == pytest.approx(450 / 7)
    assert weighted_conformance((), ()) is None


def test_conformance_rejects_duplicates_unknowns_and_invalid_scores() -> None:
    with pytest.raises(ValueError, match="duplicate requirement score"):
        weighted_conformance(
            REQUIREMENTS,
            (RequirementScore("LR1", 1.0), RequirementScore("LR1", 0.5)),
        )
    with pytest.raises(ValueError, match="unknown latent requirement"):
        weighted_conformance(REQUIREMENTS, (RequirementScore("LR404", 1.0),))
    with pytest.raises(ValueError, match="0, 0.5, or 1"):
        RequirementScore("LR1", 0.7)


def test_paired_bootstrap_is_reproducible_and_preserves_pairing() -> None:
    candidate = (90.0, 80.0, 70.0, 60.0)
    baseline = (50.0, 45.0, 40.0, 35.0)

    first = paired_bootstrap_interval(candidate, baseline, seed=17, samples=2_000)
    second = paired_bootstrap_interval(candidate, baseline, seed=17, samples=2_000)

    assert first == second
    assert first.mean_delta == pytest.approx(32.5)
    assert first.low > 0
    assert first.high >= first.low


@pytest.mark.parametrize(
    ("candidate", "baseline", "match"),
    [
        ((), (), "at least one pair"),
        ((1.0,), (1.0, 2.0), "same length"),
    ],
)
def test_paired_bootstrap_rejects_invalid_inputs(candidate, baseline, match) -> None:
    with pytest.raises(ValueError, match=match):
        paired_bootstrap_interval(candidate, baseline, seed=1)
