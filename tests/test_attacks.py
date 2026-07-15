from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path

import pytest
from pydantic import ValidationError

from falsiq.attacks import (
    AttackCandidate,
    AttackCandidateBatch,
    RoundGateError,
    SelectionEnvelope,
    append_attack_round,
    build_selection_envelope,
    candidate_digest,
    candidate_score,
    render_collision_markdown,
    selection_rationale,
    validate_round_gate,
    write_collision_file,
)
from falsiq.facts import Artifact, ArtifactOption, AttackFact, RulingFact

TS = "2026-07-15T12:00:00.000Z"
CASE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
INTENT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
ATTACK_IDS = [
    "01ARZ3NDEKTSV4RRFFQ69G5FAX",
    "01ARZ3NDEKTSV4RRFFQ69G5FAY",
    "01ARZ3NDEKTSV4RRFFQ69G5FAZ",
    "01ARZ3NDEKTSV4RRFFQ69G5FB0",
    "01ARZ3NDEKTSV4RRFFQ69G5FB1",
]
RULING_IDS = [
    "01ARZ3NDEKTSV4RRFFQ69G5FB2",
    "01ARZ3NDEKTSV4RRFFQ69G5FB3",
    "01ARZ3NDEKTSV4RRFFQ69G5FB4",
]


def candidate(
    name: str,
    *,
    klass: str = "boundary",
    settles: int = 1,
    silent: int = 0,
    cost: str = "trivial",
    artifact: Artifact | None = None,
) -> AttackCandidate:
    decisions = [f"{name}-decision-{index}" for index in range(settles)]
    return AttackCandidate(
        klass=klass,
        targets=[INTENT_ID],
        artifact=artifact or Artifact(type="input", body=f"concrete {name} input"),
        settles=decisions,
        silent_settles=decisions[:silent],
        hate_scenario=f"The {name} behavior silently loses user work.",
        render_cost=cost,
    )


def attack_fact(
    index: int,
    *,
    klass: str = "boundary",
    round_number: int = 1,
    artifact: Artifact | None = None,
) -> AttackFact:
    return AttackFact(
        id=ATTACK_IDS[index],
        ts=TS,
        case_id=CASE_ID,
        klass=klass,
        targets=[INTENT_ID],
        artifact=artifact or Artifact(type="input", body=f"input {index}"),
        settles=[f"decision {index}"],
        silent_settles=[],
        hate_scenario=f"bad outcome {index}",
        render_cost="trivial",
        round=round_number,
    )


def ruling(index: int, attack: AttackFact, verdict: str) -> RulingFact:
    return RulingFact(
        id=RULING_IDS[index],
        ts=TS,
        case_id=CASE_ID,
        attack_id=attack.id,
        verdict=verdict,
        amendment_text="Narrow the intent." if verdict == "amend" else None,
    )


def test_candidate_batches_are_strict_class_scoped_agent_output() -> None:
    item = candidate("edge")
    batch = AttackCandidateBatch(
        case_id=CASE_ID,
        attacker="boundary",
        candidates=[item],
    )

    assert batch.schema_version == 1
    assert batch.candidates == [item]

    with pytest.raises(ValidationError, match="must emit only its own class"):
        AttackCandidateBatch(
            case_id=CASE_ID,
            attacker="consequence",
            candidates=[item],
        )
    with pytest.raises(ValidationError):
        AttackCandidateBatch.model_validate(
            {
                "case_id": CASE_ID,
                "attacker": "boundary",
                "candidates": [item.model_dump(mode="json")],
                "commentary": "not part of the contract",
            }
        )
    with pytest.raises(ValidationError):
        AttackCandidateBatch(
            case_id=CASE_ID,
            attacker="boundary",
            candidates=[candidate(str(index)) for index in range(5)],
        )


@pytest.mark.parametrize(
    "updates",
    [
        {"settles": []},
        {"settles": [" "]},
        {"settles": ["same", "same"]},
        {"settles": ["one"], "silent_settles": ["other"]},
        {"hate_scenario": ""},
        {"targets": []},
        {"extra": "forbidden"},
    ],
)
def test_transient_candidates_reject_attack_theater_and_lossy_data(
    updates: dict[str, object],
) -> None:
    payload: dict[str, object] = candidate("base").model_dump(mode="json")
    payload.update(updates)

    with pytest.raises(ValidationError):
        AttackCandidate.model_validate(payload)


def test_candidate_score_uses_exact_silent_decision_weighting() -> None:
    item = candidate("score", settles=3, silent=2, cost="cheap")

    score = candidate_score(item)

    assert score == Fraction(5, 3)
    assert isinstance(score, Fraction)


@pytest.mark.parametrize(
    ("cost", "expected"),
    [
        ("trivial", Fraction(1, 1)),
        ("cheap", Fraction(1, 3)),
        ("expensive", Fraction(1, 9)),
    ],
)
def test_render_costs_use_fixed_policy_units(cost: str, expected: Fraction) -> None:
    assert candidate_score(candidate("cost", cost=cost)) == expected


def test_candidate_digest_is_canonical_content_identity() -> None:
    payload = candidate("digest", settles=2, silent=1, cost="expensive").model_dump(
        mode="json"
    )
    reordered = json.loads(json.dumps(payload, sort_keys=False))

    assert candidate_digest(AttackCandidate.model_validate(reordered)) == (
        "94f4e76dac12ea2bd6ab6d8c62d647f431ce96f0bfca11ae61cb50565ad99d2e"
    )


def test_selection_is_input_order_independent_and_makes_room_for_diversity() -> None:
    boundary_one = candidate("b1", settles=8)
    boundary_two = candidate("b2", settles=7)
    boundary_three = candidate("b3", settles=6)
    consequence = candidate("c1", klass="consequence", settles=1)

    forward = build_selection_envelope(
        CASE_ID,
        1,
        [boundary_one, boundary_two, boundary_three, consequence],
    )
    reverse = build_selection_envelope(
        CASE_ID,
        1,
        [consequence, boundary_three, boundary_two, boundary_one],
    )

    assert forward.selected == reverse.selected
    assert set(forward.selected) == {
        candidate_digest(boundary_one),
        candidate_digest(boundary_two),
        candidate_digest(consequence),
    }
    assert len({record.candidate.klass for record in forward.selected_records}) == 2


def test_selection_enforces_prototype_and_omission_caps() -> None:
    proto_one = candidate("p1", klass="prototype", settles=10)
    proto_two = candidate("p2", klass="prototype", settles=9)
    boundary = candidate("b", settles=1)
    prototype_envelope = build_selection_envelope(
        CASE_ID, 1, [proto_one, proto_two, boundary]
    )

    assert [record.candidate.klass for record in prototype_envelope.selected_records].count(
        "prototype"
    ) == 1
    assert len(prototype_envelope.selected) == 2

    omissions = [candidate(f"o{index}", klass="omission", settles=10 - index) for index in range(3)]
    conflict = candidate("conflict", klass="conflict", settles=1)
    omission_envelope = build_selection_envelope(CASE_ID, 1, [*omissions, conflict])

    classes = [record.candidate.klass for record in omission_envelope.selected_records]
    assert classes.count("omission") == 2
    assert classes.count("conflict") == 1


def test_equal_scores_use_content_digests_as_the_only_tie_breaker() -> None:
    items = [
        candidate("one", klass="boundary"),
        candidate("two", klass="boundary"),
        candidate("three", klass="consequence"),
        candidate("four", klass="conflict"),
    ]
    envelope = build_selection_envelope(CASE_ID, 1, items)

    valid_digest_sets = []
    for omitted in items:
        kept = [item for item in items if item is not omitted]
        if len({item.klass for item in kept}) >= 2:
            valid_digest_sets.append(tuple(sorted(candidate_digest(item) for item in kept)))

    assert tuple(sorted(envelope.selected)) == min(valid_digest_sets)


def test_same_class_pool_selects_only_one_and_empty_pool_is_a_noop() -> None:
    same_class = build_selection_envelope(
        CASE_ID,
        1,
        [candidate("high", settles=3), candidate("low", settles=1)],
    )
    empty = build_selection_envelope(CASE_ID, 1, [])

    assert same_class.selected == [candidate_digest(candidate("high", settles=3))]
    assert empty.selected == []


def test_selection_envelope_rejects_duplicates_and_selector_policy_tampering() -> None:
    first = candidate("first", klass="boundary", settles=3)
    second = candidate("second", klass="consequence", settles=2)
    envelope = build_selection_envelope(CASE_ID, 1, [first, second])
    payload = envelope.model_dump(mode="json")

    payload["selected"] = [candidate_digest(first)]
    with pytest.raises(ValidationError, match="deterministic selection policy"):
        SelectionEnvelope.model_validate(payload)

    duplicate_payload = envelope.model_dump(mode="json")
    duplicate_payload["candidates"].append(duplicate_payload["candidates"][0])
    with pytest.raises(ValidationError, match="duplicate candidate content"):
        SelectionEnvelope.model_validate(duplicate_payload)

    prose_payload = envelope.model_dump(mode="json")
    prose_payload["rationale"] = "Trust the selector."
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SelectionEnvelope.model_validate(prose_payload)


def test_selection_rationale_is_derived_from_verified_scoring_inputs() -> None:
    selected = candidate("scored", klass="boundary", settles=2, silent=1, cost="cheap")
    diversity = candidate("other", klass="conflict", settles=1)
    envelope = build_selection_envelope(CASE_ID, 1, [selected, diversity])

    rationale = selection_rationale(envelope)

    assert len(rationale) == 2
    assert any("score=1" in line and "settles=2; silent=1; cost=3" in line for line in rationale)


def test_candidate_envelopes_reject_artifact_paths_outside_the_case() -> None:
    outside = candidate(
        "outside",
        artifact=Artifact(type="diff", path="cases/a-different-case/diff.txt"),
    )

    with pytest.raises(ValidationError, match="case artifact path"):
        AttackCandidateBatch(
            case_id=CASE_ID,
            attacker="boundary",
            candidates=[outside],
        )
    with pytest.raises(ValidationError, match="case artifact path"):
        build_selection_envelope(CASE_ID, 1, [outside])


def test_round_two_requires_closed_moving_round_one() -> None:
    first = attack_fact(0)
    second = attack_fact(1)

    with pytest.raises(RoundGateError, match="round 1 attacks"):
        validate_round_gate(2, existing_attacks=[], active_rulings={})
    with pytest.raises(RoundGateError, match="still open"):
        validate_round_gate(2, existing_attacks=[first, second], active_rulings={})
    with pytest.raises(RoundGateError, match="amend or forbidden"):
        validate_round_gate(
            2,
            existing_attacks=[first, second],
            active_rulings={
                first.id: ruling(0, first, "intended"),
                second.id: ruling(1, second, "dont_care"),
            },
        )

    validate_round_gate(
        2,
        existing_attacks=[first, second],
        active_rulings={
            first.id: ruling(0, first, "intended"),
            second.id: ruling(1, second, "forbidden"),
        },
    )


def test_round_gate_allows_one_batch_per_round_and_rejects_cross_case_context() -> None:
    first = attack_fact(0)
    other_case = first.model_copy(
        update={"case_id": "01ARZ3NDEKTSV4RRFFQ69G5FC0", "id": ATTACK_IDS[1]}
    )

    validate_round_gate(1, existing_attacks=[], active_rulings={})
    with pytest.raises(RoundGateError, match="already exists"):
        validate_round_gate(1, existing_attacks=[first], active_rulings={})
    with pytest.raises(RoundGateError, match="one case"):
        validate_round_gate(2, existing_attacks=[first, other_case], active_rulings={})


def test_selected_candidates_become_one_durable_batch_and_raw_candidates_do_not() -> None:
    candidates = [
        candidate("one", klass="boundary", settles=5),
        candidate("two", klass="consequence", settles=4),
        candidate("three", klass="omission", settles=3),
        candidate("discarded", klass="conflict", settles=1, cost="expensive"),
    ]
    envelope = build_selection_envelope(CASE_ID, 1, candidates)
    calls: list[tuple[AttackFact, ...]] = []
    ids = iter(ATTACK_IDS)

    facts = append_attack_round(
        envelope,
        existing_attacks=[],
        active_rulings={},
        append_batch=calls.append,
        id_factory=lambda: next(ids),
        timestamp_factory=lambda: TS,
    )

    assert calls == [facts]
    assert len(facts) == 3
    assert all(isinstance(fact, AttackFact) for fact in facts)
    assert {candidate_digest_from_fact(fact) for fact in facts} == set(envelope.selected)
    assert all(fact.case_id == CASE_ID and fact.round == 1 for fact in facts)


def candidate_digest_from_fact(fact: AttackFact) -> str:
    return candidate_digest(
        AttackCandidate.model_validate(
            fact.model_dump(
                mode="json",
                exclude={"schema_version", "id", "ts", "kind", "case_id", "round"},
            )
        )
    )


def test_empty_selection_does_not_append_a_batch() -> None:
    calls: list[tuple[AttackFact, ...]] = []

    facts = append_attack_round(
        build_selection_envelope(CASE_ID, 1, []),
        existing_attacks=[],
        active_rulings={},
        append_batch=calls.append,
    )

    assert facts == ()
    assert calls == []


def collision_attacks() -> list[AttackFact]:
    return [
        attack_fact(
            0,
            klass="boundary",
            artifact=Artifact(
                type="input",
                body="empty file\n# this must not become a heading",
                options=[
                    ArtifactOption(
                        key="A",
                        body="exit 0",
                        path=f"cases/{CASE_ID}/collisions/accept output.txt",
                    ),
                    ArtifactOption(key="B", body="exit 2: error"),
                ],
            ),
        ),
        attack_fact(
            1,
            klass="consequence",
            artifact=Artifact(type="scenario", body="On day 30, the cache serves stale data."),
        ),
        attack_fact(
            2,
            klass="prototype",
            artifact=Artifact(
                type="rivals",
                path=f"cases/{CASE_ID}/collisions/prototype/transcript.md",
            ),
        ),
        attack_fact(
            3,
            klass="conflict",
            artifact=Artifact(type="diff", body="- current behavior\n+ requested behavior"),
        ),
        attack_fact(
            4,
            klass="omission",
            artifact=Artifact(type="transcript", body="$ tool --empty\nerror: empty input"),
        ),
    ]


def test_collision_markdown_is_stable_safe_and_matches_golden() -> None:
    expected = (Path(__file__).parent / "golden" / "collision.md").read_text()

    rendered = render_collision_markdown(CASE_ID, list(reversed(collision_attacks())))

    assert rendered == expected
    assert "# this must not become a heading" not in rendered
    assert "# this must not become a heading".replace("#", "&#x23;") in rendered
    assert f"cases/{CASE_ID}/collisions/accept%20output.txt" in rendered


def test_collision_writer_uses_case_round_path_and_is_idempotent(tmp_path: Path) -> None:
    attacks = collision_attacks()

    first = write_collision_file(tmp_path, CASE_ID, attacks)
    second = write_collision_file(tmp_path, CASE_ID, list(reversed(attacks)))

    assert first == tmp_path / ".falsiq" / "cases" / CASE_ID / "collisions" / "1.md"
    assert second == first
    assert first.read_text() == render_collision_markdown(CASE_ID, attacks)


def test_collision_writer_refuses_symlinked_case_directories(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    state_dir = tmp_path / ".falsiq"
    state_dir.mkdir()
    (state_dir / "cases").symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError, match="symlink"):
        write_collision_file(tmp_path, CASE_ID, collision_attacks())

    assert list(outside.iterdir()) == []


def test_collision_renderer_rejects_empty_mixed_or_duplicate_batches() -> None:
    attacks = collision_attacks()

    with pytest.raises(ValueError, match="at least one"):
        render_collision_markdown(CASE_ID, [])
    with pytest.raises(ValueError, match="requested case"):
        render_collision_markdown(
            CASE_ID,
            [attacks[0].model_copy(update={"case_id": "01ARZ3NDEKTSV4RRFFQ69G5FC0"})],
        )
    with pytest.raises(ValueError, match="one round"):
        render_collision_markdown(
            CASE_ID, [attacks[0], attacks[1].model_copy(update={"round": 2})]
        )
    with pytest.raises(ValueError, match="duplicate"):
        render_collision_markdown(CASE_ID, [attacks[0], attacks[0]])


def test_prompts_define_all_attackers_and_machine_checked_selector_contract() -> None:
    root = Path(__file__).parents[1]
    for klass in ("boundary", "consequence", "prototype", "conflict", "omission"):
        prompt = (root / "agents" / f"attacker_{klass}.md").read_text()
        assert f"`{klass}`" in prompt
        assert "0 to 4" in prompt
        assert "concrete artifact" in prompt
        assert "hate_scenario" in prompt
        assert "settles" in prompt

    selector = (root / "agents" / "selector.md").read_text()
    assert "SelectionEnvelope" in selector
    assert "content digest" in selector
    assert "Do not add rationale" in selector
    assert "1, 3, and 9" in selector
