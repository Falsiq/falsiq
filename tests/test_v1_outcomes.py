from __future__ import annotations

from falsiq.facts import (
    Artifact,
    AttackFact,
    IntentFact,
    OutcomeFact,
    ReviewRoundFact,
    RulingFact,
)
from falsiq.outcomes import build_outcomes_report

IDS = [f"01ARZ3NDEKTSV4RRFFQ69G5F{suffix}" for suffix in ("AV", "AW", "AX", "AY", "AZ")]
CASE_ID, ATTACK_ID, RULING_ID, ROUND_ID, OUTCOME_ID = IDS
TS = "2026-07-29T12:00:00.000Z"
DIGEST = "a" * 64
PROMPTS = {
    "boundary": DIGEST,
    "consequence": "b" * 64,
    "prototype": "c" * 64,
    "conflict": "d" * 64,
    "omission": "e" * 64,
}


def test_report_attributes_missable_rework_and_complete_case_state() -> None:
    facts = [
        IntentFact(
            schema_version=2,
            id=CASE_ID,
            ts=TS,
            case_id=CASE_ID,
            text="Handle empty input",
            source="user",
            profile_name="coding",
            profile_digest=DIGEST,
        ),
        AttackFact(
            schema_version=2,
            id=ATTACK_ID,
            ts=TS,
            case_id=CASE_ID,
            klass="boundary",
            targets=[CASE_ID],
            artifact=Artifact(type="input", body="Empty input"),
            settles=["empty-input behavior"],
            hate_scenario="Silent behavior surprises callers.",
            render_cost="trivial",
            round=1,
            attacker_version=DIGEST,
        ),
        RulingFact(
            schema_version=2,
            id=RULING_ID,
            ts=TS,
            case_id=CASE_ID,
            attack_id=ATTACK_ID,
            verdict="dont_care",
        ),
        ReviewRoundFact(
            id=ROUND_ID,
            ts=TS,
            case_id=CASE_ID,
            round=1,
            max_rounds=2,
            prompt_versions=PROMPTS,
            policy_digest=DIGEST,
            profile_name="coding",
            profile_digest=DIGEST,
            selected_attack_ids=[ATTACK_ID],
            open_ambiguities=[{"decision": "timeout behavior", "reason": "budget exhausted"}],
        ),
        OutcomeFact(
            schema_version=2,
            id=OUTCOME_ID,
            ts=TS,
            case_id=CASE_ID,
            otype="rework",
            trace="missable",
            missable_class="boundary",
            prompt_version=DIGEST,
            notes="The empty input path failed later.",
        ),
    ]

    report = build_outcomes_report(facts)

    assert report["by_class"]["boundary"]["reworks_missable"] == 1
    assert report["by_class"]["boundary"]["waste_rate"] == 1.0
    assert report["cases"][CASE_ID]["rounds_used"] == [1]
    assert report["cases"][CASE_ID]["open_ambiguities"] == [
        {"decision": "timeout behavior", "reason": "budget exhausted"}
    ]
    assert report["prompt_versions"][DIGEST]["reworks_missable"] == 1


def test_since_filters_outcome_attribution_but_keeps_case_context() -> None:
    intent = IntentFact(
        id=CASE_ID,
        ts=TS,
        case_id=CASE_ID,
        text="Handle empty input",
        source="user",
    )
    old = OutcomeFact(
        id=OUTCOME_ID,
        ts=TS,
        case_id=CASE_ID,
        otype="accepted",
        trace="n/a",
        notes="",
    )

    report = build_outcomes_report([intent, old], since="2026-07-30T00:00:00.000Z")

    assert CASE_ID in report["cases"]
    assert report["cases"][CASE_ID]["outcomes"] == []
