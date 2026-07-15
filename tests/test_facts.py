from __future__ import annotations

import json
import re

import pytest
from pydantic import ValidationError

from falsiq.facts import (
    SCHEMA_VERSION,
    Artifact,
    ArtifactOption,
    AttackFact,
    DerivationFact,
    IntentFact,
    OutcomeFact,
    RulingFact,
    new_ulid,
    parse_fact,
    ulid_timestamp_ms,
)

TS = "2026-07-15T12:00:00.000Z"
CASE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
INTENT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
ATTACK_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
RULING_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
FACT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"


def base_fields(*, fact_id: str = FACT_ID) -> dict[str, object]:
    return {"schema_version": SCHEMA_VERSION, "id": fact_id, "ts": TS, "case_id": CASE_ID}


def test_ulids_are_canonical_and_round_trip_the_timestamp() -> None:
    assert new_ulid(timestamp_ms=0, randomness=b"\0" * 10) == "0" * 26
    assert new_ulid(timestamp_ms=(1 << 48) - 1, randomness=b"\xff" * 10) == "7" + "Z" * 25

    ulid = new_ulid(timestamp_ms=1_469_918_176_385, randomness=bytes(range(10)))

    assert re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", ulid)
    assert ulid_timestamp_ms(ulid) == 1_469_918_176_385


@pytest.mark.parametrize(
    "value",
    [
        "",
        "01ARZ3NDEKTSV4RRFFQ69G5FA",
        "01ARZ3NDEKTSV4RRFFQ69G5FAVV",
        "01arz3ndektsv4rrffq69g5fav",
        "01ARZ3NDEKTSV4RRFFQ69G5FAU",
        "81ARZ3NDEKTSV4RRFFQ69G5FAV",
    ],
)
def test_invalid_ulids_are_rejected(value: str) -> None:
    with pytest.raises(ValidationError):
        IntentFact(
            **base_fields(fact_id=value),
            text="Keep my words",
            source="amendment",
            supersedes=INTENT_ID,
            source_ruling_id=RULING_ID,
        )


@pytest.mark.parametrize(
    "value",
    [
        "2026-07-15T12:00:00Z",  # canonical facts always carry milliseconds
        "2026-07-15T12:00:00.000+00:00",
        "2026-07-15 12:00:00.000Z",
        "2026-02-30T12:00:00.000Z",
        "2026-07-15T12:00:00.0000000Z",
    ],
)
def test_noncanonical_timestamps_are_rejected(value: str) -> None:
    with pytest.raises(ValidationError):
        IntentFact(
            **(base_fields() | {"ts": value}),
            text="Keep my words",
            source="amendment",
            supersedes=INTENT_ID,
            source_ruling_id=RULING_ID,
        )


def test_root_intent_opens_its_case_and_preserves_verbatim_text() -> None:
    text = "  Keep the user's exact spacing.  "
    fact = IntentFact(
        **base_fields(fact_id=CASE_ID),
        text=text,
        source="user",
    )

    assert fact.case_id == fact.id
    assert fact.text == text
    assert fact.supersedes is None
    assert fact.source_ruling_id is None


def test_root_intent_requires_case_id_equal_to_its_id() -> None:
    with pytest.raises(ValidationError, match="root intent"):
        IntentFact(
            **base_fields(fact_id=INTENT_ID),
            text="A root intent",
            source="user",
        )


def test_amendment_intent_records_complete_provenance() -> None:
    fact = IntentFact(
        **base_fields(),
        text="Use exponential backoff",
        source="amendment",
        supersedes=INTENT_ID,
        source_ruling_id=RULING_ID,
    )

    assert fact.supersedes == INTENT_ID
    assert fact.source_ruling_id == RULING_ID


@pytest.mark.parametrize(
    ("source", "supersedes", "source_ruling_id"),
    [
        ("amendment", None, RULING_ID),
        ("amendment", INTENT_ID, None),
        ("user", None, RULING_ID),
        ("user", INTENT_ID, None),
    ],
)
def test_intent_provenance_combinations_are_strict(
    source: str, supersedes: str | None, source_ruling_id: str | None
) -> None:
    with pytest.raises(ValidationError):
        IntentFact(
            **base_fields(),
            text="An intent",
            source=source,
            supersedes=supersedes,
            source_ruling_id=source_ruling_id,
        )


def test_artifact_supports_structured_options() -> None:
    artifact = Artifact(
        type="input",
        body="Empty input permits both behaviors.",
        options=[
            ArtifactOption(key="accept", body="Exit 0 with empty output"),
            ArtifactOption(key="reject", body="Exit 2 with an error", path="examples/reject.txt"),
        ],
    )

    assert [option.key for option in artifact.options] == ["accept", "reject"]


def test_artifact_option_keys_preserve_public_uppercase_choices() -> None:
    artifact = Artifact(
        type="rivals",
        options=[
            ArtifactOption(key="A", body="First behavior"),
            ArtifactOption(key="B", body="Second behavior"),
        ],
    )

    assert [option.key for option in artifact.options] == ["A", "B"]


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"body": ""},
        {"path": ""},
        {"path": "/tmp/escape"},
        {"path": "../escape"},
        {"path": "a/../../escape"},
        {"path": "a\\windows"},
        {"path": "C:/windows"},
        {"path": "a//b"},
        {"options": [{"key": "only", "body": "one"}]},
        {
            "options": [
                {"key": "same", "body": "one"},
                {"key": "same", "body": "two"},
            ]
        },
    ],
)
def test_artifact_rejects_unsafe_or_nonconcrete_payloads(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Artifact(type="scenario", **payload)


@pytest.mark.parametrize("key", ["", "has space", "../escape", "a/b"])
def test_artifact_option_keys_are_stable_cli_tokens(key: str) -> None:
    with pytest.raises(ValidationError):
        ArtifactOption(key=key, body="Observable behavior")


def test_attack_preserves_scoring_inputs() -> None:
    fact = AttackFact(
        **base_fields(),
        klass="boundary",
        targets=[INTENT_ID],
        artifact=Artifact(type="input", body="Input: empty; behavior: accept or reject"),
        settles=["empty-input behavior", "exit code"],
        silent_settles=["exit code"],
        hate_scenario="Silent output hides an upstream failure.",
        render_cost="trivial",
        round=1,
    )

    assert fact.silent_settles == ["exit code"]
    assert fact.round == 1


@pytest.mark.parametrize(
    "updates",
    [
        {"targets": []},
        {"targets": [INTENT_ID, INTENT_ID]},
        {"settles": []},
        {"settles": [" "]},
        {"settles": ["one", "one"]},
        {"silent_settles": ["not settled"]},
        {"silent_settles": ["exit code", "exit code"]},
        {"hate_scenario": ""},
        {"round": 0},
        {"round": 3},
        {"round": "1"},
    ],
)
def test_attack_rejects_invalid_or_lossy_scoring_data(updates: dict[str, object]) -> None:
    payload: dict[str, object] = {
        **base_fields(),
        "klass": "boundary",
        "targets": [INTENT_ID],
        "artifact": {"type": "input", "body": "A concrete input"},
        "settles": ["empty-input behavior", "exit code"],
        "silent_settles": ["exit code"],
        "hate_scenario": "Silent output hides failure.",
        "render_cost": "trivial",
        "round": 1,
    }
    payload.update(updates)

    with pytest.raises(ValidationError):
        AttackFact.model_validate(payload)


@pytest.mark.parametrize("verdict", ["intended", "forbidden"])
def test_choice_rulings_accept_a_stable_option_key(verdict: str) -> None:
    fact = RulingFact(
        **base_fields(),
        attack_id=ATTACK_ID,
        verdict=verdict,
        choice="reject",
    )

    assert fact.choice == "reject"
    assert fact.amendment_text is None


def test_amend_ruling_requires_text_and_defers_link_to_amendment_intent() -> None:
    fact = RulingFact(
        **base_fields(fact_id=RULING_ID),
        attack_id=ATTACK_ID,
        verdict="amend",
        amendment_text="Use exponential backoff.",
    )

    assert fact.amendment_text == "Use exponential backoff."


@pytest.mark.parametrize(
    "updates",
    [
        {"verdict": "amend", "amendment_text": None},
        {"verdict": "amend", "amendment_text": ""},
        {"verdict": "amend", "amendment_text": "text", "choice": "a"},
        {"verdict": "dont_care", "amendment_text": "text"},
        {"verdict": "dont_care", "choice": "a"},
        {"verdict": "intended", "amendment_text": "text"},
        {"verdict": "forbidden", "choice": "not valid"},
    ],
)
def test_ruling_conditional_fields_are_enforced(updates: dict[str, object]) -> None:
    payload: dict[str, object] = {
        **base_fields(),
        "attack_id": ATTACK_ID,
        "verdict": "intended",
    }
    payload.update(updates)

    with pytest.raises(ValidationError):
        RulingFact.model_validate(payload)


@pytest.mark.parametrize(
    "path",
    ["/absolute.md", "../brief.md", "cases/../../brief.md", "cases\\brief.md", "a//b.md"],
)
def test_derivation_rejects_paths_that_can_escape_the_project(path: str) -> None:
    with pytest.raises(ValidationError):
        DerivationFact(
            **base_fields(),
            ledger_head=RULING_ID,
            brief_path=path,
            test_stub_paths=[],
        )


def test_derivation_paths_are_relative_unique_and_nonempty() -> None:
    fact = DerivationFact(
        **base_fields(),
        ledger_head=RULING_ID,
        brief_path=f"cases/{CASE_ID}/derived/IMPLEMENTATION_BRIEF.md",
        test_stub_paths=[f"cases/{CASE_ID}/derived/tests/test_forbidden.py"],
    )

    assert fact.test_stub_paths == [f"cases/{CASE_ID}/derived/tests/test_forbidden.py"]

    with pytest.raises(ValidationError):
        DerivationFact(
            **base_fields(),
            ledger_head=RULING_ID,
            brief_path="brief.md",
            test_stub_paths=["test_a.py", "test_a.py"],
        )


@pytest.mark.parametrize(
    ("otype", "trace", "attack_id"),
    [
        ("rework", "elicited", ATTACK_ID),
        ("rework", "missable", None),
        ("rework", "novel", None),
        ("accepted", "n/a", None),
        ("abandoned", "n/a", None),
    ],
)
def test_outcome_valid_combinations(otype: str, trace: str, attack_id: str | None) -> None:
    fact = OutcomeFact(
        **base_fields(),
        otype=otype,
        trace=trace,
        attack_id=attack_id,
        notes="Observed after implementation.",
    )

    assert fact.trace == trace


@pytest.mark.parametrize(
    ("otype", "trace", "attack_id"),
    [
        ("rework", "n/a", None),
        ("rework", "elicited", None),
        ("rework", "missable", ATTACK_ID),
        ("accepted", "elicited", ATTACK_ID),
        ("accepted", "n/a", ATTACK_ID),
        ("abandoned", "novel", None),
    ],
)
def test_outcome_invalid_combinations(otype: str, trace: str, attack_id: str | None) -> None:
    with pytest.raises(ValidationError):
        OutcomeFact(
            **base_fields(),
            otype=otype,
            trace=trace,
            attack_id=attack_id,
            notes="Observed after implementation.",
        )


def test_fact_union_round_trips_all_kinds_and_forbids_unknown_fields() -> None:
    facts = [
        IntentFact(**base_fields(fact_id=CASE_ID), text="Root", source="user"),
        AttackFact(
            **base_fields(),
            klass="boundary",
            targets=[CASE_ID],
            artifact=Artifact(type="input", body="Concrete"),
            settles=["behavior"],
            hate_scenario="The default loses data.",
            render_cost="trivial",
            round=1,
        ),
        RulingFact(
            **base_fields(), attack_id=ATTACK_ID, verdict="dont_care", supersedes=RULING_ID
        ),
        DerivationFact(
            **base_fields(), ledger_head=RULING_ID, brief_path="derived/brief.md"
        ),
        OutcomeFact(
            **base_fields(), otype="accepted", trace="n/a", notes="No rework needed."
        ),
    ]

    for fact in facts:
        encoded = fact.model_dump_json()
        assert parse_fact(encoded) == fact
        assert parse_fact(json.loads(encoded)) == fact

        payload = json.loads(encoded)
        payload["unexpected"] = True
        with pytest.raises(ValidationError):
            parse_fact(payload)


def test_schema_version_and_kind_are_strict() -> None:
    payload = {
        **base_fields(fact_id=CASE_ID),
        "kind": "intent",
        "text": "Root",
        "source": "user",
    }

    for updates in (
        {"schema_version": 2},
        {"schema_version": "1"},
        {"kind": "unknown"},
        {"text": 123},
    ):
        with pytest.raises(ValidationError):
            parse_fact(payload | updates)
