from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from falsiq.facts import (
    Artifact,
    AttackFact,
    IntentFact,
    ReviewRoundFact,
    SchemaMigrationFact,
    parse_fact,
)
from falsiq.policy import FalsiqPolicy, PolicyError, load_policy, validate_round
from falsiq.prompt_assets import production_prompt_digests

CASE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
ATTACK_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
MIGRATION_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
TS = "2026-07-29T12:00:00.000Z"
DIGEST = "a" * 64
PROMPT_VERSIONS = {
    "boundary": DIGEST,
    "consequence": DIGEST,
    "prototype": DIGEST,
    "conflict": DIGEST,
    "omission": DIGEST,
}


def test_v1_fact_remains_readable_and_v2_allows_policy_owned_rounds() -> None:
    v1 = IntentFact(
        schema_version=1,
        id=CASE_ID,
        ts=TS,
        case_id=CASE_ID,
        text="Build the feature",
        source="user",
    )
    assert parse_fact(v1.model_dump(mode="json")) == v1

    v2 = AttackFact(
        schema_version=2,
        id=ATTACK_ID,
        ts=TS,
        case_id=CASE_ID,
        klass="boundary",
        targets=[CASE_ID],
        artifact=Artifact(type="input", body="Empty input"),
        settles=["empty-input behavior"],
        hate_scenario="The caller cannot distinguish an empty value from failure.",
        render_cost="trivial",
        round=3,
        attacker_version=DIGEST,
    )
    assert parse_fact(v2.model_dump(mode="json")) == v2


def test_v2_attack_requires_prompt_provenance() -> None:
    with pytest.raises(ValidationError, match="attacker_version"):
        AttackFact(
            schema_version=2,
            id=ATTACK_ID,
            ts=TS,
            case_id=CASE_ID,
            klass="boundary",
            targets=[CASE_ID],
            artifact=Artifact(type="input", body="Empty input"),
            settles=["empty-input behavior"],
            hate_scenario="The caller cannot distinguish an empty value from failure.",
            render_cost="trivial",
            round=1,
        )


def test_review_round_records_empty_role_provenance_and_open_ambiguities() -> None:
    fact = ReviewRoundFact(
        id=ATTACK_ID,
        ts=TS,
        case_id=CASE_ID,
        round=2,
        max_rounds=2,
        prompt_versions=PROMPT_VERSIONS,
        policy_digest=DIGEST,
        profile_name="coding",
        profile_digest=DIGEST,
        selected_attack_ids=[],
        open_ambiguities=[
            {
                "decision": "timeout behavior",
                "reason": "round budget exhausted",
            }
        ],
    )
    assert fact.schema_version == 2
    assert fact.open_ambiguities[0].decision == "timeout behavior"

    with pytest.raises(ValidationError, match="all five reviewer roles"):
        ReviewRoundFact(
            id=ATTACK_ID,
            ts=TS,
            case_id=CASE_ID,
            round=1,
            max_rounds=2,
            prompt_versions={"boundary": DIGEST},
            policy_digest=DIGEST,
            profile_name="coding",
            profile_digest=DIGEST,
        )


def test_migration_is_an_append_only_global_marker() -> None:
    marker = SchemaMigrationFact(
        id=MIGRATION_ID,
        ts=TS,
        case_id=MIGRATION_ID,
        from_version=1,
        to_version=2,
    )
    assert marker.case_id == marker.id
    assert marker.schema_version == 2


def test_policy_controls_round_limit_without_changing_fact_schema(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.toml"
    policy_path.write_text("max_rounds = 3\n", encoding="utf-8")

    loaded = load_policy(policy_path)
    assert loaded.policy == FalsiqPolicy(max_rounds=3)
    assert len(loaded.digest) == 64
    validate_round(3, loaded.policy)
    with pytest.raises(PolicyError, match="max_rounds=3"):
        validate_round(4, loaded.policy)


def test_policy_rejects_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "real.toml"
    target.write_text("max_rounds = 2\n", encoding="utf-8")
    link = tmp_path / "policy.toml"
    link.symlink_to(target)
    with pytest.raises(PolicyError, match="symbolic link"):
        load_policy(link)


def test_all_attacker_prompts_have_stable_content_digests() -> None:
    versions = production_prompt_digests()
    assert set(versions) == {
        "boundary",
        "consequence",
        "prototype",
        "conflict",
        "omission",
    }
    assert all(len(digest) == 64 for digest in versions.values())
