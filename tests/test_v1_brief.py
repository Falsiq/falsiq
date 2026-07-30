from __future__ import annotations

import hashlib
import json
from pathlib import Path

from falsiq.brief import canonical_brief_json, render_brief_contract
from falsiq.derive import (
    DeriverResponse,
    ForbiddenTest,
    build_derivation_request,
    submit_derivation,
)
from falsiq.facts import (
    Artifact,
    ArtifactOption,
    AttackFact,
    IntentFact,
    ReviewRoundFact,
    RulingFact,
    SchemaMigrationFact,
)
from falsiq.ledger import Ledger

IDS = [f"01ARZ3NDEKTSV4RRFFQ69G5F{suffix}" for suffix in ("AV", "AW", "AX", "AY", "AZ")]
CASE_ID, ATTACK_ID, RULING_ID, ROUND_ID, MIGRATION_ID = IDS
TS = "2026-07-29T12:00:00.000Z"
DIGEST = "a" * 64
PROMPTS = {
    "boundary": DIGEST,
    "consequence": DIGEST,
    "prototype": DIGEST,
    "conflict": DIGEST,
    "omission": DIGEST,
}


def ruled_facts() -> list[object]:
    return [
        IntentFact(
            id=CASE_ID,
            ts=TS,
            case_id=CASE_ID,
            text="Reject empty input",
            source="user",
        ),
        AttackFact(
            id=ATTACK_ID,
            ts=TS,
            case_id=CASE_ID,
            klass="boundary",
            targets=[CASE_ID],
            artifact=Artifact(
                type="input",
                options=[
                    ArtifactOption(key="A", body="Return an empty result."),
                    ArtifactOption(key="B", body="Raise a validation error."),
                ],
            ),
            settles=["empty-input behavior", "exit code"],
            hate_scenario="Silent success hides an upstream failure.",
            render_cost="trivial",
            round=1,
        ),
        RulingFact(
            id=RULING_ID,
            ts=TS,
            case_id=CASE_ID,
            attack_id=ATTACK_ID,
            verdict="forbidden",
            choice="A",
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
            open_ambiguities=[
                {
                    "decision": "logging behavior",
                    "reason": "round budget exhausted",
                }
            ],
        ),
    ]


def response_for(facts: list[object]) -> DeriverResponse:
    request = build_derivation_request(facts, CASE_ID)
    return DeriverResponse(
        request_id=request.request_id,
        case_id=CASE_ID,
        ledger_head=request.ledger_head,
        forbidden_tests=[
            ForbiddenTest(
                ruling_id=RULING_ID,
                filename="test_empty_input.py",
                content="def test_empty_input() -> None:\n    raise NotImplementedError\n",
            )
        ],
    )


def test_brief_json_is_deterministic_citable_and_explicit() -> None:
    facts = ruled_facts()
    response = response_for(facts)
    brief = render_brief_contract(facts, response)
    encoded = canonical_brief_json(brief)

    assert encoded == canonical_brief_json(json.loads(encoded))
    assert brief.obligations[0].obligation_id == RULING_ID
    assert brief.obligations[0].verification.strength == "executable"
    assert brief.discretion == []
    assert brief.open_ambiguities[0].decision == "logging behavior"
    assert brief.provenance.attacker_versions == PROMPTS


def test_v2_derivation_commits_markdown_and_machine_brief(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    state = tmp_path / "state"
    workspace.mkdir()
    state.mkdir()
    monkeypatch.chdir(workspace)
    monkeypatch.setenv("FALSIQ_STATE_ROOT", str(state))
    ledger = Ledger.initialize()
    facts = ruled_facts()
    ledger.append_batch(facts)
    ledger.append(
        SchemaMigrationFact(
            id=MIGRATION_ID,
            ts=TS,
            case_id=MIGRATION_ID,
            from_version=1,
            to_version=2,
        )
    )
    current = list(ledger.read())
    response = response_for(current)
    head = current[-1].id

    fact, brief_path = submit_derivation(
        ledger.root,
        current,
        response,
        state_dir=ledger.state_dir,
        append_batch=lambda batch: ledger.append_batch(batch, expected_head=head),
        fact_committed=lambda fact_id: any(item.id == fact_id for item in ledger.read()),
    )

    json_path = state / "cases" / CASE_ID / "derived" / "brief.json"
    assert brief_path.is_file()
    assert json_path.is_file()
    assert fact.schema_version == 2
    assert fact.brief_json_path == f"cases/{CASE_ID}/derived/brief.json"
    assert fact.brief_json_sha256 == hashlib.sha256(json_path.read_bytes()).hexdigest()
    assert json.loads(json_path.read_text())["obligations"][0]["obligation_id"] == RULING_ID


def test_outcomes_report_does_not_treat_migration_marker_as_case() -> None:
    from falsiq.outcomes import build_outcomes_report

    facts = ruled_facts()
    report = build_outcomes_report(
        [
            *facts,
            SchemaMigrationFact(
                id=MIGRATION_ID,
                ts=TS,
                case_id=MIGRATION_ID,
            ),
        ]
    )
    assert MIGRATION_ID not in report["cases"]
