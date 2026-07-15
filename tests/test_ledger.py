from __future__ import annotations

import json
import random
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from falsiq.facts import (
    Artifact,
    ArtifactOption,
    AttackFact,
    DerivationFact,
    IntentFact,
    OutcomeFact,
    RulingFact,
    new_ulid,
)
from falsiq.ledger import (
    Ledger,
    LedgerIntegrityError,
    LedgerNotInitializedError,
    LedgerValidationError,
    RepositoryNotFoundError,
    canonical_fact_json,
    discover_repository,
)

TS = "2026-07-15T12:00:00.000Z"


def make_id(number: int) -> str:
    return new_ulid(timestamp_ms=number, randomness=number.to_bytes(10, "big"))


def git_repo(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    return path


def root_intent(number: int, text: str = "Build the feature") -> IntentFact:
    case_id = make_id(number)
    return IntentFact(id=case_id, ts=TS, case_id=case_id, text=text, source="user")


def attack(
    number: int,
    case_id: str,
    target_id: str,
    *,
    options: bool = False,
    round_number: int = 1,
) -> AttackFact:
    artifact = Artifact(type="input", body="Input is empty; observe the result")
    if options:
        artifact = Artifact(
            type="input",
            body="Input is empty",
            options=[
                ArtifactOption(key="A", body="Exit zero"),
                ArtifactOption(key="B", body="Exit two"),
            ],
        )
    return AttackFact(
        id=make_id(number),
        ts=TS,
        case_id=case_id,
        klass="boundary",
        targets=[target_id],
        artifact=artifact,
        settles=["empty-input behavior", "exit code"],
        silent_settles=["exit code"],
        hate_scenario="Silent success hides an upstream failure.",
        render_cost="trivial",
        round=round_number,
    )


def test_repository_discovery_walks_from_nested_directory(tmp_path: Path) -> None:
    repo = git_repo(tmp_path / "repo")
    nested = repo / "src" / "package"
    nested.mkdir(parents=True)

    assert discover_repository(nested) == repo.resolve()


def test_repository_discovery_and_open_report_usable_errors(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(RepositoryNotFoundError, match="Git repository"):
        discover_repository(outside)
    with pytest.raises(LedgerNotInitializedError, match="falsiq init"):
        Ledger.open(git_repo(tmp_path / "repo"))


def test_init_is_idempotent_and_never_replaces_an_existing_ledger(tmp_path: Path) -> None:
    repo = git_repo(tmp_path / "repo")

    first = Ledger.initialize(repo)
    first.append(root_intent(1))
    before = first.path.read_bytes()
    second = Ledger.initialize(repo / ".falsiq")

    assert second.root == repo.resolve()
    assert second.path.read_bytes() == before
    assert (repo / ".falsiq" / "cases").is_dir()


def test_init_rejects_a_falsiq_symlink_that_escapes_the_repo(tmp_path: Path) -> None:
    repo = git_repo(tmp_path / "repo")
    outside = tmp_path / "outside"
    outside.mkdir()
    (repo / ".falsiq").symlink_to(outside, target_is_directory=True)

    with pytest.raises(LedgerValidationError, match="symlink"):
        Ledger.initialize(repo)


def test_canonical_batch_append_is_single_global_jsonl(tmp_path: Path) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    intent = root_intent(1, "Keep Unicode: λ")
    probe = attack(2, intent.case_id, intent.id)

    appended = ledger.append_batch([intent, probe])
    lines = ledger.path.read_text(encoding="utf-8").splitlines()

    assert appended == (intent, probe)
    assert lines == [canonical_fact_json(intent), canonical_fact_json(probe)]
    assert all('"case_id": "' not in line for line in lines)
    assert json.loads(lines[0])["text"] == "Keep Unicode: λ"
    assert list(json.loads(lines[0])) == sorted(json.loads(lines[0]))


def test_failed_append_never_changes_ledger_bytes(tmp_path: Path) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    intent = root_intent(1)
    ledger.append(intent)
    before = ledger.path.read_bytes()
    invalid = attack(2, intent.case_id, make_id(999))

    with pytest.raises(LedgerValidationError, match="target"):
        ledger.append(invalid)

    assert ledger.path.read_bytes() == before


def test_empty_batches_are_rejected_without_writes(tmp_path: Path) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))

    with pytest.raises(LedgerValidationError, match="empty"):
        ledger.append_batch([])

    assert ledger.path.read_bytes() == b""


@pytest.mark.parametrize(
    "corrupt",
    [
        b"not json\n",
        b'{"kind":"intent"}\n',
        b'{"case_id": "spaced"}\n',
        b"{}",
        b"\n",
        b"{\"schema_version\":1}\r\n",
        b"\xff\n",
    ],
)
def test_integrity_check_rejects_malformed_noncanonical_or_truncated_lines(
    tmp_path: Path, corrupt: bytes
) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    ledger.path.write_bytes(corrupt)

    with pytest.raises(LedgerIntegrityError, match="line 1"):
        ledger.read()


def test_integrity_check_rejects_valid_json_with_noncanonical_key_order(tmp_path: Path) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    fact = root_intent(1)
    payload = fact.model_dump(mode="json")
    noncanonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    assert noncanonical != canonical_fact_json(fact)
    ledger.path.write_text(noncanonical + "\n", encoding="utf-8")

    with pytest.raises(LedgerIntegrityError, match="canonical"):
        ledger.read()


def test_integrity_check_rejects_duplicate_ids_and_unknown_references(tmp_path: Path) -> None:
    for suffix, facts, error in (
        (
            "duplicate",
            [root_intent(1), root_intent(1)],
            "duplicate fact id",
        ),
        (
            "reference",
            [root_intent(1), attack(2, make_id(1), make_id(999))],
            "target",
        ),
    ):
        ledger = Ledger.initialize(git_repo(tmp_path / suffix))
        ledger.path.write_text(
            "".join(canonical_fact_json(fact) + "\n" for fact in facts), encoding="utf-8"
        )

        with pytest.raises(LedgerIntegrityError, match=error):
            ledger.read()


def test_references_cannot_cross_cases(tmp_path: Path) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    first = root_intent(1)
    second = root_intent(2)
    ledger.append_batch([first, second])
    before = ledger.path.read_bytes()

    with pytest.raises(LedgerValidationError, match="same case"):
        ledger.append(attack(3, first.case_id, second.id))

    assert ledger.path.read_bytes() == before


def test_option_aware_rulings_validate_choices_against_the_attack(tmp_path: Path) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    intent = root_intent(1)
    option_attack = attack(2, intent.case_id, intent.id, options=True)
    ledger.append_batch([intent, option_attack])

    for number, verdict, choice, error in (
        (3, "intended", None, "requires --choice"),
        (4, "forbidden", "missing", "unknown option"),
    ):
        before = ledger.path.read_bytes()
        ruling = RulingFact(
            id=make_id(number),
            ts=TS,
            case_id=intent.case_id,
            attack_id=option_attack.id,
            verdict=verdict,
            choice=choice,
        )
        with pytest.raises(LedgerValidationError, match=error):
            ledger.append(ruling)
        assert ledger.path.read_bytes() == before

    plain_attack = attack(5, intent.case_id, intent.id)
    ledger.append(plain_attack)
    with pytest.raises(LedgerValidationError, match="does not have options"):
        ledger.append(
            RulingFact(
                id=make_id(6),
                ts=TS,
                case_id=intent.case_id,
                attack_id=plain_attack.id,
                verdict="intended",
                choice="A",
            )
        )


def test_reruling_must_supersede_the_active_ruling(tmp_path: Path) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    intent = root_intent(1)
    probe = attack(2, intent.case_id, intent.id, options=True)
    first = RulingFact(
        id=make_id(3),
        ts=TS,
        case_id=intent.case_id,
        attack_id=probe.id,
        verdict="intended",
        choice="A",
    )
    ledger.append_batch([intent, probe, first])

    missing_supersession = RulingFact(
        id=make_id(4),
        ts=TS,
        case_id=intent.case_id,
        attack_id=probe.id,
        verdict="forbidden",
        choice="B",
    )
    with pytest.raises(LedgerValidationError, match="active ruling"):
        ledger.append(missing_supersession)

    second = missing_supersession.model_copy(
        update={"id": make_id(5), "supersedes": first.id}
    )
    ledger.append(second)
    stale = RulingFact(
        id=make_id(6),
        ts=TS,
        case_id=intent.case_id,
        attack_id=probe.id,
        verdict="dont_care",
        supersedes=first.id,
    )
    with pytest.raises(LedgerValidationError, match="active ruling"):
        ledger.append(stale)

    assert ledger.state(intent.case_id)["rulings"][0]["id"] == second.id


def test_amendment_ruling_and_intent_are_one_validated_batch(tmp_path: Path) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    intent = root_intent(1)
    probe = attack(2, intent.case_id, intent.id)
    ledger.append_batch([intent, probe])
    ruling = RulingFact(
        id=make_id(3),
        ts=TS,
        case_id=intent.case_id,
        attack_id=probe.id,
        verdict="amend",
        amendment_text="Reject empty input.",
    )
    amended = IntentFact(
        id=make_id(4),
        ts=TS,
        case_id=intent.case_id,
        text="Reject empty input.",
        source="amendment",
        supersedes=intent.id,
        source_ruling_id=ruling.id,
    )

    before = ledger.path.read_bytes()
    with pytest.raises(LedgerValidationError, match="amendment intent"):
        ledger.append(ruling)
    assert ledger.path.read_bytes() == before

    ledger.append_batch([ruling, amended])
    state = ledger.state(intent.case_id)
    assert [item["id"] for item in state["intents"]] == [amended.id]
    assert state["rulings"][0]["verdict"] == "amend"


@pytest.mark.parametrize(
    ("intent_text", "supersedes_offset", "source_ruling_offset", "error"),
    [
        ("Different text", 1, 3, "text"),
        ("Reject empty input.", 999, 3, "supersedes"),
        ("Reject empty input.", 1, 999, "source ruling"),
    ],
)
def test_amendment_provenance_is_cross_checked(
    tmp_path: Path,
    intent_text: str,
    supersedes_offset: int,
    source_ruling_offset: int,
    error: str,
) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    intent = root_intent(1)
    probe = attack(2, intent.case_id, intent.id)
    ledger.append_batch([intent, probe])
    ruling = RulingFact(
        id=make_id(3),
        ts=TS,
        case_id=intent.case_id,
        attack_id=probe.id,
        verdict="amend",
        amendment_text="Reject empty input.",
    )
    amended = IntentFact(
        id=make_id(4),
        ts=TS,
        case_id=intent.case_id,
        text=intent_text,
        source="amendment",
        supersedes=make_id(supersedes_offset),
        source_ruling_id=make_id(source_ruling_offset),
    )

    with pytest.raises(LedgerValidationError, match=error):
        ledger.append_batch([ruling, amended])


def test_intent_supersession_cannot_branch(tmp_path: Path) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    intent = root_intent(1)
    first_attack = attack(2, intent.case_id, intent.id)
    first_ruling = RulingFact(
        id=make_id(3),
        ts=TS,
        case_id=intent.case_id,
        attack_id=first_attack.id,
        verdict="amend",
        amendment_text="First amendment",
    )
    first_amendment = IntentFact(
        id=make_id(4),
        ts=TS,
        case_id=intent.case_id,
        text="First amendment",
        source="amendment",
        supersedes=intent.id,
        source_ruling_id=first_ruling.id,
    )
    ledger.append_batch([intent, first_attack, first_ruling, first_amendment])
    second_attack = attack(5, intent.case_id, first_amendment.id)
    second_ruling = RulingFact(
        id=make_id(6),
        ts=TS,
        case_id=intent.case_id,
        attack_id=second_attack.id,
        verdict="amend",
        amendment_text="Branched amendment",
    )
    branched = IntentFact(
        id=make_id(7),
        ts=TS,
        case_id=intent.case_id,
        text="Branched amendment",
        source="amendment",
        supersedes=intent.id,
        source_ruling_id=second_ruling.id,
    )

    with pytest.raises(LedgerValidationError, match="active intent"):
        ledger.append_batch([second_attack, second_ruling, branched])


def test_derivation_head_must_be_the_current_global_ledger_head(tmp_path: Path) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    first = root_intent(1)
    second = root_intent(2)
    ledger.append_batch([first, second])
    derivation = DerivationFact(
        id=make_id(3),
        ts=TS,
        case_id=first.case_id,
        ledger_head=first.id,
        brief_path=f"cases/{first.case_id}/derived/IMPLEMENTATION_BRIEF.md",
    )

    with pytest.raises(LedgerValidationError, match="current ledger head"):
        ledger.append(derivation)


def test_durable_artifact_paths_stay_beneath_their_case(tmp_path: Path) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    intent = root_intent(1)
    ledger.append(intent)
    escaped = AttackFact(
        **(
            attack(2, intent.case_id, intent.id).model_dump()
            | {"artifact": {"type": "diff", "path": "cases/another-case/diff.txt"}}
        )
    )

    with pytest.raises(LedgerValidationError, match="case artifact"):
        ledger.append(escaped)


def test_outcome_attack_reference_must_be_in_the_same_case(tmp_path: Path) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    first = root_intent(1)
    second = root_intent(2)
    probe = attack(3, first.case_id, first.id)
    ledger.append_batch([first, second, probe])
    outcome = OutcomeFact(
        id=make_id(4),
        ts=TS,
        case_id=second.case_id,
        otype="rework",
        trace="elicited",
        attack_id=probe.id,
        notes="Found rework.",
    )

    with pytest.raises(LedgerValidationError, match="same case"):
        ledger.append(outcome)


def test_case_state_is_deterministic_and_option_aware(tmp_path: Path) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    intent = root_intent(1)
    decided = attack(2, intent.case_id, intent.id, options=True)
    open_probe = attack(3, intent.case_id, intent.id, round_number=2)
    first = RulingFact(
        id=make_id(4),
        ts=TS,
        case_id=intent.case_id,
        attack_id=decided.id,
        verdict="intended",
        choice="A",
    )
    ledger.append_batch([intent, decided, open_probe, first])

    intended_state = ledger.state(intent.case_id)
    assert intended_state["rulings"][0]["option_states"] == {
        "A": "intended",
        "B": "not_intended",
    }

    second = RulingFact(
        id=make_id(5),
        ts=TS,
        case_id=intent.case_id,
        attack_id=decided.id,
        verdict="forbidden",
        choice="B",
        supersedes=first.id,
    )
    ledger.append(second)

    state = ledger.state(intent.case_id)
    assert state == ledger.state(intent.case_id)
    assert state["ledger_head"] == second.id
    assert state["case_head"] == second.id
    assert [item["id"] for item in state["intents"]] == [intent.id]
    assert [item["id"] for item in state["open_attacks"]] == [open_probe.id]
    assert state["rulings"][0]["id"] == second.id
    assert state["rulings"][0]["option_states"] == {"A": "unruled", "B": "forbidden"}


def test_global_state_and_log_filter_cases_without_losing_global_head(tmp_path: Path) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    first = root_intent(1)
    second = root_intent(2)
    probe = attack(3, first.case_id, first.id)
    ledger.append_batch([first, second, probe])

    state = ledger.state()
    filtered = ledger.log(kind="intent", case_id=first.case_id)

    assert state["ledger_head"] == probe.id
    assert [case["case_id"] for case in state["cases"]] == [first.case_id, second.case_id]
    assert filtered == (first,)
    assert state["cases"][1]["ledger_head"] == probe.id
    assert state["cases"][1]["case_head"] == second.id


def test_round_trip_500_seeded_mixed_facts(tmp_path: Path) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    rng = random.Random(20_260_715)
    facts = []
    next_id = 1
    expected_cases = []
    for case_number in range(100):
        intent = root_intent(next_id, f"Intent {case_number}: seed {rng.randrange(1_000_000)}")
        next_id += 1
        probe = attack(next_id, intent.case_id, intent.id, round_number=rng.choice([1, 2]))
        next_id += 1
        ruling = RulingFact(
            id=make_id(next_id),
            ts=TS,
            case_id=intent.case_id,
            attack_id=probe.id,
            verdict=rng.choice(["intended", "forbidden", "dont_care"]),
        )
        next_id += 1
        outcome = OutcomeFact(
            id=make_id(next_id),
            ts=TS,
            case_id=intent.case_id,
            otype=rng.choice(["accepted", "abandoned"]),
            trace="n/a",
            notes=f"Outcome {rng.randrange(1_000_000)}",
        )
        next_id += 1
        derivation = DerivationFact(
            id=make_id(next_id),
            ts=TS,
            case_id=intent.case_id,
            ledger_head=outcome.id,
            brief_path=f"cases/{intent.case_id}/derived/IMPLEMENTATION_BRIEF.md",
        )
        next_id += 1
        facts.extend([intent, probe, ruling, outcome, derivation])
        expected_cases.append(intent.case_id)

    ledger.append_batch(facts)
    reread = ledger.read()

    assert len(reread) == 500
    assert reread == tuple(facts)
    assert [case["case_id"] for case in ledger.state()["cases"]] == expected_cases
    assert ledger.path.read_bytes().count(b"\n") == 500


def test_concurrent_writers_are_serialized_without_lost_facts(tmp_path: Path) -> None:
    repo = git_repo(tmp_path / "repo")
    Ledger.initialize(repo)

    def append_one(number: int) -> str:
        ledger = Ledger.open(repo)
        fact = root_intent(number)
        ledger.append(fact)
        return fact.id

    with ThreadPoolExecutor(max_workers=8) as executor:
        expected = set(executor.map(append_one, range(1, 33)))

    facts = Ledger.open(repo).read()
    assert len(facts) == 32
    assert {fact.id for fact in facts} == expected
    assert len(Ledger.open(repo).state()["cases"]) == 32
