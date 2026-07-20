from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from falsiq.cli import main
from falsiq.facts import (
    Artifact,
    ArtifactOption,
    AttackFact,
    IntentFact,
    OutcomeFact,
    RulingFact,
    new_ulid,
    utc_timestamp,
)
from falsiq.ledger import Ledger

TS = "2026-07-15T12:00:00.000Z"


def git_repo(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    return path


def initialize_case(repo: Path, text: str = "Build the feature") -> tuple[Ledger, IntentFact]:
    Ledger.initialize(repo)
    case_id = new_ulid()
    intent = IntentFact(
        id=case_id,
        ts=TS,
        case_id=case_id,
        text=text,
        source="user",
    )
    ledger = Ledger.open(repo)
    ledger.append(intent)
    return ledger, intent


def add_attack(
    ledger: Ledger,
    intent: IntentFact,
    *,
    options: bool = False,
    targets: list[str] | None = None,
) -> AttackFact:
    artifact = Artifact(type="input", body="Empty input produces an observable result")
    if options:
        artifact = Artifact(
            type="input",
            body="Empty input",
            options=[
                ArtifactOption(key="A", body="Exit zero"),
                ArtifactOption(key="B", body="Exit two"),
            ],
        )
    attack = AttackFact(
        id=new_ulid(),
        ts=TS,
        case_id=intent.case_id,
        klass="boundary",
        targets=targets or [intent.id],
        artifact=artifact,
        settles=["empty-input behavior"],
        silent_settles=["empty-input behavior"],
        hate_scenario="Silent success masks an upstream failure.",
        render_cost="trivial",
        round=1,
    )
    ledger.append(attack)
    return attack


def test_rule_validates_choices_and_updates_derived_option_state(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent = initialize_case(repo)
    attack = add_attack(ledger, intent, options=True)
    monkeypatch.chdir(repo)
    before = ledger.path.read_bytes()

    assert main(["rule", attack.id, "intended"]) == 2
    missing = capsys.readouterr()
    assert missing.out == ""
    assert "requires --choice" in missing.err
    assert ledger.path.read_bytes() == before

    assert main(["rule", attack.id, "intended", "--choice", "missing"]) == 2
    invalid = capsys.readouterr()
    assert invalid.out == ""
    assert "unknown option" in invalid.err
    assert ledger.path.read_bytes() == before

    assert main(["rule", attack.id, "intended", "--choice", "B"]) == 0
    output = capsys.readouterr()
    ruling_id = output.out.strip()
    assert output.err == ""
    assert len(ruling_id) == 26
    state = ledger.state(intent.case_id)
    assert state["open_attacks"] == []
    assert state["rulings"][0]["option_states"] == {
        "A": "not_intended",
        "B": "intended",
    }

    assert main(["rule", attack.id, "forbidden", "--choice", "A"]) == 0
    reruled = capsys.readouterr()
    assert reruled.err == ""
    assert ledger.state(intent.case_id)["rulings"][0]["option_states"] == {
        "A": "forbidden",
        "B": "unruled",
    }


def test_reruling_automatically_supersedes_the_active_ruling(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent = initialize_case(repo)
    attack = add_attack(ledger, intent)
    monkeypatch.chdir(repo)

    assert main(["rule", attack.id, "intended"]) == 0
    first_id = capsys.readouterr().out.strip()
    assert main(["rule", attack.id, "forbidden"]) == 0
    second_id = capsys.readouterr().out.strip()

    rulings = [fact for fact in ledger.read() if isinstance(fact, RulingFact)]
    assert [fact.id for fact in rulings] == [first_id, second_id]
    assert rulings[0].supersedes is None
    assert rulings[1].supersedes == rulings[0].id
    assert ledger.state(intent.case_id)["rulings"][0]["id"] == second_id


@pytest.mark.parametrize(
    "arguments",
    [
        ["intended", "--choice", "A"],
        ["dont_care", "--choice", "A"],
        ["amend"],
        ["amend", "--text", "replacement", "--choice", "A"],
        ["intended", "--text", "replacement"],
        ["forbidden", "--intent", "01ARZ3NDEKTSV4RRFFQ69G5FAV"],
    ],
)
def test_rule_rejects_flags_that_do_not_match_the_attack_or_verdict(
    tmp_path: Path, monkeypatch, capsys, arguments: list[str]
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent = initialize_case(repo)
    attack = add_attack(ledger, intent)
    monkeypatch.chdir(repo)
    before = ledger.path.read_bytes()

    assert main(["rule", attack.id, *arguments]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err.startswith("error:")
    assert ledger.path.read_bytes() == before


def test_amend_rule_appends_ruling_and_verbatim_linked_intent_atomically(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent = initialize_case(repo)
    attack = add_attack(ledger, intent)
    monkeypatch.chdir(repo)
    amended_text = "  Reject empty input with exit code 2.  "

    assert main(["rule", attack.id, "amend", "--text", amended_text]) == 0
    output = capsys.readouterr()
    appended_ids = output.out.splitlines()
    assert output.err == ""
    assert len(appended_ids) == 2

    facts = ledger.read()
    ruling = facts[-2]
    amended = facts[-1]
    assert isinstance(ruling, RulingFact)
    assert isinstance(amended, IntentFact)
    assert ruling.id == appended_ids[0]
    assert ruling.amendment_text == amended_text
    assert amended.id == appended_ids[1]
    assert amended.text == amended_text
    assert amended.supersedes == intent.id
    assert amended.source_ruling_id == ruling.id
    assert ledger.state(intent.case_id)["intents"][0]["text"] == amended_text


def test_multi_target_amend_requires_explicit_active_intent(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, root = initialize_case(repo)
    first_attack = add_attack(ledger, root)
    monkeypatch.chdir(repo)
    assert main(["rule", first_attack.id, "amend", "--text", "First amendment"]) == 0
    first_output = capsys.readouterr().out.splitlines()
    amended_id = first_output[1]
    amended = next(
        fact for fact in ledger.read() if isinstance(fact, IntentFact) and fact.id == amended_id
    )
    inactive_only = add_attack(ledger, amended, targets=[root.id])
    before_inactive = ledger.path.read_bytes()
    assert main(["rule", inactive_only.id, "amend", "--text", "Cannot replace inactive root"]) == 2
    inactive_only_output = capsys.readouterr()
    assert "exactly one active review target" in inactive_only_output.err
    assert ledger.path.read_bytes() == before_inactive

    multi = add_attack(ledger, amended, targets=[root.id, amended.id])
    before = ledger.path.read_bytes()

    assert main(["rule", multi.id, "amend", "--text", "Second amendment"]) == 2
    ambiguous = capsys.readouterr()
    assert ambiguous.out == ""
    assert "--intent" in ambiguous.err
    assert ledger.path.read_bytes() == before

    assert (
        main(
            [
                "rule",
                multi.id,
                "amend",
                "--text",
                "Second amendment",
                "--intent",
                root.id,
            ]
        )
        == 2
    )
    inactive = capsys.readouterr()
    assert inactive.out == ""
    assert "active review target" in inactive.err
    assert ledger.path.read_bytes() == before

    assert (
        main(
            [
                "rule",
                multi.id,
                "amend",
                "--text",
                "Second amendment",
                "--intent",
                amended.id,
            ]
        )
        == 0
    )
    success = capsys.readouterr()
    assert success.err == ""
    newest = ledger.read()[-1]
    assert isinstance(newest, IntentFact)
    assert newest.supersedes == amended.id


def test_rule_rejects_unknown_attack_without_writing(tmp_path: Path, monkeypatch, capsys) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, _intent = initialize_case(repo)
    monkeypatch.chdir(repo)
    before = ledger.path.read_bytes()

    assert main(["rule", new_ulid(), "intended"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "unknown review" in output.err
    assert ledger.path.read_bytes() == before


@pytest.mark.parametrize(
    ("otype", "trace", "with_attack"),
    [
        ("accepted", "n/a", False),
        ("abandoned", "n/a", False),
        ("rework", "missable", False),
        ("rework", "novel", False),
        ("rework", "elicited", True),
    ],
)
def test_outcome_records_every_valid_trace_combination(
    tmp_path: Path,
    monkeypatch,
    capsys,
    otype: str,
    trace: str,
    with_attack: bool,
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent = initialize_case(repo)
    attack = add_attack(ledger, intent)
    monkeypatch.chdir(repo)
    arguments = [
        "outcome",
        otype,
        "--case",
        intent.case_id,
        "--trace",
        trace,
        "--notes",
        "  Observed verbatim.  ",
    ]
    if with_attack:
        arguments.extend(["--review", attack.id])

    assert main(arguments) == 0
    output = capsys.readouterr()
    outcome_id = output.out.strip()
    assert output.err == ""
    fact = ledger.read()[-1]
    assert isinstance(fact, OutcomeFact)
    assert fact.id == outcome_id
    assert fact.notes == "  Observed verbatim.  "
    assert fact.attack_id == (attack.id if with_attack else None)


@pytest.mark.parametrize(
    ("otype", "trace", "with_attack"),
    [
        ("rework", "n/a", False),
        ("rework", "elicited", False),
        ("rework", "missable", True),
        ("accepted", "missable", False),
        ("abandoned", "n/a", True),
    ],
)
def test_outcome_rejects_invalid_schema_combinations_without_writes(
    tmp_path: Path,
    monkeypatch,
    capsys,
    otype: str,
    trace: str,
    with_attack: bool,
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent = initialize_case(repo)
    attack = add_attack(ledger, intent)
    monkeypatch.chdir(repo)
    before = ledger.path.read_bytes()
    arguments = ["outcome", otype, "--case", intent.case_id, "--trace", trace]
    if with_attack:
        arguments.extend(["--review", attack.id])

    assert main(arguments) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err.startswith("error:")
    assert ledger.path.read_bytes() == before


def test_outcome_enforces_case_and_attack_references(tmp_path: Path, monkeypatch, capsys) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, first = initialize_case(repo)
    first_attack = add_attack(ledger, first)
    second_id = new_ulid()
    second = IntentFact(
        id=second_id,
        ts=TS,
        case_id=second_id,
        text="Second case",
        source="user",
    )
    ledger.append(second)
    monkeypatch.chdir(repo)
    before = ledger.path.read_bytes()

    assert (
        main(
            [
                "outcome",
                "rework",
                "--case",
                second.id,
                "--trace",
                "elicited",
                "--review",
                first_attack.id,
            ]
        )
        == 2
    )
    wrong_case = capsys.readouterr()
    assert "same case" in wrong_case.err
    assert ledger.path.read_bytes() == before

    assert (
        main(
            [
                "outcome",
                "rework",
                "--case",
                second.id,
                "--trace",
                "elicited",
                "--review",
                new_ulid(),
            ]
        )
        == 2
    )
    unknown_attack = capsys.readouterr()
    assert "unknown review" in unknown_attack.err
    assert ledger.path.read_bytes() == before

    assert main(["outcome", "accepted", "--case", new_ulid(), "--trace", "n/a"]) == 2
    unknown_case = capsys.readouterr()
    assert "unknown case" in unknown_case.err
    assert ledger.path.read_bytes() == before


@pytest.mark.parametrize("command", ["rule", "outcome"])
def test_concurrent_change_rejects_whole_ruling_or_outcome_batch(
    tmp_path: Path, monkeypatch, capsys, command: str
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent = initialize_case(repo)
    attack = add_attack(ledger, intent)
    monkeypatch.chdir(repo)
    original_append_batch = Ledger.append_batch
    raced = False

    def append_after_concurrent_change(self, facts, **kwargs):
        nonlocal raced
        if "expected_head" in kwargs and not raced:
            raced = True
            concurrent_id = new_ulid()
            concurrent = IntentFact(
                id=concurrent_id,
                ts=utc_timestamp(),
                case_id=concurrent_id,
                text="Concurrent case",
                source="user",
            )
            original_append_batch(self, [concurrent])
        return original_append_batch(self, facts, **kwargs)

    monkeypatch.setattr(Ledger, "append_batch", append_after_concurrent_change)
    arguments = (
        ["rule", attack.id, "amend", "--text", "Atomic replacement"]
        if command == "rule"
        else ["outcome", "accepted", "--case", intent.id, "--trace", "n/a"]
    )

    assert main(arguments) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "ledger head changed" in output.err
    facts = Ledger.open(repo).read()
    assert not any(isinstance(fact, RulingFact) for fact in facts)
    assert not any(isinstance(fact, OutcomeFact) for fact in facts)
    assert [fact for fact in facts if isinstance(fact, IntentFact)][-1].text == "Concurrent case"
