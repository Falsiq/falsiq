from __future__ import annotations

import json
import subprocess
from pathlib import Path

import falsiq.cli as cli_module
from falsiq.attacks import AttackCandidate, build_selection_envelope
from falsiq.cli import main
from falsiq.facts import (
    Artifact,
    AttackFact,
    IntentFact,
    RulingFact,
    new_ulid,
    utc_timestamp,
)
from falsiq.ledger import Ledger


def git_repo(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    return path


def make_candidate(
    case_id: str,
    name: str,
    *,
    klass: str,
    settles: int,
) -> AttackCandidate:
    decisions = [f"{name} decision {index}" for index in range(settles)]
    return AttackCandidate(
        klass=klass,
        targets=[case_id],
        artifact=Artifact(
            type="input" if klass != "consequence" else "scenario",
            body=f"Concrete {name} behavior",
            path=f"cases/{case_id}/collisions/{name}.txt",
        ),
        settles=decisions,
        silent_settles=decisions[:1],
        hate_scenario=f"The {name} behavior loses data.",
        render_cost="trivial",
    )


def write_envelope(
    path: Path,
    case_id: str,
    round_number: int,
    candidates: list[AttackCandidate],
) -> Path:
    envelope = build_selection_envelope(case_id, round_number, candidates)
    path.write_text(envelope.model_dump_json(indent=2), encoding="utf-8")
    return path


def initialize_case(repo: Path, monkeypatch, capsys) -> str:
    monkeypatch.chdir(repo)
    assert main(["init"]) == 0
    capsys.readouterr()
    assert main(["intent", "Add robust import handling"]) == 0
    case_id = capsys.readouterr().out.strip()
    assert len(case_id) == 26
    return case_id


def test_attack_add_persists_only_selected_facts_and_collide_renders_open_attacks(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    case_id = initialize_case(repo, monkeypatch, capsys)
    candidates = [
        make_candidate(case_id, "boundary", klass="boundary", settles=5),
        make_candidate(case_id, "consequence", klass="consequence", settles=4),
        make_candidate(case_id, "omission", klass="omission", settles=3),
        make_candidate(case_id, "discarded", klass="conflict", settles=1),
    ]
    envelope_path = write_envelope(repo / "round-1.json", case_id, 1, candidates)

    assert main(["attack", "add", "-f", str(envelope_path)]) == 0
    output = capsys.readouterr()
    attack_ids = output.out.splitlines()
    assert output.err == ""
    assert len(attack_ids) == 3

    facts = Ledger.open(repo).read()
    attacks = [fact for fact in facts if isinstance(fact, AttackFact)]
    assert [fact.id for fact in attacks] == attack_ids
    assert len(facts) == 4
    assert {fact.hate_scenario for fact in attacks} == {
        "The boundary behavior loses data.",
        "The consequence behavior loses data.",
        "The omission behavior loses data.",
    }

    assert main(["collide", "--case", case_id]) == 0
    collision_output = capsys.readouterr()
    collision_path = repo / ".falsiq" / "cases" / case_id / "collisions" / "1.md"
    assert collision_output.err == ""
    assert collision_output.out == f"{collision_path}\n"
    rendered = collision_path.read_text()
    assert all(attack_id in rendered for attack_id in attack_ids)
    assert "The discarded behavior loses data." not in rendered
    assert "falsiq rule" in rendered


def test_attack_add_rejects_tampered_selection_without_mutating_ledger(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    case_id = initialize_case(repo, monkeypatch, capsys)
    candidates = [
        make_candidate(case_id, "one", klass="boundary", settles=2),
        make_candidate(case_id, "two", klass="consequence", settles=1),
    ]
    envelope = build_selection_envelope(case_id, 1, candidates).model_dump(mode="json")
    envelope["selected"] = envelope["selected"][:1]
    path = repo / "tampered.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    ledger_path = repo / ".falsiq" / "ledger.jsonl"
    before = ledger_path.read_bytes()

    assert main(["attack", "add", "-f", str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "deterministic selection policy" in output.err
    assert ledger_path.read_bytes() == before


def test_attack_add_enforces_one_batch_and_evidence_gated_round_two(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    case_id = initialize_case(repo, monkeypatch, capsys)
    first_path = write_envelope(
        repo / "round-1.json",
        case_id,
        1,
        [
            make_candidate(case_id, "one", klass="boundary", settles=2),
            make_candidate(case_id, "two", klass="consequence", settles=1),
        ],
    )
    assert main(["attack", "add", "-f", str(first_path)]) == 0
    capsys.readouterr()
    ledger_path = repo / ".falsiq" / "ledger.jsonl"
    before_duplicate = ledger_path.read_bytes()

    assert main(["attack", "add", "-f", str(first_path)]) == 2
    duplicate_output = capsys.readouterr()
    assert "round 1 already exists" in duplicate_output.err
    assert ledger_path.read_bytes() == before_duplicate

    round_two_path = write_envelope(
        repo / "round-2.json",
        case_id,
        2,
        [make_candidate(case_id, "round-two", klass="conflict", settles=1)],
    )
    assert main(["attack", "add", "-f", str(round_two_path)]) == 2
    open_output = capsys.readouterr()
    assert "round 1 is still open" in open_output.err

    ledger = Ledger.open(repo)
    attacks = [fact for fact in ledger.read() if isinstance(fact, AttackFact)]
    intended_rulings = []
    for attack in attacks:
        intended_rulings.append(
            RulingFact(
                id=new_ulid(),
                ts=utc_timestamp(),
                case_id=case_id,
                attack_id=attack.id,
                verdict="intended",
            )
        )
    ledger.append_batch(intended_rulings)

    assert main(["attack", "add", "-f", str(round_two_path)]) == 2
    settled_output = capsys.readouterr()
    assert "amend or forbidden" in settled_output.err

    first_ruling = intended_rulings[0]
    ledger.append(
        RulingFact(
            id=new_ulid(),
            ts=utc_timestamp(),
            case_id=case_id,
            attack_id=first_ruling.attack_id,
            verdict="forbidden",
            supersedes=first_ruling.id,
        )
    )
    assert main(["attack", "add", "-f", str(round_two_path)]) == 0
    allowed_output = capsys.readouterr()
    assert allowed_output.err == ""
    assert len(allowed_output.out.splitlines()) == 1


def test_attack_add_handles_degenerate_empty_pool_without_a_ledger_fact(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    case_id = initialize_case(repo, monkeypatch, capsys)
    path = write_envelope(repo / "empty.json", case_id, 1, [])
    ledger_path = repo / ".falsiq" / "ledger.jsonl"
    before = ledger_path.read_bytes()

    assert main(["attack", "add", "-f", str(path)]) == 0
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == ""
    assert ledger_path.read_bytes() == before


def test_collide_requires_a_known_case_with_open_attacks(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    case_id = initialize_case(repo, monkeypatch, capsys)

    assert main(["collide", "--case", case_id]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "no open attacks" in output.err

    unknown = new_ulid()
    assert main(["collide", "--case", unknown]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "unknown case" in output.err


def test_attack_add_reports_malformed_json_as_one_actionable_error(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    initialize_case(repo, monkeypatch, capsys)
    malformed = repo / "bad.json"
    malformed.write_text("{not json", encoding="utf-8")

    assert main(["attack", "add", "-f", str(malformed)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err.startswith("error: Invalid JSON")
    assert "Traceback" not in output.err


def test_concurrent_ledger_change_rejects_the_whole_attack_batch(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    case_id = initialize_case(repo, monkeypatch, capsys)
    path = write_envelope(
        repo / "round-1.json",
        case_id,
        1,
        [
            make_candidate(case_id, "one", klass="boundary", settles=2),
            make_candidate(case_id, "two", klass="consequence", settles=1),
        ],
    )
    real_append_attack_round = cli_module.append_attack_round

    def append_after_concurrent_change(*args, **kwargs):
        concurrent_case = new_ulid()
        Ledger.open(repo).append(
            IntentFact(
                id=concurrent_case,
                ts=utc_timestamp(),
                case_id=concurrent_case,
                text="Concurrent case",
                source="user",
            )
        )
        return real_append_attack_round(*args, **kwargs)

    monkeypatch.setattr(cli_module, "append_attack_round", append_after_concurrent_change)

    assert main(["attack", "add", "-f", str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "ledger head changed" in output.err
    assert "retry the command" in output.err
    facts = Ledger.open(repo).read()
    assert len([fact for fact in facts if isinstance(fact, IntentFact)]) == 2
    assert not any(isinstance(fact, AttackFact) for fact in facts)
