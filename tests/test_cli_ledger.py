from __future__ import annotations

import json
import subprocess
from pathlib import Path

from falsiq.cli import main
from falsiq.facts import new_ulid


def git_repo(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    return path


def test_init_intent_log_and_state_commands(tmp_path: Path, monkeypatch, capsys) -> None:
    repo = git_repo(tmp_path / "repo")
    nested = repo / "nested"
    nested.mkdir()
    monkeypatch.chdir(nested)

    assert main(["init"]) == 0
    init_output = capsys.readouterr()
    assert init_output.err == ""
    assert init_output.out == f"Initialized {repo / '.falsiq'}\n"

    text = "  Preserve this intent verbatim.  "
    assert main(["intent", text]) == 0
    intent_output = capsys.readouterr()
    case_id = intent_output.out.strip()
    assert intent_output.err == ""
    assert len(case_id) == 26

    assert main(["log", "--kind", "intent", "--case", case_id]) == 0
    log_output = capsys.readouterr()
    logged = json.loads(log_output.out)
    assert log_output.err == ""
    assert logged["id"] == case_id
    assert logged["case_id"] == case_id
    assert logged["text"] == text

    assert main(["state", "--json", "--case", case_id]) == 0
    state_output = capsys.readouterr()
    state = json.loads(state_output.out)
    assert state_output.err == ""
    assert state["case_id"] == case_id
    assert state["intents"][0]["text"] == text
    assert state["open_attacks"] == []


def test_state_human_output_is_stable_and_readable(tmp_path: Path, monkeypatch, capsys) -> None:
    repo = git_repo(tmp_path / "repo")
    monkeypatch.chdir(repo)
    assert main(["init"]) == 0
    capsys.readouterr()
    assert main(["state"]) == 0
    assert capsys.readouterr().out == "No cases.\n"

    assert main(["intent", "Ship it"]) == 0
    case_id = capsys.readouterr().out.strip()
    assert main(["state"]) == 0
    first = capsys.readouterr().out
    assert main(["state"]) == 0
    second = capsys.readouterr().out

    assert first == second
    assert f"Case {case_id}\n" in first
    assert "Intent: Ship it\n" in first
    assert "Open attacks: 0\n" in first


def test_cli_errors_are_concise_and_do_not_mutate_the_ledger(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    monkeypatch.chdir(repo)

    assert main(["intent", "Before init"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "error:" in output.err
    assert "falsiq init" in output.err

    assert main(["init"]) == 0
    capsys.readouterr()
    ledger_path = repo / ".falsiq" / "ledger.jsonl"
    before = ledger_path.read_bytes()
    assert main(["intent", "   "]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "error:" in output.err
    assert "intent text" in output.err
    assert ledger_path.read_bytes() == before


def test_cli_reports_integrity_failure_with_line_number(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    monkeypatch.chdir(repo)
    assert main(["init"]) == 0
    capsys.readouterr()
    (repo / ".falsiq" / "ledger.jsonl").write_text("bad json\n", encoding="utf-8")

    assert main(["state", "--json"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "error:" in output.err
    assert "line 1" in output.err


def test_cli_rejects_unknown_case_without_traceback(tmp_path: Path, monkeypatch, capsys) -> None:
    repo = git_repo(tmp_path / "repo")
    monkeypatch.chdir(repo)
    assert main(["init"]) == 0
    capsys.readouterr()

    assert main(["state", "--case", new_ulid(timestamp_ms=1, randomness=b"\0" * 10)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "error: unknown case" in output.err
