from __future__ import annotations

import json
from pathlib import Path

from falsiq.attacks import build_selection_envelope
from falsiq.cli import main
from falsiq.facts import IntentFact, ReviewRoundFact, SchemaMigrationFact
from falsiq.ledger import Ledger


def test_migrated_non_git_case_pins_profile_and_complete_empty_round(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    workspace = tmp_path / "workspace"
    state_root = tmp_path / "state"
    workspace.mkdir()
    state_root.mkdir()
    monkeypatch.chdir(workspace)
    monkeypatch.setenv("FALSIQ_STATE_ROOT", str(state_root))

    assert main(["init"]) == 0
    capsys.readouterr()
    assert main(["migrate", "--to", "2"]) == 0
    assert "Dry run" in capsys.readouterr().out
    assert not any(isinstance(fact, SchemaMigrationFact) for fact in Ledger.open().read())

    assert main(["migrate", "--to", "2", "--apply"]) == 0
    capsys.readouterr()
    assert main(["intent", "--profile", "writing", "Draft a welcome email"]) == 0
    case_id = capsys.readouterr().out.strip()

    envelope = build_selection_envelope(case_id, 1, [])
    path = workspace / "round.json"
    path.write_text(envelope.model_dump_json(), encoding="utf-8")
    assert main(["review", "add", "-f", str(path)]) == 0
    assert capsys.readouterr().out == ""

    facts = Ledger.open().read()
    intent = next(fact for fact in facts if isinstance(fact, IntentFact))
    round_fact = next(fact for fact in facts if isinstance(fact, ReviewRoundFact))
    assert intent.schema_version == 2
    assert intent.profile_name == "writing"
    assert round_fact.selected_attack_ids == []
    assert set(round_fact.prompt_versions) == {
        "boundary",
        "consequence",
        "prototype",
        "conflict",
        "omission",
    }

    assert main(["outcomes", "report", "--since", "2026-07-29T00:00:00.000Z", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert case_id in report["cases"]
