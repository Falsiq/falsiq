from __future__ import annotations

from pathlib import Path

import pytest

from falsiq.facts import (
    IntentFact,
    ReviewRoundFact,
    SchemaMigrationFact,
)
from falsiq.ledger import Ledger, LedgerValidationError

CASE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
MIGRATION_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
ROUND_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
TS = "2026-07-29T12:00:00.000Z"
DIGEST = "a" * 64
PROMPT_VERSIONS = {
    "boundary": DIGEST,
    "consequence": DIGEST,
    "prototype": DIGEST,
    "conflict": DIGEST,
    "omission": DIGEST,
}


def external_ledger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Ledger:
    workspace = tmp_path / "workspace"
    state = tmp_path / "state"
    workspace.mkdir()
    state.mkdir()
    monkeypatch.chdir(workspace)
    monkeypatch.setenv("FALSIQ_STATE_ROOT", str(state))
    return Ledger.initialize()


def test_external_state_root_supports_non_git_workspaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = external_ledger(tmp_path, monkeypatch)
    assert ledger.state_dir == (tmp_path / "state").resolve()
    assert ledger.root == (tmp_path / "workspace").resolve()
    assert Ledger.open().state_dir == ledger.state_dir


def test_external_state_root_must_exist_and_must_not_be_a_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / "missing"
    monkeypatch.setenv("FALSIQ_STATE_ROOT", str(missing))
    with pytest.raises(LedgerValidationError, match="existing directory"):
        Ledger.initialize()

    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    monkeypatch.setenv("FALSIQ_STATE_ROOT", str(link))
    with pytest.raises(LedgerValidationError, match="symbolic link"):
        Ledger.initialize()


def test_schema_migration_changes_future_write_version_without_rewriting_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = external_ledger(tmp_path, monkeypatch)
    root = IntentFact(
        schema_version=1,
        id=CASE_ID,
        ts=TS,
        case_id=CASE_ID,
        text="Build the feature",
        source="user",
    )
    ledger.append(root)
    before = ledger.path.read_bytes()
    assert ledger.write_schema_version() == 1

    marker = SchemaMigrationFact(
        id=MIGRATION_ID,
        ts=TS,
        case_id=MIGRATION_ID,
        from_version=1,
        to_version=2,
    )
    ledger.append(marker)
    assert ledger.path.read_bytes().startswith(before)
    assert ledger.write_schema_version() == 2

    with pytest.raises(LedgerValidationError, match="already migrated"):
        ledger.append(
            SchemaMigrationFact(
                id="01ARZ3NDEKTSV4RRFFQ69G5FAY",
                ts=TS,
                case_id="01ARZ3NDEKTSV4RRFFQ69G5FAY",
                from_version=1,
                to_version=2,
            )
        )


def test_review_round_references_only_same_round_attacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = external_ledger(tmp_path, monkeypatch)
    ledger.append(
        IntentFact(
            schema_version=1,
            id=CASE_ID,
            ts=TS,
            case_id=CASE_ID,
            text="Build the feature",
            source="user",
        )
    )
    ledger.append(
        ReviewRoundFact(
            id=ROUND_ID,
            ts=TS,
            case_id=CASE_ID,
            round=1,
            max_rounds=2,
            prompt_versions=PROMPT_VERSIONS,
            policy_digest=DIGEST,
            profile_name="coding",
            profile_digest=DIGEST,
        )
    )
    state = ledger.state(CASE_ID)
    assert state["review_rounds"][0]["prompt_versions"] == PROMPT_VERSIONS
