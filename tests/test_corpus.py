from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from falsiq.benchmark import EvalTask
from falsiq.corpus import (
    CorpusError,
    HoldoutEntry,
    build_holdout_manifest,
    read_private_holdout_task,
    select_holdout,
)


def make_task(task_id: str, stratum: str, *, curated: bool = True) -> EvalTask:
    requirements = []
    if stratum != "control":
        requirements = [
            {
                "id": "LR1",
                "text": f"hidden behavior for {task_id}",
                "discriminator": f"probe for {task_id}",
                "severity": "rework",
            }
        ]
    payload: dict[str, object] = {
        "schema_version": 1,
        "task_id": task_id,
        "stratum": stratum,
        "vague_prompt": f"implement {task_id}",
        "context": {"repo_fixture": f"fixtures/{task_id}"},
        "latent_requirements": requirements,
        "annoyance_budget": 2,
        "human_curated": curated,
    }
    if stratum == "mined":
        payload["provenance"] = {
            "source_urls": [f"https://github.com/example/project/issues/{task_id[1:]}"],
            "source_revision": f"revision-{task_id}",
            "license": "MIT",
            "curator_notes": "Confirmed from review history.",
        }
    return EvalTask.model_validate(payload)


def approved_corpus() -> list[EvalTask]:
    return [
        *(make_task(f"s{index:02d}", "synthetic") for index in range(10)),
        *(make_task(f"m{index:02d}", "mined") for index in range(10)),
        *(make_task(f"c{index:02d}", "control") for index in range(10)),
    ]


def test_seeded_holdout_is_stable_stratified_and_order_independent() -> None:
    tasks = approved_corpus()

    first = select_holdout(tasks, seed="approval-2026-07-15")
    second = select_holdout(list(reversed(tasks)), seed="approval-2026-07-15")

    assert [task.task_id for task in first] == [task.task_id for task in second]
    assert len(first) == 10
    assert sum(task.stratum == "synthetic" for task in first) == 3
    assert sum(task.stratum == "mined" for task in first) == 3
    assert sum(task.stratum == "control" for task in first) == 4
    assert {task.task_id for task in first} != {
        task.task_id for task in select_holdout(tasks, seed="another-seed")
    }


def test_split_requires_unique_human_curated_tasks_and_sufficient_strata() -> None:
    tasks = approved_corpus()
    tasks[0] = make_task("s00", "synthetic", curated=False)
    with pytest.raises(CorpusError, match="human-curated"):
        select_holdout(tasks, seed="seed")

    tasks = approved_corpus()
    with pytest.raises(CorpusError, match="duplicate task ID"):
        select_holdout([*tasks, tasks[0]], seed="seed")

    with pytest.raises(CorpusError, match="requires 4 control"):
        select_holdout(
            [task for task in approved_corpus() if task.task_id != "c09"][:20],
            seed="seed",
        )


def test_manifest_contains_only_ids_strata_and_salted_hashes() -> None:
    tasks = approved_corpus()
    manifest = build_holdout_manifest(
        tasks,
        corpus_version="v0-approved-1",
        seed="seed",
        salt=b"private salt",
    )

    dumped = manifest.model_dump(mode="json")
    encoded = json.dumps(dumped)
    assert len(manifest.tasks) == 10
    assert all(len(entry.salted_hash) == 64 for entry in manifest.tasks)
    assert "latent_requirements" not in encoded
    assert "vague_prompt" not in encoded
    assert manifest.split_policy == {"synthetic": 3, "mined": 3, "control": 4}


@pytest.mark.parametrize("task_id", ["../outside", "synthetic/01", "Synthetic_01"])
def test_manifest_task_ids_cannot_address_unsafe_paths(task_id: str) -> None:
    with pytest.raises(ValueError, match="stable lowercase token"):
        HoldoutEntry(task_id=task_id, stratum="synthetic", salted_hash="0" * 64)


def test_manifest_cannot_bypass_human_review_gate() -> None:
    tasks = approved_corpus()
    tasks[0] = tasks[0].model_copy(update={"human_curated": False})

    with pytest.raises(CorpusError, match="human-curated"):
        build_holdout_manifest(
            tasks,
            corpus_version="v0-approved-1",
            seed="seed",
            salt=b"private salt",
        )

    selected = select_holdout(approved_corpus(), seed="seed")
    with pytest.raises(CorpusError, match="exactly 10 tasks in each stratum"):
        build_holdout_manifest(
            selected,
            corpus_version="v0-approved-1",
            seed="seed",
            salt=b"private salt",
        )


def write_private_tasks(root: Path, tasks: list[EvalTask]) -> None:
    root.mkdir()
    for task in tasks:
        (root / f"{task.task_id}.json").write_text(task.model_dump_json(indent=2), encoding="utf-8")


def test_private_read_verifies_hash_and_logs_access_before_return(tmp_path: Path) -> None:
    tasks = approved_corpus()
    selected = select_holdout(tasks, seed="seed")
    salt = b"private salt"
    manifest = build_holdout_manifest(
        tasks,
        corpus_version="v0-approved-1",
        seed="seed",
        salt=salt,
    )
    store = tmp_path / "private"
    write_private_tasks(store, selected)
    access_log = tmp_path / "access.jsonl"

    loaded = read_private_holdout_task(
        selected[0].task_id,
        manifest=manifest,
        store=store,
        salt=salt,
        access_log=access_log,
        actor="official-runner",
        purpose="held-out scoring",
        timestamp="2026-07-15T20:00:00.000Z",
    )

    assert loaded == selected[0]
    events = [json.loads(line) for line in access_log.read_text().splitlines()]
    assert events == [
        {
            "actor": "official-runner",
            "corpus_version": "v0-approved-1",
            "purpose": "held-out scoring",
            "task_id": selected[0].task_id,
            "ts": "2026-07-15T20:00:00.000Z",
        }
    ]
    assert stat.S_IMODE(access_log.stat().st_mode) == 0o600


def test_failed_or_tampered_reads_still_burn_freshness(tmp_path: Path) -> None:
    tasks = approved_corpus()
    selected = select_holdout(tasks, seed="seed")
    manifest = build_holdout_manifest(
        tasks,
        corpus_version="v0-approved-1",
        seed="seed",
        salt=b"correct salt",
    )
    store = tmp_path / "private"
    write_private_tasks(store, selected)
    access_log = tmp_path / "access.jsonl"

    with pytest.raises(CorpusError, match="hash mismatch"):
        read_private_holdout_task(
            selected[0].task_id,
            manifest=manifest,
            store=store,
            salt=b"wrong salt",
            access_log=access_log,
            actor="runner",
            purpose="scoring",
        )
    (store / f"{selected[1].task_id}.json").unlink()
    with pytest.raises(CorpusError, match="could not read"):
        read_private_holdout_task(
            selected[1].task_id,
            manifest=manifest,
            store=store,
            salt=b"correct salt",
            access_log=access_log,
            actor="runner",
            purpose="scoring",
        )

    assert len(access_log.read_text().splitlines()) == 2


def test_private_read_rejects_unknown_task_without_logging(tmp_path: Path) -> None:
    tasks = approved_corpus()
    manifest = build_holdout_manifest(
        tasks,
        corpus_version="v0",
        seed="seed",
        salt=b"salt",
    )
    access_log = tmp_path / "access.jsonl"

    with pytest.raises(CorpusError, match="not in the holdout manifest"):
        read_private_holdout_task(
            "unknown",
            manifest=manifest,
            store=tmp_path,
            salt=b"salt",
            access_log=access_log,
            actor="runner",
            purpose="scoring",
        )
    assert not access_log.exists()
