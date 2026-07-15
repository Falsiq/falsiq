from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

import falsiq.corpus as corpus_module
from falsiq.corpus import CorpusError, prepare_corpus_release, read_owner_secret_file


def _task_payload(task_id: str, stratum: str, *, curated: bool = True) -> dict[str, object]:
    requirements: list[dict[str, str]] = []
    if stratum != "control":
        requirements.append(
            {
                "id": "LR1",
                "text": f"private behavior for {task_id}",
                "discriminator": f"private probe for {task_id}",
                "severity": "rework",
            }
        )
    payload: dict[str, object] = {
        "schema_version": 1,
        "task_id": task_id,
        "stratum": stratum,
        "vague_prompt": f"public prompt for {task_id}",
        "context": {
            "repo_fixture": f"fixtures/{task_id}",
            "notes": "offline test fixture",
        },
        "latent_requirements": requirements,
        "annoyance_budget": 2,
        "human_curated": curated,
    }
    if stratum == "mined":
        payload["provenance"] = {
            "source_urls": [f"https://github.com/example/project/issues/{task_id[-2:]}"],
            "source_revision": f"revision-{task_id}",
            "license": "MIT",
            "curator_notes": "Human checked the primary source.",
        }
    return payload


def _write_source(root: Path, *, curated: bool = True) -> None:
    (root / "tasks").mkdir(parents=True)
    for stratum in ("synthetic", "mined", "control"):
        for index in range(1, 11):
            task_id = f"{stratum}_{index:02d}"
            payload = _task_payload(task_id, stratum, curated=curated)
            (root / "tasks" / f"{task_id}.json").write_text(
                json.dumps(payload, indent=2), encoding="utf-8"
            )
            fixture = root / "fixtures" / task_id
            fixture.mkdir(parents=True)
            (fixture / "task.py").write_text(f'TASK_ID = "{task_id}"\n', encoding="utf-8")
            if task_id == "synthetic_01":
                (fixture / "nested").mkdir()
                (fixture / "nested" / "data.txt").write_text("offline\n", encoding="utf-8")


def _release_paths(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    repository = tmp_path / "repository"
    public_parent = repository / "eval"
    private_parent = tmp_path / "owner-private"
    public_parent.mkdir(parents=True)
    private_parent.mkdir()
    return (
        repository,
        public_parent / "corpus-v0",
        private_parent / "corpus-v0-holdout",
        private_parent,
    )


def _materialize(tmp_path: Path, source: Path):
    repository, public_output, private_output, _ = _release_paths(tmp_path)
    plan = prepare_corpus_release(
        source=source,
        public_output=public_output,
        private_output=private_output,
        repository_root=repository,
        corpus_version="v0-approved-1",
        seed="split seed not printed",
        salt=b"salt bytes not printed",
    )
    return plan, public_output, private_output


def test_release_materializes_twenty_dev_and_ten_private_tasks(tmp_path: Path) -> None:
    source = tmp_path / "approved-source"
    _write_source(source)

    plan, public_output, private_output = _materialize(tmp_path, source)

    public_tasks = sorted((public_output / "tasks").glob("*.json"))
    private_tasks = sorted((private_output / "tasks").glob("*.json"))
    assert len(public_tasks) == 20
    assert len(private_tasks) == 10
    assert {path.stem for path in public_tasks} == {
        entry.task_id for entry in plan.development_tasks
    }
    assert {path.stem for path in private_tasks} == {
        entry.task_id for entry in plan.holdout_manifest.tasks
    }
    assert not {path.stem for path in public_tasks}.intersection(
        path.stem for path in private_tasks
    )
    assert Counter(entry.stratum for entry in plan.development_tasks) == {
        "synthetic": 7,
        "mined": 7,
        "control": 6,
    }
    assert Counter(entry.stratum for entry in plan.holdout_manifest.tasks) == {
        "synthetic": 3,
        "mined": 3,
        "control": 4,
    }
    assert sorted(path.name for path in (public_output / "fixtures").iterdir()) == sorted(
        path.stem for path in public_tasks
    )
    assert sorted(path.name for path in (private_output / "fixtures").iterdir()) == sorted(
        path.stem for path in private_tasks
    )
    if os.name != "nt":
        assert stat.S_IMODE(private_output.stat().st_mode) == 0o700
        assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in private_tasks)


def test_release_does_not_require_descriptor_chmod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "approved-source"
    _write_source(source)
    monkeypatch.delattr(corpus_module.os, "fchmod")

    plan, public_output, private_output = _materialize(tmp_path, source)

    assert len(plan.holdout_manifest.tasks) == 10
    assert public_output.is_dir()
    assert private_output.is_dir()


def test_release_requires_every_task_to_be_individually_human_curated(
    tmp_path: Path,
) -> None:
    source = tmp_path / "draft-source"
    _write_source(source)
    task_path = source / "tasks" / "synthetic_03.json"
    payload = json.loads(task_path.read_text(encoding="utf-8"))
    payload["human_curated"] = False
    task_path.write_text(json.dumps(payload), encoding="utf-8")
    repository, public_output, private_output, _ = _release_paths(tmp_path)

    with pytest.raises(CorpusError, match="human-curated"):
        prepare_corpus_release(
            source=source,
            public_output=public_output,
            private_output=private_output,
            repository_root=repository,
            corpus_version="v0",
            seed="seed",
            salt=b"salt",
        )

    assert not public_output.exists()
    assert not private_output.exists()


def test_release_rejects_traversal_and_fixture_symlinks(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_source(source)
    task_path = source / "tasks" / "control_01.json"
    payload = json.loads(task_path.read_text(encoding="utf-8"))
    payload["context"]["repo_fixture"] = "../outside"
    task_path.write_text(json.dumps(payload), encoding="utf-8")
    repository, public_output, private_output, _ = _release_paths(tmp_path)

    with pytest.raises(CorpusError, match="invalid task"):
        prepare_corpus_release(
            source=source,
            public_output=public_output,
            private_output=private_output,
            repository_root=repository,
            corpus_version="v0",
            seed="seed",
            salt=b"salt",
        )

    payload["context"]["repo_fixture"] = "fixtures/control_01"
    task_path.write_text(json.dumps(payload), encoding="utf-8")
    fixture_file = source / "fixtures" / "control_01" / "task.py"
    fixture_file.unlink()
    fixture_file.symlink_to(source / "tasks" / "control_01.json")

    with pytest.raises(CorpusError, match="symbolic link"):
        prepare_corpus_release(
            source=source,
            public_output=public_output,
            private_output=private_output,
            repository_root=repository,
            corpus_version="v0",
            seed="seed",
            salt=b"salt",
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing-task", "exactly 10 tasks"),
        ("wrong-filename", "filename must match"),
        ("non-json-task", "only JSON"),
        ("missing-fixture", "is missing"),
        ("fixture-not-directory", "real directory"),
        ("fixture-outside-root", "rooted below fixtures"),
        ("reserved-fixture-name", "reserved or ambiguous"),
    ],
)
def test_release_rejects_malformed_corpus_layouts(
    tmp_path: Path, mutation: str, message: str
) -> None:
    source = tmp_path / "source"
    _write_source(source)
    task_path = source / "tasks" / "control_01.json"
    fixture = source / "fixtures" / "control_01"
    if mutation == "missing-task":
        task_path.unlink()
    elif mutation == "wrong-filename":
        task_path.rename(source / "tasks" / "renamed.json")
    elif mutation == "non-json-task":
        (source / "tasks" / "notes.txt").write_text("not a task", encoding="utf-8")
    elif mutation == "missing-fixture":
        (fixture / "task.py").unlink()
        fixture.rmdir()
    elif mutation == "fixture-not-directory":
        (fixture / "task.py").unlink()
        fixture.rmdir()
        fixture.write_text("not a directory", encoding="utf-8")
    elif mutation == "fixture-outside-root":
        payload = json.loads(task_path.read_text(encoding="utf-8"))
        payload["context"]["repo_fixture"] = "other/control_01"
        task_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "reserved-fixture-name":
        (fixture / "task.py").rename(fixture / "NUL")
    repository, public_output, private_output, _ = _release_paths(tmp_path)

    with pytest.raises(CorpusError, match=message):
        prepare_corpus_release(
            source=source,
            public_output=public_output,
            private_output=private_output,
            repository_root=repository,
            corpus_version="v0",
            seed="seed",
            salt=b"salt",
            dry_run=True,
        )


def test_public_manifest_is_redacted_and_dry_run_writes_nothing(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_source(source)
    repository, public_output, private_output, _ = _release_paths(tmp_path)

    dry_plan = prepare_corpus_release(
        source=source,
        public_output=public_output,
        private_output=private_output,
        repository_root=repository,
        corpus_version="v0",
        seed="secret-seed",
        salt=b"secret-salt",
        dry_run=True,
    )

    assert not public_output.exists()
    assert not private_output.exists()
    encoded_plan = dry_plan.model_dump_json()
    assert "secret-seed" not in encoded_plan
    assert "secret-salt" not in encoded_plan
    assert "public prompt" not in encoded_plan
    assert "private behavior" not in encoded_plan

    plan, public_output, _ = _materialize(tmp_path / "materialized", source)
    manifest_text = (public_output / "holdout-manifest.json").read_text(encoding="utf-8")
    assert json.loads(manifest_text) == plan.holdout_manifest.model_dump(mode="json")
    assert "vague_prompt" not in manifest_text
    assert "latent_requirements" not in manifest_text
    assert "private behavior" not in manifest_text


def test_release_rejects_overlapping_or_repository_private_outputs(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_source(source)
    repository, public_output, private_output, private_parent = _release_paths(tmp_path)

    with pytest.raises(CorpusError, match="overlap"):
        prepare_corpus_release(
            source=source,
            public_output=public_output,
            private_output=public_output / "holdout",
            repository_root=repository,
            corpus_version="v0",
            seed="seed",
            salt=b"salt",
            dry_run=True,
        )

    with pytest.raises(CorpusError, match="outside the repository"):
        prepare_corpus_release(
            source=source,
            public_output=public_output,
            private_output=repository / "private-holdout",
            repository_root=repository,
            corpus_version="v0",
            seed="seed",
            salt=b"salt",
            dry_run=True,
        )

    repository_source = repository / "drafts"
    _write_source(repository_source)
    with pytest.raises(CorpusError, match="source must be outside the repository"):
        prepare_corpus_release(
            source=repository_source,
            public_output=public_output,
            private_output=private_output,
            repository_root=repository,
            corpus_version="v0",
            seed="seed",
            salt=b"salt",
            dry_run=True,
        )

    existing = private_parent / "existing"
    existing.mkdir()
    with pytest.raises(CorpusError, match="must not already exist"):
        prepare_corpus_release(
            source=source,
            public_output=public_output,
            private_output=existing,
            repository_root=repository,
            corpus_version="v0",
            seed="seed",
            salt=b"salt",
            dry_run=True,
        )


def test_release_rejects_case_insensitive_output_alias(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_source(source)
    repository, public_output, private_output, _ = _release_paths(tmp_path)
    (public_output.parent / public_output.name.upper()).mkdir()

    with pytest.raises(CorpusError, match="case-insensitive alias"):
        prepare_corpus_release(
            source=source,
            public_output=public_output,
            private_output=private_output,
            repository_root=repository,
            corpus_version="v0",
            seed="seed",
            salt=b"salt",
            dry_run=True,
        )


def test_publication_failure_rolls_back_both_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    _write_source(source)
    repository, public_output, private_output, private_parent = _release_paths(tmp_path)
    original_publish = corpus_module._publish_directory
    calls = 0
    targets: list[Path] = []

    def fail_second_publish(staged: Path, target: Path) -> None:
        nonlocal calls
        calls += 1
        targets.append(target)
        if calls == 2:
            raise OSError("injected publication failure")
        original_publish(staged, target)

    monkeypatch.setattr(corpus_module, "_publish_directory", fail_second_publish)

    with pytest.raises(CorpusError, match="could not publish"):
        prepare_corpus_release(
            source=source,
            public_output=public_output,
            private_output=private_output,
            repository_root=repository,
            corpus_version="v0",
            seed="seed",
            salt=b"salt",
        )

    assert not public_output.exists()
    assert not private_output.exists()
    assert targets == [private_output, public_output]
    assert not list((repository / "eval").glob(".*.stage-*"))
    assert not list(private_parent.glob(".*.stage-*"))


def test_staging_failure_leaves_no_output_or_staging_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    _write_source(source)
    repository, public_output, private_output, private_parent = _release_paths(tmp_path)
    original_mkdtemp = corpus_module.tempfile.mkdtemp
    calls = 0

    def fail_second_stage(*args, **kwargs) -> str:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected staging failure")
        return original_mkdtemp(*args, **kwargs)

    monkeypatch.setattr(corpus_module.tempfile, "mkdtemp", fail_second_stage)

    with pytest.raises(CorpusError, match="could not publish"):
        prepare_corpus_release(
            source=source,
            public_output=public_output,
            private_output=private_output,
            repository_root=repository,
            corpus_version="v0",
            seed="seed",
            salt=b"salt",
        )

    assert not public_output.exists()
    assert not private_output.exists()
    assert not list((repository / "eval").glob(".*.stage-*"))
    assert not list(private_parent.glob(".*.stage-*"))


def test_secret_reader_rejects_nonprivate_symlinked_and_empty_files(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.write_text("value", encoding="utf-8")
    os.chmod(secret, 0o644)
    if os.name != "nt":
        with pytest.raises(CorpusError, match="owner-only"):
            read_owner_secret_file(secret, label="seed")

    os.chmod(secret, 0o600)
    link = tmp_path / "link"
    link.symlink_to(secret)
    with pytest.raises(CorpusError, match="symbolic link"):
        read_owner_secret_file(link, label="seed")

    secret.write_bytes(b"")
    with pytest.raises(CorpusError, match="must not be empty"):
        read_owner_secret_file(secret, label="seed")


def test_prepare_script_reads_owner_only_secret_files_without_echoing_them(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    _write_source(source)
    repository, public_output, private_output, _ = _release_paths(tmp_path)
    seed_file = tmp_path / "seed"
    salt_file = tmp_path / "salt"
    seed_file.write_text("cli-secret-seed", encoding="utf-8")
    salt_file.write_bytes(b"cli-secret-salt")
    os.chmod(seed_file, 0o600)
    os.chmod(salt_file, 0o600)
    script = Path(__file__).parents[1] / "eval" / "prepare_corpus.py"

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--source",
            str(source),
            "--public-output",
            str(public_output),
            "--private-output",
            str(private_output),
            "--corpus-version",
            "v0-approved-1",
            "--seed-file",
            str(seed_file),
            "--salt-file",
            str(salt_file),
            "--dry-run",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "cli-secret-seed" not in result.stdout + result.stderr
    assert "cli-secret-salt" not in result.stdout + result.stderr
    assert len(json.loads(result.stdout)["holdout_manifest"]["tasks"]) == 10
    assert not public_output.exists()
    assert not private_output.exists()
