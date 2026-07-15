from __future__ import annotations

import json
import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import falsiq.sandbox as sandbox_module
from falsiq.cli import main
from falsiq.ledger import Ledger, LedgerValidationError
from falsiq.sandbox import (
    LOCK_PATH,
    MANIFEST_PATH,
    SandboxError,
    _run_git,
    create_sandbox,
    reap_sandboxes,
)

ATTACK_ID = "01J00000000000000000000000"
SECOND_ATTACK_ID = "01J00000000000000000000001"


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=check,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "target"
    root.mkdir()
    git(root, "init", "--initial-branch=main")
    git(root, "config", "user.email", "tests@example.com")
    git(root, "config", "user.name", "Falsiq Tests")
    (root / "tracked.txt").write_text("base\n", encoding="utf-8")
    Ledger.initialize(root)
    git(root, "add", "tracked.txt", ".falsiq")
    git(root, "commit", "-m", "base")
    return root


def manifest(repo: Path) -> dict[str, object]:
    return json.loads((repo / MANIFEST_PATH).read_text(encoding="utf-8"))


def branches(repo: Path) -> set[str]:
    result = git(repo, "for-each-ref", "--format=%(refname:short)", "refs/heads/")
    return set(result.stdout.splitlines())


def registered_worktrees(repo: Path) -> set[Path]:
    result = git(repo, "worktree", "list", "--porcelain")
    return {
        Path(line.removeprefix("worktree ")).resolve()
        for line in result.stdout.splitlines()
        if line.startswith("worktree ")
    }


def test_init_adds_managed_ignore_without_replacing_user_rules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "target"
    root.mkdir()
    git(root, "init", "--initial-branch=main")
    state_dir = root / ".falsiq"
    state_dir.mkdir()
    ignore_path = state_dir / ".gitignore"
    ignore_path.write_bytes(b"# local rules\n*.private")
    monkeypatch.chdir(root)

    assert main(["init"]) == 0
    capsys.readouterr()
    first = ignore_path.read_bytes()
    assert first == b"# local rules\n*.private\n/sandbox/\n"

    assert main(["init"]) == 0
    capsys.readouterr()
    assert ignore_path.read_bytes() == first


def test_init_preserves_an_existing_managed_ignore_byte_for_byte(tmp_path: Path) -> None:
    root = tmp_path / "target"
    root.mkdir()
    git(root, "init", "--initial-branch=main")
    state_dir = root / ".falsiq"
    state_dir.mkdir()
    ignore_path = state_dir / ".gitignore"
    before = b"# before\r\n/sandbox/\r\n*.local\r\n"
    ignore_path.write_bytes(before)

    Ledger.initialize(root)

    assert ignore_path.read_bytes() == before


def test_init_rejects_a_symlinked_managed_ignore(tmp_path: Path) -> None:
    root = tmp_path / "target"
    root.mkdir()
    git(root, "init", "--initial-branch=main")
    state_dir = root / ".falsiq"
    state_dir.mkdir()
    outside = tmp_path / "outside-ignore"
    outside.write_text("keep\n", encoding="utf-8")
    (state_dir / ".gitignore").symlink_to(outside)

    with pytest.raises(LedgerValidationError, match="gitignore.*symlink"):
        Ledger.initialize(root)

    assert outside.read_text(encoding="utf-8") == "keep\n"


def test_create_requires_initialized_managed_state(tmp_path: Path) -> None:
    root = tmp_path / "target"
    root.mkdir()
    git(root, "init", "--initial-branch=main")
    git(root, "config", "user.email", "tests@example.com")
    git(root, "config", "user.name", "Falsiq Tests")
    (root / "tracked.txt").write_text("base\n", encoding="utf-8")
    git(root, "add", "tracked.txt")
    git(root, "commit", "-m", "base")

    with pytest.raises(SandboxError, match="falsiq init"):
        create_sandbox(root, ATTACK_ID)

    assert f"falsiq/proto/{ATTACK_ID}" not in branches(root)
    assert not (root / ".falsiq").exists()


def test_create_uses_exact_branch_path_head_and_ignored_manifest(repo: Path) -> None:
    original_head = git(repo, "rev-parse", "HEAD").stdout.strip()
    local_exclude = repo / ".git" / "info" / "exclude"
    exclude_before = local_exclude.read_bytes()
    ignore_before = (repo / ".falsiq" / ".gitignore").read_bytes()

    created = create_sandbox(repo, ATTACK_ID)

    expected = repo / ".falsiq" / "sandbox" / ATTACK_ID
    assert created.attack_id == ATTACK_ID
    assert created.path == expected.resolve()
    assert created.branch == f"falsiq/proto/{ATTACK_ID}"
    assert git(expected, "rev-parse", "HEAD").stdout.strip() == original_head
    assert git(expected, "branch", "--show-current").stdout.strip() == created.branch
    assert expected.resolve() in registered_worktrees(repo)
    assert manifest(repo)["sandboxes"] == {
        ATTACK_ID: {
            "branch": created.branch,
            "head": original_head,
            "path": f".falsiq/sandbox/{ATTACK_ID}",
        }
    }
    assert (repo / LOCK_PATH).is_file()
    ignored = git(repo, "check-ignore", str(repo / MANIFEST_PATH))
    assert ignored.returncode == 0
    assert git(repo, "check-ignore", str(repo / LOCK_PATH)).returncode == 0
    assert local_exclude.read_bytes() == exclude_before
    assert (repo / ".falsiq" / ".gitignore").read_bytes() == ignore_before
    assert git(repo, "status", "--porcelain").stdout == ""


def test_create_from_a_nested_directory_still_uses_the_repository_root(repo: Path) -> None:
    nested = repo / "nested" / "directory"
    nested.mkdir(parents=True)

    created = create_sandbox(nested, ATTACK_ID)

    assert created.path == (repo / ".falsiq" / "sandbox" / ATTACK_ID).resolve()
    assert created.path in registered_worktrees(repo)


def test_create_without_id_reuses_the_fact_ulid_allocator(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sandbox_module, "new_ulid", lambda: SECOND_ATTACK_ID)

    created = create_sandbox(repo)

    assert created.attack_id == SECOND_ATTACK_ID
    assert created.path == (repo / ".falsiq" / "sandbox" / created.attack_id).resolve()


@pytest.mark.parametrize(
    "attack_id",
    [
        "",
        "01j00000000000000000000000",
        "01J0000000000000000000000I",
        "81J00000000000000000000000",
        "../01J00000000000000000000000",
    ],
)
def test_create_rejects_noncanonical_or_unsafe_ids(repo: Path, attack_id: str) -> None:
    with pytest.raises(SandboxError, match="canonical ULID"):
        create_sandbox(repo, attack_id)

    assert "falsiq/proto/" not in "\n".join(branches(repo))
    assert not (repo / ".falsiq" / "sandbox").exists()


def test_create_refuses_duplicate_id_without_changing_manifest(repo: Path) -> None:
    create_sandbox(repo, ATTACK_ID)
    before = (repo / MANIFEST_PATH).read_bytes()

    with pytest.raises(SandboxError, match="already exists"):
        create_sandbox(repo, ATTACK_ID)

    assert (repo / MANIFEST_PATH).read_bytes() == before


def test_parallel_creates_serialize_manifest_and_git_mutations(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_run_git = sandbox_module._run_git
    real_load_manifest = sandbox_module._load_manifest
    first_in_git = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()
    second_loaded = threading.Event()
    load_count = 0
    count_lock = threading.Lock()

    def tracked_load(target: object) -> dict[str, object]:
        nonlocal load_count
        with count_lock:
            load_count += 1
            if load_count == 2:
                second_loaded.set()
        return real_load_manifest(target)

    def blocking_run_git(
        cwd: Path, *args: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        if (
            args[:3] == ("worktree", "add", "-b")
            and len(args) > 3
            and args[3] == f"falsiq/proto/{ATTACK_ID}"
        ):
            first_in_git.set()
            if not release_first.wait(timeout=5):
                raise AssertionError("timed out waiting to release the first create")
        return real_run_git(cwd, *args, check=check)

    def create_second() -> object:
        second_started.set()
        return create_sandbox(repo, SECOND_ATTACK_ID)

    monkeypatch.setattr(sandbox_module, "_load_manifest", tracked_load)
    monkeypatch.setattr(sandbox_module, "_run_git", blocking_run_git)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(create_sandbox, repo, ATTACK_ID)
        assert first_in_git.wait(timeout=5)
        second = executor.submit(create_second)
        assert second_started.wait(timeout=5)
        try:
            assert not second_loaded.wait(timeout=0.2)
        finally:
            release_first.set()
        first.result(timeout=10)
        second.result(timeout=10)

    assert second_loaded.is_set()
    assert set(manifest(repo)["sandboxes"]) == {ATTACK_ID, SECOND_ATTACK_ID}
    assert registered_worktrees(repo) == {
        repo.resolve(),
        (repo / ".falsiq" / "sandbox" / ATTACK_ID).resolve(),
        (repo / ".falsiq" / "sandbox" / SECOND_ATTACK_ID).resolve(),
    }


def test_create_and_reap_share_the_same_transaction_lock(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_run_git = sandbox_module._run_git
    real_load_manifest = sandbox_module._load_manifest
    create_in_git = threading.Event()
    release_create = threading.Event()
    reap_started = threading.Event()
    reap_loaded = threading.Event()
    load_count = 0
    count_lock = threading.Lock()

    def tracked_load(target: object) -> dict[str, object]:
        nonlocal load_count
        with count_lock:
            load_count += 1
            if load_count == 2:
                reap_loaded.set()
        return real_load_manifest(target)

    def blocking_run_git(
        cwd: Path, *args: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        if args[:3] == ("worktree", "add", "-b"):
            create_in_git.set()
            if not release_create.wait(timeout=5):
                raise AssertionError("timed out waiting to release create")
        return real_run_git(cwd, *args, check=check)

    def reap() -> object:
        reap_started.set()
        return reap_sandboxes(repo)

    monkeypatch.setattr(sandbox_module, "_load_manifest", tracked_load)
    monkeypatch.setattr(sandbox_module, "_run_git", blocking_run_git)

    with ThreadPoolExecutor(max_workers=2) as executor:
        created = executor.submit(create_sandbox, repo, ATTACK_ID)
        assert create_in_git.wait(timeout=5)
        reaped = executor.submit(reap)
        assert reap_started.wait(timeout=5)
        try:
            assert not reap_loaded.wait(timeout=0.2)
        finally:
            release_create.set()
        created.result(timeout=10)
        result = reaped.result(timeout=10)

    assert reap_loaded.is_set()
    assert result.reaped == (ATTACK_ID,)
    assert result.failures == {}
    assert manifest(repo)["sandboxes"] == {}
    assert registered_worktrees(repo) == {repo.resolve()}


def test_create_rejects_symlink_and_nonregular_lock_paths(
    repo: Path, tmp_path: Path
) -> None:
    lock_path = repo / LOCK_PATH
    lock_path.parent.mkdir(parents=True)
    outside = tmp_path / "outside-lock"
    outside.write_text("keep\n", encoding="utf-8")
    lock_path.symlink_to(outside)

    with pytest.raises(SandboxError, match="lock path.*symlink"):
        create_sandbox(repo, ATTACK_ID)
    assert outside.read_text(encoding="utf-8") == "keep\n"

    lock_path.unlink()
    lock_path.mkdir()
    with pytest.raises(SandboxError, match="lock path.*regular file"):
        create_sandbox(repo, ATTACK_ID)
    assert f"falsiq/proto/{ATTACK_ID}" not in branches(repo)


def test_manifest_replacements_fsync_the_sandbox_directory(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    synced: list[Path] = []
    monkeypatch.setattr(sandbox_module, "_fsync_directory", synced.append)

    create_sandbox(repo, ATTACK_ID)
    assert repo / ".falsiq" / "sandbox" in synced

    synced.clear()
    reap_sandboxes(repo)
    assert synced == [repo / ".falsiq" / "sandbox"]


def test_create_refuses_an_existing_exact_branch(repo: Path) -> None:
    git(repo, "branch", f"falsiq/proto/{ATTACK_ID}")

    with pytest.raises(SandboxError, match="branch .* already exists"):
        create_sandbox(repo, ATTACK_ID)

    assert not (repo / MANIFEST_PATH).exists()


def test_create_rolls_back_manifest_worktree_and_branch_after_validation_failure(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_validation(*_args: object) -> None:
        raise SandboxError("simulated identity validation failure")

    monkeypatch.setattr(sandbox_module, "_validate_created_worktree", fail_validation)

    with pytest.raises(SandboxError, match="simulated identity validation failure"):
        create_sandbox(repo, ATTACK_ID)

    assert manifest(repo)["sandboxes"] == {}
    assert not (repo / ".falsiq" / "sandbox" / ATTACK_ID).exists()
    assert f"falsiq/proto/{ATTACK_ID}" not in branches(repo)
    assert registered_worktrees(repo) == {repo.resolve()}
    assert git(repo, "status", "--porcelain").stdout == ""


def test_create_refuses_code_dirtiness_but_allows_falsiq_state(repo: Path) -> None:
    (repo / "tracked.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(SandboxError, match="outside .falsiq"):
        create_sandbox(repo, ATTACK_ID)

    git(repo, "restore", "tracked.txt")
    state = repo / ".falsiq" / "local-state"
    state.write_text("ignored lifecycle state\n", encoding="utf-8")

    created = create_sandbox(repo, ATTACK_ID)

    assert created.path.is_dir()


def test_create_rejects_a_symlink_escape(repo: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (repo / ".falsiq" / ".gitignore").unlink()
    (repo / ".falsiq" / "ledger.jsonl").unlink()
    (repo / ".falsiq" / "cases").rmdir()
    (repo / ".falsiq").rmdir()
    os.symlink(outside, repo / ".falsiq", target_is_directory=True)

    with pytest.raises(SandboxError, match="escapes repository"):
        create_sandbox(repo, ATTACK_ID)

    assert not (outside / "sandbox").exists()
    assert f"falsiq/proto/{ATTACK_ID}" not in branches(repo)


def test_reap_removes_clean_manifest_entries_and_is_idempotent(repo: Path) -> None:
    create_sandbox(repo, ATTACK_ID)
    result = reap_sandboxes(repo)

    assert result.reaped == (ATTACK_ID,)
    assert result.failures == {}
    assert not (repo / ".falsiq" / "sandbox" / ATTACK_ID).exists()
    assert f"falsiq/proto/{ATTACK_ID}" not in branches(repo)
    assert registered_worktrees(repo) == {repo.resolve()}
    assert manifest(repo)["sandboxes"] == {}
    assert git(repo, "status", "--porcelain").stdout == ""

    second = reap_sandboxes(repo)
    assert second.reaped == ()
    assert second.failures == {}


def test_reap_requires_explicit_force_for_dirty_prototypes_and_preserves_unrelated_worktrees(
    repo: Path,
) -> None:
    dirty = create_sandbox(repo, ATTACK_ID)
    clean = create_sandbox(repo, SECOND_ATTACK_ID)
    (dirty.path / "tracked.txt").write_text("prototype work\n", encoding="utf-8")

    unrelated_path = repo.parent / "unrelated"
    git(repo, "worktree", "add", "-b", "unrelated", str(unrelated_path), "HEAD")

    result = reap_sandboxes(repo)

    assert result.reaped == (SECOND_ATTACK_ID,)
    assert ATTACK_ID in result.failures
    assert "dirty" in result.failures[ATTACK_ID]
    assert dirty.path.exists()
    assert not clean.path.exists()
    assert unrelated_path.resolve() in registered_worktrees(repo)
    assert "unrelated" in branches(repo)
    assert set(manifest(repo)["sandboxes"]) == {ATTACK_ID}

    forced = reap_sandboxes(repo, force=True)

    assert forced.reaped == (ATTACK_ID,)
    assert forced.failures == {}
    assert not dirty.path.exists()
    assert unrelated_path.resolve() in registered_worktrees(repo)
    assert f"falsiq/proto/{ATTACK_ID}" not in branches(repo)
    assert manifest(repo)["sandboxes"] == {}
    assert git(repo, "status", "--porcelain").stdout == ""


def test_reap_finishes_an_orphaned_manifest_entry(repo: Path) -> None:
    created = create_sandbox(repo, ATTACK_ID)
    git(repo, "worktree", "remove", str(created.path))
    assert created.branch in branches(repo)

    result = reap_sandboxes(repo)

    assert result.reaped == (ATTACK_ID,)
    assert result.failures == {}
    assert created.branch not in branches(repo)
    assert manifest(repo)["sandboxes"] == {}


def test_reap_does_not_delete_a_replacement_at_the_managed_path(repo: Path) -> None:
    created = create_sandbox(repo, ATTACK_ID)
    git(repo, "worktree", "remove", str(created.path))
    created.path.mkdir(parents=True)
    git(created.path, "init", "--initial-branch=other")
    marker = created.path / "keep-me"
    marker.write_text("unrelated\n", encoding="utf-8")

    result = reap_sandboxes(repo)

    assert ATTACK_ID in result.failures
    assert "repository identity" in result.failures[ATTACK_ID]
    assert marker.read_text(encoding="utf-8") == "unrelated\n"
    assert set(manifest(repo)["sandboxes"]) == {ATTACK_ID}


def test_reap_preserves_a_manifest_entry_moved_to_an_unexpected_path(repo: Path) -> None:
    created = create_sandbox(repo, ATTACK_ID)
    moved = repo.parent / "moved-prototype"
    git(repo, "worktree", "move", str(created.path), str(moved))

    result = reap_sandboxes(repo)

    assert ATTACK_ID in result.failures
    assert "registered at an unexpected path" in result.failures[ATTACK_ID]
    assert moved.resolve() in registered_worktrees(repo)
    assert created.branch in branches(repo)
    assert set(manifest(repo)["sandboxes"]) == {ATTACK_ID}


def test_reap_keeps_failed_entries_while_removing_other_entries(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    failed = create_sandbox(repo, ATTACK_ID)
    removed = create_sandbox(repo, SECOND_ATTACK_ID)
    real_run_git = sandbox_module._run_git

    def fail_one_remove(
        cwd: Path, *args: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        if (
            args[:2] == ("worktree", "remove")
            and len(args) in {3, 4}
            and args[-1] == str(failed.path)
        ):
            return subprocess.CompletedProcess(
                args=["git", *args],
                returncode=1,
                stdout="",
                stderr="simulated cleanup failure",
            )
        return real_run_git(cwd, *args, check=check)

    monkeypatch.setattr(sandbox_module, "_run_git", fail_one_remove)

    result = reap_sandboxes(repo)

    assert result.reaped == (SECOND_ATTACK_ID,)
    assert result.failures == {ATTACK_ID: "simulated cleanup failure"}
    assert failed.path.is_dir()
    assert not removed.path.exists()
    assert set(manifest(repo)["sandboxes"]) == {ATTACK_ID}


@pytest.mark.parametrize("verb", ["push", "merge", "rebase"])
def test_git_runner_rejects_dangerous_verbs(
    repo: Path, monkeypatch: pytest.MonkeyPatch, verb: str
) -> None:
    called = False

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal called
        called = True
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(SandboxError, match="forbidden git operation"):
        _run_git(repo, verb)

    assert called is False


def test_git_runner_uses_argv_and_disables_shell(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    invocation: tuple[object, ...] | None = None
    options: dict[str, object] = {}

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal invocation, options
        invocation = args
        options = kwargs
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="head\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = _run_git(repo, "rev-parse", "HEAD")

    assert invocation == (["git", "rev-parse", "HEAD"],)
    assert options["cwd"] == repo
    assert options["shell"] is False
    assert result.stdout == "head\n"


def test_cli_creates_and_reaps_sandbox(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(repo)

    assert main(["sandbox", "new", ATTACK_ID]) == 0
    created_output = capsys.readouterr()
    assert created_output.err == ""
    assert created_output.out == (
        '{"attack_id":"01J00000000000000000000000",'
        '"branch":"falsiq/proto/01J00000000000000000000000",'
        '"path":".falsiq/sandbox/01J00000000000000000000000"}\n'
    )

    assert main(["sandbox", "reap"]) == 0
    reap_output = capsys.readouterr()
    assert reap_output.err == ""
    assert reap_output.out == f"reaped {ATTACK_ID}\n"


def test_cli_requires_force_before_discarding_dirty_prototype(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    created = create_sandbox(repo, ATTACK_ID)
    (created.path / "tracked.txt").write_text("dirty prototype\n", encoding="utf-8")
    monkeypatch.chdir(repo)

    assert main(["sandbox", "reap"]) == 2
    refused = capsys.readouterr()
    assert refused.out == ""
    assert "error:" in refused.err
    assert "--force" in refused.err
    assert created.path.is_dir()

    assert main(["sandbox", "reap", "--force"]) == 0
    forced = capsys.readouterr()
    assert forced.err == ""
    assert forced.out == f"reaped {ATTACK_ID}\n"
    assert not created.path.exists()
    assert registered_worktrees(repo) == {repo.resolve()}


def test_cli_allocates_an_id_when_omitted(
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sandbox_module, "new_ulid", lambda: SECOND_ATTACK_ID)
    monkeypatch.chdir(repo)

    assert main(["sandbox", "new"]) == 0

    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out) == {
        "attack_id": SECOND_ATTACK_ID,
        "branch": f"falsiq/proto/{SECOND_ATTACK_ID}",
        "path": f".falsiq/sandbox/{SECOND_ATTACK_ID}",
    }


def test_cli_reports_identity_failure(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    created = create_sandbox(repo, ATTACK_ID)
    git(repo, "worktree", "remove", str(created.path))
    created.path.mkdir(parents=True)
    git(created.path, "init", "--initial-branch=replacement")
    monkeypatch.chdir(repo)

    assert main(["sandbox", "reap"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err.startswith(f"error: {ATTACK_ID}: ")
