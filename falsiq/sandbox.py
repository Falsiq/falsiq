"""Disposable Git worktrees for rendering rival prototype behavior.

Only worktrees recorded in this module's manifest are ever reaped.  The
manifest is deliberately stored below ``.falsiq/sandbox/`` so the project
owned ``.falsiq/.gitignore`` rule can ignore both it and the worktrees.
"""

from __future__ import annotations

import errno
import json
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .facts import new_ulid, ulid_timestamp_ms

SANDBOX_ROOT = Path(".falsiq/sandbox")
MANIFEST_PATH = SANDBOX_ROOT / "manifest.json"
LOCK_PATH = SANDBOX_ROOT / ".lock"
BRANCH_PREFIX = "falsiq/proto/"
MANIFEST_VERSION = 1

_HEX_OBJECT_ID_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_FORBIDDEN_GIT_VERBS = frozenset({"merge", "push", "rebase"})


class SandboxError(RuntimeError):
    """A sandbox operation could not be completed safely."""


@dataclass(frozen=True)
class Sandbox:
    attack_id: str
    branch: str
    path: Path

    @property
    def relative_path(self) -> PurePosixPath:
        return PurePosixPath(".falsiq", "sandbox", self.attack_id)


@dataclass(frozen=True)
class ReapResult:
    reaped: tuple[str, ...]
    failures: dict[str, str]


@dataclass(frozen=True)
class _Repository:
    root: Path
    common_git_dir: Path
    head: str


@dataclass(frozen=True)
class _RegisteredWorktree:
    path: Path
    branch: str | None


def _fsync_directory(path: Path) -> None:
    """Durably order directory changes, with a documented Windows no-op."""

    if os.name == "nt":  # pragma: no cover - Windows cannot fsync directories.
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        directory_fd = os.open(path, flags)
    except OSError as exc:
        unsupported = {errno.EINVAL, errno.EISDIR}
        if hasattr(errno, "ENOTSUP"):
            unsupported.add(errno.ENOTSUP)
        if exc.errno in unsupported:
            return
        raise
    try:
        try:
            os.fsync(directory_fd)
        except OSError as exc:
            unsupported = {errno.EINVAL, errno.EBADF}
            if hasattr(errno, "ENOTSUP"):
                unsupported.add(errno.ENOTSUP)
            if exc.errno not in unsupported:
                raise
    finally:
        os.close(directory_fd)


def _run_git(
    cwd: Path,
    *args: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run an allowlisted class of local Git commands using argv only."""

    if any(arg in _FORBIDDEN_GIT_VERBS for arg in args):
        verb = next(arg for arg in args if arg in _FORBIDDEN_GIT_VERBS)
        raise SandboxError(f"forbidden git operation: {verb}")

    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            shell=False,
        )
    except OSError as exc:
        raise SandboxError(f"could not run git: {exc}") from exc

    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "git command failed"
        raise SandboxError(detail)
    return result


def _repository(start: str | os.PathLike[str] | Path) -> _Repository:
    candidate = Path(start).expanduser()
    if not candidate.is_dir():
        raise SandboxError(f"repository path is not a directory: {candidate}")

    top_result = _run_git(candidate, "rev-parse", "--show-toplevel", check=False)
    if top_result.returncode != 0 or not top_result.stdout.strip():
        raise SandboxError(f"not a Git worktree: {candidate}")
    root = Path(top_result.stdout.strip()).resolve(strict=True)

    bare = _run_git(root, "rev-parse", "--is-bare-repository").stdout.strip()
    if bare != "false":
        raise SandboxError("prototype sandboxes require a non-bare Git worktree")

    head = _run_git(root, "rev-parse", "--verify", "HEAD", check=False)
    if head.returncode != 0 or not _HEX_OBJECT_ID_RE.fullmatch(head.stdout.strip()):
        raise SandboxError("prototype sandboxes require a repository with a valid HEAD")

    return _Repository(
        root=root,
        common_git_dir=_common_git_dir(root),
        head=head.stdout.strip(),
    )


def _common_git_dir(worktree: Path) -> Path:
    raw = _run_git(worktree, "rev-parse", "--git-common-dir").stdout.strip()
    path = Path(raw)
    if not path.is_absolute():
        path = worktree / path
    return path.resolve(strict=True)


def _validate_attack_id(attack_id: str) -> None:
    try:
        ulid_timestamp_ms(attack_id)
    except ValueError:
        raise SandboxError("sandbox id must be a canonical ULID") from None


def _entry_path(root: Path, attack_id: str) -> Path:
    expected = root / SANDBOX_ROOT / attack_id
    _validate_containment(root, expected)
    return expected.resolve(strict=False)


def _validate_containment(root: Path, path: Path) -> None:
    resolved_root = root.resolve(strict=True)
    resolved_path = path.resolve(strict=False)
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError as exc:
        raise SandboxError(f"sandbox path escapes repository: {path}") from exc

    try:
        relative = path.absolute().relative_to(root.absolute())
    except ValueError as exc:
        raise SandboxError(f"sandbox path is not rooted at the repository: {path}") from exc

    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise SandboxError(f"sandbox path uses a symlink and escapes repository: {current}")


@contextmanager
def _manifest_lock(repo: _Repository) -> Iterator[None]:
    """Serialize each manifest read/Git mutation/write transaction."""

    path = repo.root / LOCK_PATH
    if path.is_symlink():
        raise SandboxError("sandbox lock path must not be a symlink")
    _validate_containment(repo.root, path)
    parent_existed = path.parent.exists()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SandboxError(f"could not create sandbox lock directory: {exc}") from exc
    if not parent_existed:
        try:
            _fsync_directory(path.parent.parent)
        except OSError as exc:
            raise SandboxError(f"could not persist sandbox lock directory: {exc}") from exc
    if path.exists() and not path.is_file():
        raise SandboxError("sandbox lock path must be a regular file")

    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        file_descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise SandboxError(f"could not open sandbox lock: {exc}") from exc
    try:
        if path.is_symlink() or not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
            raise SandboxError("sandbox lock path must be a regular file")
        with os.fdopen(file_descriptor, "r+b", closefd=True) as lock_file:
            file_descriptor = -1
            if os.name == "nt":  # pragma: no cover - exercised on Windows CI
                import msvcrt

                lock_file.seek(0, os.SEEK_END)
                if lock_file.tell() == 0:
                    lock_file.write(b"\0")
                    lock_file.flush()
                    os.fsync(lock_file.fileno())
                lock_file.seek(0)
                try:
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                except OSError as exc:
                    raise SandboxError(f"could not acquire sandbox lock: {exc}") from exc
                try:
                    yield
                finally:
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                except OSError as exc:
                    raise SandboxError(f"could not acquire sandbox lock: {exc}") from exc
                try:
                    yield
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)


def _dirty_paths(repo: _Repository) -> list[str]:
    result = _run_git(
        repo.root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    )
    records = result.stdout.split("\0")
    paths: list[str] = []
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record:
            continue
        if len(record) < 4:
            raise SandboxError("could not parse Git status output")
        paths.append(record[3:])
        if "R" in record[:2] or "C" in record[:2]:
            if index >= len(records) or not records[index]:
                raise SandboxError("could not parse renamed path in Git status output")
            paths.append(records[index])
            index += 1
    return paths


def _is_falsiq_path(path: str) -> bool:
    normalized = PurePosixPath(path)
    return normalized == PurePosixPath(".falsiq") or (
        normalized.parts and normalized.parts[0] == ".falsiq"
    )


def _require_clean_code(repo: _Repository) -> None:
    dirty = [path for path in _dirty_paths(repo) if not _is_falsiq_path(path)]
    if dirty:
        rendered = ", ".join(sorted(dirty))
        raise SandboxError(f"repository has changes outside .falsiq: {rendered}")


def _require_initialized_state(repo: _Repository) -> None:
    state_dir = repo.root / ".falsiq"
    ledger_path = state_dir / "ledger.jsonl"
    ignore_path = state_dir / ".gitignore"
    _validate_containment(repo.root, state_dir)
    if (
        state_dir.is_symlink()
        or not state_dir.is_dir()
        or ledger_path.is_symlink()
        or not ledger_path.is_file()
    ):
        raise SandboxError("Falsiq is not initialized; run `falsiq init`")
    _validate_containment(repo.root, ignore_path)
    if ignore_path.is_symlink() or not ignore_path.is_file():
        raise SandboxError("sandbox ignore rule is missing; rerun `falsiq init`")
    try:
        ignore_lines = ignore_path.read_bytes().splitlines()
    except OSError as exc:
        raise SandboxError(f"could not read sandbox ignore rule: {exc}") from exc
    if b"/sandbox/" not in ignore_lines:
        raise SandboxError("sandbox ignore rule is missing; rerun `falsiq init`")


def _empty_manifest(repo: _Repository) -> dict[str, Any]:
    return {
        "repository": {
            "common_git_dir": str(repo.common_git_dir),
            "root": str(repo.root),
        },
        "sandboxes": {},
        "version": MANIFEST_VERSION,
    }


def _load_manifest(repo: _Repository) -> dict[str, Any]:
    path = repo.root / MANIFEST_PATH
    _validate_containment(repo.root, path)
    if not path.exists():
        return _empty_manifest(repo)
    if not path.is_file():
        raise SandboxError(f"sandbox manifest is not a regular file: {path}")

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SandboxError(f"could not read sandbox manifest: {exc}") from exc

    if not isinstance(document, dict) or document.get("version") != MANIFEST_VERSION:
        raise SandboxError("sandbox manifest has an unsupported format")
    repository = document.get("repository")
    sandboxes = document.get("sandboxes")
    if not isinstance(repository, dict) or not isinstance(sandboxes, dict):
        raise SandboxError("sandbox manifest has an unsupported format")
    if repository.get("root") != str(repo.root):
        raise SandboxError("sandbox manifest repository root does not match this repository")
    if repository.get("common_git_dir") != str(repo.common_git_dir):
        raise SandboxError("sandbox manifest repository identity does not match this repository")
    return document


def _write_manifest(repo: _Repository, document: dict[str, Any]) -> None:
    path = repo.root / MANIFEST_PATH
    _validate_containment(repo.root, path)
    parent_existed = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not parent_existed:
        try:
            _fsync_directory(path.parent.parent)
        except OSError as exc:
            raise SandboxError(f"could not persist sandbox directory: {exc}") from exc
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"

    temporary_name: str | None = None
    replaced = False
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=".manifest-",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
        replaced = True
        _fsync_directory(path.parent)
    except OSError as exc:
        raise SandboxError(f"could not write sandbox manifest: {exc}") from exc
    finally:
        if temporary_name is not None and not replaced:
            temporary_path = Path(temporary_name)
            if temporary_path.exists():
                with suppress(OSError):
                    temporary_path.unlink()
                    _fsync_directory(path.parent)


def _branch_exists(repo: _Repository, branch: str) -> bool:
    result = _run_git(
        repo.root,
        "show-ref",
        "--verify",
        "--quiet",
        f"refs/heads/{branch}",
        check=False,
    )
    if result.returncode not in {0, 1}:
        raise SandboxError(result.stderr.strip() or "could not inspect prototype branch")
    return result.returncode == 0


def _registered_worktrees(repo: _Repository) -> dict[Path, _RegisteredWorktree]:
    result = _run_git(repo.root, "worktree", "list", "--porcelain", "-z")
    registered: dict[Path, _RegisteredWorktree] = {}
    for block in result.stdout.split("\0\0"):
        fields = block.split("\0")
        path_field = next((field for field in fields if field.startswith("worktree ")), None)
        if path_field is None:
            continue
        path = Path(path_field.removeprefix("worktree ")).resolve(strict=False)
        branch_field = next((field for field in fields if field.startswith("branch ")), None)
        branch = None
        if branch_field is not None:
            branch = branch_field.removeprefix("branch refs/heads/")
        registered[path] = _RegisteredWorktree(path=path, branch=branch)
    return registered


def _validate_created_worktree(repo: _Repository, sandbox: Sandbox) -> None:
    if not sandbox.path.is_dir():
        raise SandboxError("Git did not create the prototype worktree")
    _validate_containment(repo.root, sandbox.path)

    top = Path(_run_git(sandbox.path, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    if top != sandbox.path:
        raise SandboxError("prototype worktree path does not match its manifest entry")
    if _common_git_dir(sandbox.path) != repo.common_git_dir:
        raise SandboxError("prototype worktree repository identity does not match")
    branch = _run_git(sandbox.path, "symbolic-ref", "--short", "HEAD").stdout.strip()
    if branch != sandbox.branch:
        raise SandboxError("prototype worktree branch does not match its manifest entry")
    head = _run_git(sandbox.path, "rev-parse", "--verify", "HEAD").stdout.strip()
    if head != repo.head:
        raise SandboxError("prototype worktree was not created at repository HEAD")


def _delete_exact_branch(repo: _Repository, branch: str) -> None:
    if not _branch_exists(repo, branch):
        return
    _run_git(repo.root, "update-ref", "-d", f"refs/heads/{branch}")
    if _branch_exists(repo, branch):
        raise SandboxError(f"could not delete prototype branch {branch}")


def _rollback_creation(repo: _Repository, sandbox: Sandbox) -> str | None:
    errors: list[str] = []
    try:
        registered = _registered_worktrees(repo)
    except SandboxError as exc:
        errors.append(str(exc))
        registered = {}
    if sandbox.path in registered:
        removed = _run_git(
            repo.root,
            "worktree",
            "remove",
            "--force",
            str(sandbox.path),
            check=False,
        )
        if removed.returncode != 0:
            errors.append(removed.stderr.strip() or "could not remove prototype worktree")
    elif sandbox.path.exists():
        try:
            _validate_containment(repo.root, sandbox.path)
            sandbox.path.rmdir()
        except (OSError, SandboxError) as exc:
            errors.append(f"could not remove partial sandbox path: {exc}")
    try:
        _delete_exact_branch(repo, sandbox.branch)
    except SandboxError as exc:
        errors.append(str(exc))
    return "; ".join(errors) or None


def _refresh_repository(repo: _Repository) -> _Repository:
    refreshed = _repository(repo.root)
    if refreshed.root != repo.root or refreshed.common_git_dir != repo.common_git_dir:
        raise SandboxError("repository identity changed while waiting for the sandbox lock")
    return refreshed


def _create_sandbox_locked(repo: _Repository, allocated_id: str) -> Sandbox:
    _require_initialized_state(repo)
    _require_clean_code(repo)
    path = _entry_path(repo.root, allocated_id)
    branch = f"{BRANCH_PREFIX}{allocated_id}"
    sandbox = Sandbox(attack_id=allocated_id, branch=branch, path=path)

    document = _load_manifest(repo)
    entries = document["sandboxes"]
    if allocated_id in entries or path.exists() or path in _registered_worktrees(repo):
        raise SandboxError(f"sandbox {allocated_id} already exists")
    if _branch_exists(repo, branch):
        raise SandboxError(f"sandbox branch {branch} already exists")

    entries[allocated_id] = {
        "branch": branch,
        "head": repo.head,
        "path": sandbox.relative_path.as_posix(),
    }
    _write_manifest(repo, document)

    try:
        _run_git(repo.root, "worktree", "add", "-b", branch, str(path), "HEAD")
        _validate_created_worktree(repo, sandbox)
    except SandboxError as exc:
        cleanup_error = _rollback_creation(repo, sandbox)
        if cleanup_error is None:
            entries.pop(allocated_id, None)
            _write_manifest(repo, document)
        suffix = f"; cleanup failed: {cleanup_error}" if cleanup_error else ""
        raise SandboxError(f"could not create sandbox {allocated_id}: {exc}{suffix}") from exc

    return sandbox


def create_sandbox(
    repository: str | os.PathLike[str] | Path | None = None,
    attack_id: str | None = None,
) -> Sandbox:
    """Create a manifest-backed prototype worktree at the repository's HEAD."""

    repo = _repository(Path.cwd() if repository is None else repository)
    _require_initialized_state(repo)
    allocated_id = new_ulid() if attack_id is None else attack_id
    _validate_attack_id(allocated_id)
    with _manifest_lock(repo):
        return _create_sandbox_locked(_refresh_repository(repo), allocated_id)


def _validated_entry(
    repo: _Repository,
    attack_id: str,
    raw: object,
) -> tuple[Sandbox, str]:
    _validate_attack_id(attack_id)
    if not isinstance(raw, dict):
        raise SandboxError("manifest entry is not an object")
    expected_branch = f"{BRANCH_PREFIX}{attack_id}"
    expected_path = PurePosixPath(".falsiq", "sandbox", attack_id).as_posix()
    branch = raw.get("branch")
    path = raw.get("path")
    head = raw.get("head")
    if branch != expected_branch or path != expected_path:
        raise SandboxError("manifest entry does not name the exact managed branch and path")
    if not isinstance(head, str) or not _HEX_OBJECT_ID_RE.fullmatch(head):
        raise SandboxError("manifest entry has an invalid starting HEAD")
    return Sandbox(attack_id, expected_branch, _entry_path(repo.root, attack_id)), head


def _validate_existing_worktree(repo: _Repository, sandbox: Sandbox) -> None:
    top_result = _run_git(sandbox.path, "rev-parse", "--show-toplevel", check=False)
    if top_result.returncode != 0 or not top_result.stdout.strip():
        raise SandboxError("managed path does not have the expected repository identity")
    top = Path(top_result.stdout.strip()).resolve(strict=False)
    if top != sandbox.path:
        raise SandboxError("managed path does not have the expected repository identity")
    if _common_git_dir(sandbox.path) != repo.common_git_dir:
        raise SandboxError("managed path does not have the expected repository identity")
    branch_result = _run_git(
        sandbox.path,
        "symbolic-ref",
        "--quiet",
        "--short",
        "HEAD",
        check=False,
    )
    if branch_result.returncode != 0 or branch_result.stdout.strip() != sandbox.branch:
        raise SandboxError("managed worktree no longer uses its exact prototype branch")


def _reap_entry(
    repo: _Repository,
    sandbox: Sandbox,
    registered: dict[Path, _RegisteredWorktree],
    *,
    force: bool,
) -> None:
    unexpected_branch_paths = [
        entry.path
        for entry in registered.values()
        if entry.branch == sandbox.branch and entry.path != sandbox.path
    ]
    if unexpected_branch_paths:
        raise SandboxError(
            f"managed branch is registered at an unexpected path: {unexpected_branch_paths[0]}"
        )

    if sandbox.path.exists():
        _validate_containment(repo.root, sandbox.path)
        if sandbox.path not in registered:
            try:
                sandbox.path.rmdir()
            except OSError as exc:
                raise SandboxError(
                    "managed path has unexpected contents or repository identity"
                ) from exc
        else:
            _validate_existing_worktree(repo, sandbox)
            dirty = _run_git(
                sandbox.path,
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
            ).stdout
            if dirty and not force:
                raise SandboxError(
                    "managed prototype worktree is dirty; rerun with --force to discard it"
                )
            remove_args = ["worktree", "remove"]
            if force:
                remove_args.append("--force")
            remove_args.append(str(sandbox.path))
            result = _run_git(
                repo.root,
                *remove_args,
                check=False,
            )
            if result.returncode != 0:
                detail = result.stderr.strip() or "could not remove prototype worktree"
                raise SandboxError(detail)
    elif sandbox.path in registered:
        remove_args = ["worktree", "remove"]
        if force:
            remove_args.append("--force")
        remove_args.append(str(sandbox.path))
        result = _run_git(
            repo.root,
            *remove_args,
            check=False,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or "could not remove missing prototype worktree"
            raise SandboxError(detail)

    _delete_exact_branch(repo, sandbox.branch)


def reap_sandboxes(
    repository: str | os.PathLike[str] | Path | None = None,
    *,
    force: bool = False,
) -> ReapResult:
    """Remove validated manifest entries, preserving failures and dirty worktrees."""

    repo = _repository(Path.cwd() if repository is None else repository)
    _require_initialized_state(repo)
    with _manifest_lock(repo):
        return _reap_sandboxes_locked(_refresh_repository(repo), force=force)


def _reap_sandboxes_locked(repo: _Repository, *, force: bool) -> ReapResult:
    document = _load_manifest(repo)
    entries = document["sandboxes"]
    registered = _registered_worktrees(repo)
    reaped: list[str] = []
    failures: dict[str, str] = {}

    for attack_id in sorted(entries):
        raw = entries[attack_id]
        try:
            sandbox, _starting_head = _validated_entry(repo, attack_id, raw)
            _reap_entry(repo, sandbox, registered, force=force)
        except SandboxError as exc:
            failures[attack_id] = str(exc)
        else:
            reaped.append(attack_id)

    if reaped:
        document["sandboxes"] = {
            attack_id: raw for attack_id, raw in entries.items() if attack_id not in reaped
        }
        _write_manifest(repo, document)

    return ReapResult(reaped=tuple(reaped), failures=failures)


def sandbox_json(sandbox: Sandbox) -> str:
    """Return the stable CLI representation of a newly created sandbox."""

    return json.dumps(
        {
            "review_id": sandbox.attack_id,
            "branch": sandbox.branch,
            "path": sandbox.relative_path.as_posix(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
