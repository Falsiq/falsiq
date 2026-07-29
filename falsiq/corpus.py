"""Seeded corpus splitting and private holdout access controls."""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import shutil
import stat
import tempfile
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator

from .benchmark import EvalTask, canonical_task_hash
from .facts import utc_timestamp

_SPLIT_POLICY: dict[str, int] = {"synthetic": 3, "mined": 3, "control": 4}
_CORPUS_POLICY: dict[str, int] = {"synthetic": 10, "mined": 10, "control": 10}
_HEX_DIGEST_LENGTH = 64
_TASK_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_WINDOWS_DEVICE_NAME = re.compile(r"(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?")


class CorpusError(RuntimeError):
    """A corpus operation would weaken holdout integrity."""


class _CorpusModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class HoldoutEntry(_CorpusModel):
    task_id: str
    stratum: Literal["synthetic", "mined", "control"]
    salted_hash: str

    @field_validator("task_id")
    @classmethod
    def task_id_is_safe(cls, value: str) -> str:
        if _TASK_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("holdout task ID must be a stable lowercase token")
        return value

    @field_validator("salted_hash")
    @classmethod
    def hash_is_sha256(cls, value: str) -> str:
        invalid_character = any(character not in "0123456789abcdef" for character in value)
        if len(value) != _HEX_DIGEST_LENGTH or invalid_character:
            raise ValueError("salted_hash must be a lowercase SHA-256 digest")
        return value


class HoldoutManifest(_CorpusModel):
    schema_version: Literal[1] = 1
    corpus_version: str
    seed_digest: str
    split_policy: dict[str, int]
    tasks: list[HoldoutEntry]

    @field_validator("corpus_version")
    @classmethod
    def version_is_nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("corpus_version must not be blank")
        return value

    @field_validator("seed_digest")
    @classmethod
    def seed_digest_is_sha256(cls, value: str) -> str:
        invalid_character = any(character not in "0123456789abcdef" for character in value)
        if len(value) != _HEX_DIGEST_LENGTH or invalid_character:
            raise ValueError("seed_digest must be a lowercase SHA-256 digest")
        return value

    @model_validator(mode="after")
    def manifest_matches_precommitted_policy(self) -> HoldoutManifest:
        if self.split_policy != _SPLIT_POLICY:
            raise ValueError("holdout manifest does not match the precommitted split policy")
        task_ids = [entry.task_id for entry in self.tasks]
        if len(task_ids) != len(set(task_ids)):
            raise ValueError("holdout manifest task IDs must be unique")
        counts = Counter(entry.stratum for entry in self.tasks)
        if dict(counts) != _SPLIT_POLICY:
            raise ValueError("holdout manifest strata do not match the split policy")
        return self


class CorpusTaskEntry(_CorpusModel):
    task_id: str
    stratum: Literal["synthetic", "mined", "control"]


class CorpusReleasePlan(_CorpusModel):
    """Redacted plan safe to print before an approved corpus is published."""

    schema_version: Literal[1] = 1
    corpus_version: str
    development_tasks: list[CorpusTaskEntry]
    holdout_manifest: HoldoutManifest

    @model_validator(mode="after")
    def release_matches_precommitted_policy(self) -> CorpusReleasePlan:
        if self.corpus_version != self.holdout_manifest.corpus_version:
            raise ValueError("release and holdout manifest versions must match")
        development_ids = [entry.task_id for entry in self.development_tasks]
        if len(development_ids) != len(set(development_ids)):
            raise ValueError("development task IDs must be unique")
        expected_development = {
            stratum: _CORPUS_POLICY[stratum] - _SPLIT_POLICY[stratum] for stratum in _CORPUS_POLICY
        }
        if dict(Counter(entry.stratum for entry in self.development_tasks)) != (
            expected_development
        ):
            raise ValueError("development tasks do not match the precommitted split policy")
        holdout_ids = {entry.task_id for entry in self.holdout_manifest.tasks}
        if holdout_ids.intersection(development_ids):
            raise ValueError("development and holdout task IDs must be disjoint")
        return self


@dataclass(frozen=True)
class _FixtureTree:
    directories: frozenset[str]
    files: dict[str, bytes]


@dataclass(frozen=True)
class _PreparedRelease:
    plan: CorpusReleasePlan
    public_directories: frozenset[str]
    public_files: dict[str, bytes]
    private_directories: frozenset[str]
    private_files: dict[str, bytes]


def _seed_bytes(seed: str) -> bytes:
    if not seed:
        raise CorpusError("split seed must not be empty")
    return hashlib.sha256(seed.encode("utf-8")).digest()


def select_holdout(tasks: Sequence[EvalTask], *, seed: str) -> list[EvalTask]:
    """Select the fixed 3/3/4 held-out strata after human approval."""

    task_ids = [task.task_id for task in tasks]
    if len(task_ids) != len(set(task_ids)):
        raise CorpusError("approved corpus contains a duplicate task ID")
    if any(not task.human_curated for task in tasks):
        raise CorpusError("holdout selection requires every task to be human-curated")

    seed_digest = _seed_bytes(seed)
    selected: list[EvalTask] = []
    for index, (stratum, count) in enumerate(_SPLIT_POLICY.items()):
        candidates = sorted(
            (task for task in tasks if task.stratum == stratum),
            key=lambda task: task.task_id,
        )
        if len(candidates) < count:
            raise CorpusError(f"holdout split requires {count} {stratum} tasks")
        stratum_seed = hashlib.sha256(seed_digest + index.to_bytes(1, "big")).digest()
        generator = random.Random(int.from_bytes(stratum_seed, "big"))
        generator.shuffle(candidates)
        selected.extend(candidates[:count])
    return sorted(selected, key=lambda task: task.task_id)


def _require_approved_corpus(tasks: Sequence[EvalTask]) -> None:
    task_ids = [task.task_id for task in tasks]
    if len(task_ids) != len(set(task_ids)):
        raise CorpusError("approved corpus contains a duplicate task ID")
    if dict(Counter(task.stratum for task in tasks)) != _CORPUS_POLICY:
        raise CorpusError("approved corpus requires exactly 10 tasks in each stratum")
    if any(not task.human_curated for task in tasks):
        raise CorpusError("release preparation requires every task to be human-curated")


def _build_selected_manifest(
    selected: Sequence[EvalTask],
    *,
    corpus_version: str,
    seed: str,
    salt: bytes,
) -> HoldoutManifest:
    if not salt:
        raise CorpusError("holdout salt must not be empty")
    if any(not task.human_curated for task in selected):
        raise CorpusError("holdout manifest requires every task to be human-curated")
    entries = [
        HoldoutEntry(
            task_id=task.task_id,
            stratum=task.stratum,
            salted_hash=canonical_task_hash(task, salt=salt),
        )
        for task in selected
    ]
    try:
        return HoldoutManifest(
            corpus_version=corpus_version,
            seed_digest=hashlib.sha256(_seed_bytes(seed)).hexdigest(),
            split_policy=dict(_SPLIT_POLICY),
            tasks=entries,
        )
    except ValueError as exc:
        raise CorpusError(f"invalid holdout selection: {exc}") from exc


def build_holdout_manifest(
    approved_corpus: Sequence[EvalTask],
    *,
    corpus_version: str,
    seed: str,
    salt: bytes,
) -> HoldoutManifest:
    """Derive a manifest from the full approved 10/10/10 corpus."""

    _require_approved_corpus(approved_corpus)
    selected = select_holdout(approved_corpus, seed=seed)
    return _build_selected_manifest(
        selected,
        corpus_version=corpus_version,
        seed=seed,
        salt=salt,
    )


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _casefolded_parts(path: Path) -> tuple[str, ...]:
    return tuple(part.casefold() for part in _absolute(path).parts)


def _paths_overlap(first: Path, second: Path) -> bool:
    first_parts = _casefolded_parts(first)
    second_parts = _casefolded_parts(second)
    common = min(len(first_parts), len(second_parts))
    return first_parts[:common] == second_parts[:common]


def _require_existing_directory(path: Path, *, label: str) -> Path:
    absolute = _absolute(path)
    try:
        metadata = absolute.lstat()
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise CorpusError(f"{label} must be an existing directory") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise CorpusError(f"{label} must not be a symbolic link")
    if not stat.S_ISDIR(metadata.st_mode):
        raise CorpusError(f"{label} must be an existing directory")
    return resolved


def _require_new_output(path: Path, *, label: str) -> Path:
    absolute = _absolute(path)
    try:
        absolute.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise CorpusError(f"could not inspect {label}") from exc
    else:
        raise CorpusError(f"{label} must not already exist")

    parent = _require_existing_directory(absolute.parent, label=f"{label} parent")
    for sibling in parent.iterdir():
        if sibling.name.casefold() == absolute.name.casefold():
            raise CorpusError(f"{label} has an existing case-insensitive alias")
    return parent / absolute.name


def _safe_tree_path(value: str) -> str:
    if not value or "\0" in value or "\\" in value:
        raise CorpusError("fixture paths must be non-empty POSIX relative paths")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if posix.is_absolute() or windows.is_absolute() or windows.drive:
        raise CorpusError("fixture paths must be relative")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise CorpusError("fixture paths must be normalized without traversal")
    if any(
        part.casefold() in {".git", ".falsiq"}
        or ":" in part
        or part.endswith((" ", "."))
        or _WINDOWS_DEVICE_NAME.fullmatch(part) is not None
        for part in parts
    ):
        raise CorpusError("fixture path is reserved or ambiguous on supported filesystems")
    return value


def _read_regular_file(path: Path, *, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CorpusError(f"{label} is missing") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise CorpusError(f"{label} must not be a symbolic link")
    if not stat.S_ISREG(metadata.st_mode):
        raise CorpusError(f"{label} must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise CorpusError(f"{label} must be a regular file")
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise CorpusError(f"{label} changed while it was being read")
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, 1024 * 1024):
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except CorpusError:
        raise
    except OSError as exc:
        raise CorpusError(f"could not read {label}") from exc


def _validate_casefold_unique(paths: Sequence[str], *, label: str) -> None:
    seen: dict[str, str] = {}
    for path in paths:
        folded = path.casefold()
        previous = seen.get(folded)
        if previous is not None and previous != path:
            raise CorpusError(f"{label} collide on a case-insensitive filesystem")
        seen[folded] = path


def _collect_fixture_tree(source: Path, relative_root: str) -> _FixtureTree:
    safe_root = _safe_tree_path(relative_root)
    if PurePosixPath(safe_root).parts[0] != "fixtures":
        raise CorpusError("repo_fixture must be rooted below fixtures/")
    fixture_root = source
    for component in PurePosixPath(safe_root).parts:
        fixture_root /= component
        try:
            metadata = fixture_root.lstat()
        except OSError as exc:
            raise CorpusError(f"fixture {relative_root} is missing") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise CorpusError(f"fixture {relative_root} must not traverse a symbolic link")
        if not stat.S_ISDIR(metadata.st_mode):
            raise CorpusError(f"fixture {relative_root} must be a real directory")

    directories = {safe_root}
    files: dict[str, bytes] = {}
    try:
        items = sorted(fixture_root.rglob("*"), key=lambda path: path.as_posix())
    except OSError as exc:
        raise CorpusError(f"could not enumerate fixture {relative_root}") from exc
    for item in items:
        relative = item.relative_to(source).as_posix()
        safe_relative = _safe_tree_path(relative)
        try:
            metadata = item.lstat()
        except OSError as exc:
            raise CorpusError(f"could not inspect fixture path {relative}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise CorpusError(f"fixture path {relative} must not be a symbolic link")
        if stat.S_ISDIR(metadata.st_mode):
            directories.add(safe_relative)
        elif stat.S_ISREG(metadata.st_mode):
            files[safe_relative] = _read_regular_file(item, label=f"fixture path {relative}")
        else:
            raise CorpusError(f"fixture path {relative} must be a regular file or directory")
    _validate_casefold_unique([*directories, *files], label="fixture paths")
    return _FixtureTree(frozenset(directories), files)


def _load_approved_corpus(source: Path) -> tuple[list[EvalTask], dict[str, _FixtureTree]]:
    tasks_directory = _require_existing_directory(source / "tasks", label="tasks directory")
    _require_existing_directory(source / "fixtures", label="fixtures directory")
    try:
        task_paths = sorted(tasks_directory.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        raise CorpusError("could not enumerate corpus tasks") from exc
    tasks: list[EvalTask] = []
    for task_path in task_paths:
        if task_path.suffix != ".json":
            raise CorpusError("tasks directory may contain only JSON task files")
        payload = _read_regular_file(task_path, label=f"task file {task_path.name}")
        try:
            task = EvalTask.model_validate_json(payload)
        except (ValidationError, UnicodeError, ValueError) as exc:
            raise CorpusError(f"invalid task {task_path.name}") from exc
        if task_path.name != f"{task.task_id}.json":
            raise CorpusError(f"task filename must match task ID {task.task_id}")
        tasks.append(task)

    _require_approved_corpus(tasks)

    fixture_roots = [task.context.repo_fixture for task in tasks]
    _validate_casefold_unique(fixture_roots, label="repo_fixture paths")
    split_roots = [PurePosixPath(path).parts for path in fixture_roots]
    for index, parts in enumerate(split_roots):
        for other in split_roots[index + 1 :]:
            common = min(len(parts), len(other))
            if tuple(part.casefold() for part in parts[:common]) == tuple(
                part.casefold() for part in other[:common]
            ):
                raise CorpusError("repo_fixture paths must not overlap")
    fixtures = {
        task.task_id: _collect_fixture_tree(source, task.context.repo_fixture) for task in tasks
    }
    all_fixture_paths = [
        path for tree in fixtures.values() for path in [*tree.directories, *tree.files]
    ]
    _validate_casefold_unique(all_fixture_paths, label="fixture paths")
    return tasks, fixtures


def _canonical_task_bytes(task: EvalTask) -> bytes:
    return (task.model_dump_json(indent=2) + "\n").encode("utf-8")


def _prepare_release(
    source: Path,
    *,
    corpus_version: str,
    seed: str,
    salt: bytes,
) -> _PreparedRelease:
    tasks, fixtures = _load_approved_corpus(source)
    manifest = build_holdout_manifest(
        tasks,
        corpus_version=corpus_version,
        seed=seed,
        salt=salt,
    )
    holdout_ids = {entry.task_id for entry in manifest.tasks}
    development = sorted(
        (task for task in tasks if task.task_id not in holdout_ids),
        key=lambda task: task.task_id,
    )
    try:
        plan = CorpusReleasePlan(
            corpus_version=corpus_version,
            development_tasks=[
                CorpusTaskEntry(task_id=task.task_id, stratum=task.stratum) for task in development
            ],
            holdout_manifest=manifest,
        )
    except ValidationError as exc:
        raise CorpusError(f"invalid corpus release plan: {exc}") from exc

    public_directories = {"tasks", "fixtures"}
    private_directories = {"tasks", "fixtures"}
    public_files: dict[str, bytes] = {
        "holdout-manifest.json": (manifest.model_dump_json(indent=2) + "\n").encode()
    }
    private_files: dict[str, bytes] = {}
    for task in tasks:
        is_holdout = task.task_id in holdout_ids
        directories = private_directories if is_holdout else public_directories
        files = private_files if is_holdout else public_files
        files[f"tasks/{task.task_id}.json"] = _canonical_task_bytes(task)
        tree = fixtures[task.task_id]
        directories.update(tree.directories)
        files.update(tree.files)
    return _PreparedRelease(
        plan=plan,
        public_directories=frozenset(public_directories),
        public_files=public_files,
        private_directories=frozenset(private_directories),
        private_files=private_files,
    )


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":  # Windows has no equivalent directory flush.
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _set_descriptor_mode(descriptor: int, mode: int) -> None:
    """Tighten an open file where descriptor chmod is available."""

    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None:
        fchmod(descriptor, mode)


def _write_release_tree(
    root: Path,
    *,
    directories: Sequence[str],
    files: dict[str, bytes],
    private: bool,
) -> None:
    directory_mode = 0o700 if private else 0o755
    file_mode = 0o600 if private else 0o644
    for relative in sorted(directories, key=lambda value: (value.count("/"), value)):
        safe = _safe_tree_path(relative)
        destination = root.joinpath(*PurePosixPath(safe).parts)
        destination.mkdir(mode=directory_mode)
    for relative, payload in sorted(files.items()):
        safe = _safe_tree_path(relative)
        destination = root.joinpath(*PurePosixPath(safe).parts)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(destination, flags, file_mode)
        try:
            _set_descriptor_mode(descriptor, file_mode)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written == 0:
                    raise OSError("short write while staging corpus release")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for relative in sorted(directories, key=lambda value: value.count("/"), reverse=True):
        _fsync_directory(root.joinpath(*PurePosixPath(relative).parts))
    os.chmod(root, directory_mode)
    _fsync_directory(root)


def _publish_directory(staged: Path, target: Path) -> None:
    try:
        target.lstat()
    except FileNotFoundError:
        pass
    else:
        raise OSError(f"release output appeared during publication: {target}")
    os.rename(staged, target)
    _fsync_directory(target.parent)


def _discard_generated_tree(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError(f"generated staging path changed type: {path}")
    shutil.rmtree(path)


def _rollback_output(staged: Path, target: Path) -> None:
    if not staged.exists() and (target.exists() or target.is_symlink()):
        metadata = target.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise OSError(f"published output changed type during rollback: {target}")
        os.rename(target, staged)
        _fsync_directory(target.parent)
    _discard_generated_tree(staged)


def prepare_corpus_release(
    *,
    source: Path,
    public_output: Path,
    private_output: Path,
    repository_root: Path,
    corpus_version: str,
    seed: str,
    salt: bytes,
    dry_run: bool = False,
) -> CorpusReleasePlan:
    """Validate and atomically materialize one approved 20/10 corpus split.

    The private directory is published first. The public directory (including
    its redacted manifest) is the final commit point, so it can never appear
    complete before its corresponding private holdout has been published.
    """

    source_absolute = _absolute(source)
    public_absolute = _absolute(public_output)
    private_absolute = _absolute(private_output)
    repository_absolute = _absolute(repository_root)
    if _paths_overlap(public_absolute, private_absolute):
        raise CorpusError("public and private outputs must not overlap")
    if _paths_overlap(source_absolute, public_absolute) or _paths_overlap(
        source_absolute, private_absolute
    ):
        raise CorpusError("source and release outputs must not overlap")
    if _paths_overlap(repository_absolute, private_absolute):
        raise CorpusError("private output must be outside the repository")
    if _paths_overlap(repository_absolute, source_absolute):
        raise CorpusError("corpus source must be outside the repository")

    source_root = _require_existing_directory(source_absolute, label="corpus source")
    repository = _require_existing_directory(repository_absolute, label="repository root")
    public_target = _require_new_output(public_absolute, label="public output")
    private_target = _require_new_output(private_absolute, label="private output")
    if _paths_overlap(public_target, private_target):
        raise CorpusError("public and private outputs must not overlap")
    if _paths_overlap(source_root, public_target) or _paths_overlap(source_root, private_target):
        raise CorpusError("source and release outputs must not overlap")
    if _paths_overlap(repository, private_target):
        raise CorpusError("private output must be outside the repository")
    if _paths_overlap(repository, source_root):
        raise CorpusError("corpus source must be outside the repository")

    prepared = _prepare_release(
        source_root,
        corpus_version=corpus_version,
        seed=seed,
        salt=salt,
    )
    if dry_run:
        return prepared.plan

    public_stage: Path | None = None
    private_stage: Path | None = None
    try:
        public_stage = Path(
            tempfile.mkdtemp(prefix=f".{public_target.name}.stage-", dir=public_target.parent)
        )
        private_stage = Path(
            tempfile.mkdtemp(prefix=f".{private_target.name}.stage-", dir=private_target.parent)
        )
        _write_release_tree(
            public_stage,
            directories=prepared.public_directories,
            files=prepared.public_files,
            private=False,
        )
        _write_release_tree(
            private_stage,
            directories=prepared.private_directories,
            files=prepared.private_files,
            private=True,
        )
        _publish_directory(private_stage, private_target)
        _publish_directory(public_stage, public_target)
    except (OSError, CorpusError) as exc:
        cleanup_errors: list[str] = []
        for staged, target in (
            (public_stage, public_target),
            (private_stage, private_target),
        ):
            if staged is None:
                continue
            try:
                _rollback_output(staged, target)
            except OSError as cleanup_exc:
                cleanup_errors.append(str(cleanup_exc))
        detail = ""
        if cleanup_errors:
            detail = f"; manual cleanup required: {'; '.join(cleanup_errors)}"
        raise CorpusError(f"could not publish corpus release{detail}") from exc
    return prepared.plan


def read_owner_secret_file(path: Path, *, label: str) -> bytes:
    """Read a non-empty, owner-only regular file without exposing its contents."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CorpusError(f"{label} file is missing") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CorpusError(f"{label} file must be a regular file, not a symbolic link")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise CorpusError(f"{label} file must be owner-only (mode 0600)")
    payload = _read_regular_file(path, label=f"{label} file")
    if not payload:
        raise CorpusError(f"{label} file must not be empty")
    return payload


def load_holdout_manifest(path: Path) -> HoldoutManifest:
    """Load one strict manifest from a regular, non-symlinked file."""

    payload = _read_regular_file(path, label="holdout manifest")
    try:
        return HoldoutManifest.model_validate_json(payload)
    except (ValidationError, UnicodeError, ValueError) as exc:
        raise CorpusError("holdout manifest is invalid") from exc


def _append_access_event(
    path: Path,
    *,
    corpus_version: str,
    task_id: str,
    actor: str,
    purpose: str,
    timestamp: str,
) -> None:
    if not actor.strip() or not purpose.strip():
        raise CorpusError("holdout access requires a nonblank actor and purpose")
    if "\n" in actor or "\n" in purpose:
        raise CorpusError("holdout access metadata must fit on one line")
    absolute = _absolute(path)
    parent = _require_existing_directory(
        absolute.parent,
        label="holdout access log parent",
    )
    path = parent / absolute.name
    if path.exists():
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise CorpusError("holdout access log must be a regular file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    event = {
        "actor": actor,
        "corpus_version": corpus_version,
        "purpose": purpose,
        "task_id": task_id,
        "ts": timestamp,
    }
    payload = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
    try:
        descriptor = os.open(path, flags | nofollow, 0o600)
        try:
            _set_descriptor_mode(descriptor, 0o600)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written == 0:
                    raise OSError("short write to holdout access log")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise CorpusError("could not record holdout access") from exc


def read_private_holdout_task(
    task_id: str,
    *,
    manifest: HoldoutManifest,
    store: Path,
    salt: bytes,
    access_log: Path,
    actor: str,
    purpose: str,
    timestamp: str | None = None,
) -> EvalTask:
    """Log a freshness-burning access, then read and verify one private task."""

    by_id = {entry.task_id: entry for entry in manifest.tasks}
    entry = by_id.get(task_id)
    if entry is None:
        raise CorpusError(f"task {task_id} is not in the holdout manifest")
    _append_access_event(
        access_log,
        corpus_version=manifest.corpus_version,
        task_id=task_id,
        actor=actor,
        purpose=purpose,
        timestamp=utc_timestamp() if timestamp is None else timestamp,
    )

    store_root = _require_existing_directory(store, label="private task store")
    task_path = store_root / f"{task_id}.json"
    try:
        payload = _read_regular_file(task_path, label=f"private holdout task {task_id}")
        task = EvalTask.model_validate_json(payload)
    except (CorpusError, ValidationError, UnicodeError, ValueError) as exc:
        raise CorpusError(f"could not read private holdout task {task_id}") from exc
    if task.task_id != task_id:
        raise CorpusError(f"private holdout task ID mismatch for {task_id}")
    if canonical_task_hash(task, salt=salt) != entry.salted_hash:
        raise CorpusError(f"private holdout hash mismatch for {task_id}")
    return task


__all__ = [
    "CorpusError",
    "CorpusReleasePlan",
    "CorpusTaskEntry",
    "HoldoutEntry",
    "HoldoutManifest",
    "build_holdout_manifest",
    "load_holdout_manifest",
    "prepare_corpus_release",
    "read_private_holdout_task",
    "read_owner_secret_file",
    "select_holdout",
]
