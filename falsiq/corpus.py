"""Seeded corpus splitting and private holdout access controls."""

from __future__ import annotations

import hashlib
import json
import os
import random
import stat
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from .benchmark import EvalTask, canonical_task_hash, load_task
from .facts import utc_timestamp

_SPLIT_POLICY: dict[str, int] = {"synthetic": 3, "mined": 3, "control": 4}
_HEX_DIGEST_LENGTH = 64


class CorpusError(RuntimeError):
    """A corpus operation would weaken holdout integrity."""


class _CorpusModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class HoldoutEntry(_CorpusModel):
    task_id: str
    stratum: Literal["synthetic", "mined", "control"]
    salted_hash: str

    @field_validator("salted_hash")
    @classmethod
    def hash_is_sha256(cls, value: str) -> str:
        invalid_character = any(
            character not in "0123456789abcdef" for character in value
        )
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
        invalid_character = any(
            character not in "0123456789abcdef" for character in value
        )
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


def build_holdout_manifest(
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
    path.parent.mkdir(parents=True, exist_ok=True)
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
            os.fchmod(descriptor, 0o600)
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

    task_path = store / f"{task_id}.json"
    try:
        if task_path.is_symlink() or not task_path.is_file():
            raise OSError("private task is not a regular file")
        task = load_task(task_path)
    except (OSError, UnicodeError, ValueError) as exc:
        raise CorpusError(f"could not read private holdout task {task_id}") from exc
    if task.task_id != task_id:
        raise CorpusError(f"private holdout task ID mismatch for {task_id}")
    if canonical_task_hash(task, salt=salt) != entry.salted_hash:
        raise CorpusError(f"private holdout hash mismatch for {task_id}")
    return task


__all__ = [
    "CorpusError",
    "HoldoutEntry",
    "HoldoutManifest",
    "build_holdout_manifest",
    "read_private_holdout_task",
    "select_holdout",
]
