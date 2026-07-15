"""Installed-package helpers used by the Falsiq orchestration skill."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from pydantic import TypeAdapter

from .attacks import AttackCandidateBatch, SelectionEnvelope, build_selection_envelope
from .facts import AttackFact, DerivationFact, IntentFact, RulingFact, Ulid
from .ledger import FalsiqError, Ledger, LedgerValidationError, derive_case_state

ATTACK_CLASSES = ("boundary", "consequence", "prototype", "conflict", "omission")
MAX_ATTACK_BATCH_BYTES = 1_000_000


class AssemblyError(FalsiqError):
    """An attacker batch cannot safely participate in deterministic selection."""


class GuardError(FalsiqError):
    """The human-ruling or derivation barrier has not been satisfied."""


def _read_regular_file(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AssemblyError(f"cannot inspect batch {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise AssemblyError(f"batch input must not be a symlink: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise AssemblyError(f"batch input must be a regular file: {path}")
    if metadata.st_size > MAX_ATTACK_BATCH_BYTES:
        raise AssemblyError(f"batch input exceeds {MAX_ATTACK_BATCH_BYTES} bytes: {path}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AssemblyError(f"cannot open batch {path}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise AssemblyError(f"batch input must be a regular file: {path}")
        if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
            raise AssemblyError(f"batch input changed while opening: {path}")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 64 * 1024):
            size += len(chunk)
            if size > MAX_ATTACK_BATCH_BYTES:
                raise AssemblyError(f"batch input exceeds {MAX_ATTACK_BATCH_BYTES} bytes: {path}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def assemble_attack_round(
    case_id: str,
    round_number: int,
    paths: Sequence[Path],
) -> SelectionEnvelope:
    """Validate five class batches and return the canonical model-free selection."""

    if len(paths) != len(ATTACK_CLASSES):
        raise AssemblyError("exactly five attacker batch files are required")
    TypeAdapter(Ulid).validate_python(case_id, strict=True)

    batches: dict[str, AttackCandidateBatch] = {}
    for path in paths:
        batch = AttackCandidateBatch.model_validate_json(_read_regular_file(path))
        if batch.case_id != case_id:
            raise AssemblyError(
                f"batch case mismatch in {path}: expected {case_id}, got {batch.case_id}"
            )
        if batch.attacker in batches:
            raise AssemblyError(f"duplicate attacker batch: {batch.attacker}")
        batches[batch.attacker] = batch

    missing = sorted(set(ATTACK_CLASSES).difference(batches))
    if missing:
        raise AssemblyError(f"missing attacker batches: {', '.join(missing)}")

    candidates = [
        candidate for attacker in ATTACK_CLASSES for candidate in batches[attacker].candidates
    ]
    return build_selection_envelope(case_id, round_number, candidates)


def canonical_selection_json(envelope: SelectionEnvelope) -> str:
    """Serialize a selection envelope exactly once for CLI and wrapper callers."""

    return json.dumps(
        envelope.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _require_safe_path(
    ledger: Ledger,
    relative: str,
    *,
    label: str,
    directory: bool,
) -> tuple[Path, os.stat_result]:
    if (
        not relative
        or "\\" in relative
        or PurePosixPath(relative).is_absolute()
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        raise GuardError(f"{label} has an unsafe path: {relative}")
    path = ledger.state_dir
    parts = PurePosixPath(relative).parts
    for index, part in enumerate(parts):
        path = path / part
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise GuardError(f"{label} is unavailable: {path}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise GuardError(f"{label} path must not contain a symlink: {path}")
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise GuardError(f"{label} parent is not a directory: {path}")
        if index == len(parts) - 1:
            expected = stat.S_ISDIR if directory else stat.S_ISREG
            if not expected(metadata.st_mode):
                kind = "directory" if directory else "regular file"
                raise GuardError(f"{label} is not a {kind}: {path}")
    return path, metadata


def _committed_file(
    ledger: Ledger,
    relative: str,
    digest: str,
    *,
    label: str,
) -> Path:
    path, inspected = _require_safe_path(
        ledger,
        relative,
        label=label,
        directory=False,
    )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise GuardError(f"could not open {label}: {path}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise GuardError(f"{label} is not a regular file: {path}")
        if (inspected.st_dev, inspected.st_ino) != (opened.st_dev, opened.st_ino):
            raise GuardError(f"{label} changed while opening: {path}")
        hasher = hashlib.sha256()
        while chunk := os.read(descriptor, 64 * 1024):
            hasher.update(chunk)
    finally:
        os.close(descriptor)
    if hasher.hexdigest() != digest:
        raise GuardError(f"{label} digest mismatch: {path}")
    return path


def _committed_stubs(ledger: Ledger, derivation: DerivationFact) -> None:
    expected_prefix = f"cases/{derivation.case_id}/derived/tests/"
    expected_paths = set(derivation.test_stub_paths)
    if expected_paths != set(derivation.test_stub_sha256):
        raise GuardError("derivation test stub paths and digest keys do not match")
    if any(
        not path.startswith(expected_prefix) or "/" in path.removeprefix(expected_prefix)
        for path in expected_paths
    ):
        raise GuardError("derivation contains a non-canonical test stub path")

    tests_relative = expected_prefix.removesuffix("/")
    tests_path, _metadata = _require_safe_path(
        ledger,
        tests_relative,
        label="derived tests directory",
        directory=True,
    )
    expected_names = {PurePosixPath(path).name for path in expected_paths}
    try:
        with os.scandir(tests_path) as entries:
            actual_names = {entry.name for entry in entries}
    except OSError as exc:
        raise GuardError(f"could not inspect derived tests directory: {exc}") from exc
    missing = sorted(expected_names.difference(actual_names))
    if missing:
        raise GuardError(f"missing derived test stubs: {missing}")
    unexpected = sorted(actual_names.difference(expected_names))
    if unexpected:
        raise GuardError(f"unexpected derived test stubs: {unexpected}")

    for path in sorted(expected_paths):
        _committed_file(
            ledger,
            path,
            derivation.test_stub_sha256[path],
            label="derived test stub",
        )


def ready_brief(case_id: str, start: Path | None = None) -> tuple[Ledger, Path]:
    """Return the only current case-scoped brief, or fail before code is edited."""

    TypeAdapter(Ulid).validate_python(case_id, strict=True)
    ledger = Ledger.open(start)
    facts = ledger.read()
    state = derive_case_state(facts, case_id)
    open_attacks = state["open_attacks"]
    if not isinstance(open_attacks, list):
        raise LedgerValidationError("case state contains invalid open attacks")
    if open_attacks:
        label = "attack" if len(open_attacks) == 1 else "attacks"
        raise GuardError(
            f"case {case_id} has {len(open_attacks)} open {label}; STOP -- HUMAN RULING REQUIRED"
        )

    derivations = [
        (index, fact)
        for index, fact in enumerate(facts)
        if isinstance(fact, DerivationFact) and fact.case_id == case_id
    ]
    if not derivations:
        raise GuardError(
            f"case {case_id} has no current derivation; derive and submit a brief first"
        )
    derivation_index, current = derivations[-1]
    spec_facts = (IntentFact, AttackFact, RulingFact)
    if any(
        fact.case_id == case_id and isinstance(fact, spec_facts)
        for fact in facts[derivation_index + 1 :]
    ):
        raise GuardError(
            f"case {case_id} has no current derivation; intent or rulings changed after derive"
        )
    expected = f"cases/{case_id}/derived/IMPLEMENTATION_BRIEF.md"
    if current.brief_path != expected:
        raise GuardError(f"current derivation names an unexpected brief path: {current.brief_path}")
    brief = _committed_file(
        ledger,
        current.brief_path,
        current.brief_sha256,
        label="derived brief",
    )
    _committed_stubs(ledger, current)
    return ledger, brief


__all__ = [
    "ATTACK_CLASSES",
    "MAX_ATTACK_BATCH_BYTES",
    "AssemblyError",
    "GuardError",
    "assemble_attack_round",
    "canonical_selection_json",
    "ready_brief",
]
