"""Installed-package helpers used by the Falsiq orchestration skill."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from .attacks import (
    ReviewCandidate,
    ReviewCandidateBatch,
    ReviewClass,
    SelectionEnvelope,
    build_selection_envelope,
)
from .facts import (
    SCHEMA_VERSION,
    Artifact,
    ArtifactOption,
    AttackFact,
    DerivationFact,
    IntentFact,
    RulingFact,
    Ulid,
)
from .ledger import FalsiqError, Ledger, LedgerValidationError, derive_case_state
from .prompt_assets import load_production_prompt
from .review_language import neutralize_review_state

REVIEW_CLASSES = ("boundary", "consequence", "prototype", "conflict", "omission")
MAX_ATTACK_BATCH_BYTES = 1_000_000


class AssemblyError(FalsiqError):
    """A reviewer batch cannot safely participate in deterministic selection."""


class GuardError(FalsiqError):
    """The human-ruling or derivation barrier has not been satisfied."""


class ReviewGenerationRequest(BaseModel):
    """Self-contained instructions and schema for one external reviewer."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    case_id: Ulid
    reviewer: ReviewClass
    instructions: str = Field(min_length=1)
    state: dict[str, object]
    response_schema: dict[str, object]
    examples: list[dict[str, object]] = Field(min_length=2, max_length=2)


def _review_example(case_id: str, reviewer: ReviewClass) -> ReviewCandidateBatch:
    options = [
        ArtifactOption(key="A", body="Preserve the existing behavior."),
        ArtifactOption(key="B", body="Use the new behavior."),
    ]
    if reviewer == "consequence":
        artifact = Artifact(
            type="scenario",
            body=(
                "After 30 days, a second user observes the old behavior while the first "
                "sees the new behavior."
            ),
        )
    elif reviewer in {"prototype", "conflict"}:
        artifact = Artifact(type="rivals", options=options)
    else:
        artifact = Artifact(type="input", options=options)
    decision = f"observable {reviewer} behavior"
    candidate = ReviewCandidate(
        klass=reviewer,
        targets=[case_id],
        artifact=artifact,
        settles=[decision],
        silent_settles=[decision],
        risk_scenario="The implementation silently chooses the behavior the user rejects.",
        render_cost="cheap" if reviewer == "prototype" else "trivial",
    )
    return ReviewCandidateBatch(case_id=case_id, reviewer=reviewer, candidates=[candidate])


def build_review_request(
    ledger: Ledger,
    case_id: str,
    reviewer: ReviewClass,
) -> ReviewGenerationRequest:
    """Build one exact, role-scoped reviewer contract from current ledger state."""

    TypeAdapter(Ulid).validate_python(case_id, strict=True)
    TypeAdapter(ReviewClass).validate_python(reviewer, strict=True)
    case_state = ledger.state(case_id)
    state = neutralize_review_state(ledger.state() if reviewer == "conflict" else case_state)
    empty = ReviewCandidateBatch(case_id=case_id, reviewer=reviewer, candidates=[])
    populated = _review_example(case_id, reviewer)
    return ReviewGenerationRequest(
        case_id=case_id,
        reviewer=reviewer,
        instructions=load_production_prompt(reviewer),
        state=state,
        response_schema=ReviewCandidateBatch.model_json_schema(),
        examples=[empty.model_dump(mode="json"), populated.model_dump(mode="json")],
    )


def canonical_review_request_json(request: ReviewGenerationRequest) -> str:
    """Serialize one reviewer request deterministically."""

    return json.dumps(
        request.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constant: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def prepare_review_batch(
    case_id: str,
    reviewer: ReviewClass,
    path: Path,
) -> tuple[ReviewCandidateBatch, bool]:
    """Validate untrusted output or replace it with a canonical empty batch.

    A model can validly emit no candidates, so malformed output has no safer
    semantic recovery than the same empty contribution. Other reviewer roles
    can still complete the round, and deterministic assembly remains strict.
    """

    TypeAdapter(Ulid).validate_python(case_id, strict=True)
    TypeAdapter(ReviewClass).validate_python(reviewer, strict=True)
    fallback = ReviewCandidateBatch(case_id=case_id, reviewer=reviewer, candidates=[])
    try:
        value = json.loads(
            _read_regular_file(path).decode("utf-8"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
        batch = ReviewCandidateBatch.model_validate(value)
        if batch.case_id != case_id or batch.reviewer != reviewer:
            return fallback, True
    except (AssemblyError, RecursionError, UnicodeDecodeError, ValueError, TypeError):
        return fallback, True
    return batch, False


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

    if len(paths) != len(REVIEW_CLASSES):
        raise AssemblyError("exactly five reviewer batch files are required")
    TypeAdapter(Ulid).validate_python(case_id, strict=True)

    batches: dict[str, ReviewCandidateBatch] = {}
    for path in paths:
        batch = ReviewCandidateBatch.model_validate_json(_read_regular_file(path))
        if batch.case_id != case_id:
            raise AssemblyError(
                f"batch case mismatch in {path}: expected {case_id}, got {batch.case_id}"
            )
        if batch.reviewer in batches:
            raise AssemblyError(f"duplicate reviewer batch: {batch.reviewer}")
        batches[batch.reviewer] = batch

    missing = sorted(set(REVIEW_CLASSES).difference(batches))
    if missing:
        raise AssemblyError(f"missing reviewer batches: {', '.join(missing)}")

    candidates = [
        candidate for reviewer in REVIEW_CLASSES for candidate in batches[reviewer].candidates
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
        raise LedgerValidationError("case state contains invalid open reviews")
    if open_attacks:
        label = "review" if len(open_attacks) == 1 else "reviews"
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
    "REVIEW_CLASSES",
    "MAX_ATTACK_BATCH_BYTES",
    "ReviewGenerationRequest",
    "AssemblyError",
    "GuardError",
    "assemble_attack_round",
    "build_review_request",
    "canonical_review_request_json",
    "canonical_selection_json",
    "prepare_review_batch",
    "ready_brief",
]
