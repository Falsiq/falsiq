"""Append-only storage, integrity validation, and deterministic case state."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Literal, cast

from pydantic import ValidationError

from .facts import (
    SCHEMA_VERSION,
    AttackFact,
    DerivationFact,
    Fact,
    FactBase,
    IntentFact,
    OutcomeFact,
    RulingFact,
    parse_fact,
)

FactKind = Literal["intent", "attack", "ruling", "derivation", "outcome"]
_FACT_KINDS = frozenset({"intent", "attack", "ruling", "derivation", "outcome"})


class FalsiqError(Exception):
    """Base class for expected, user-facing Falsiq errors."""


class RepositoryNotFoundError(FalsiqError):
    """Raised when an operation is attempted outside a Git worktree."""


class LedgerNotInitializedError(FalsiqError):
    """Raised when the target repository has no Falsiq ledger."""


class LedgerValidationError(FalsiqError):
    """Raised when a proposed fact would violate ledger invariants."""


class LedgerIntegrityError(FalsiqError):
    """Raised when existing ledger bytes are malformed or inconsistent."""


def discover_repository(start: str | os.PathLike[str] | None = None) -> Path:
    """Return the containing Git worktree root, following Git's own semantics."""

    candidate = Path.cwd() if start is None else Path(start)
    if candidate.is_file():
        candidate = candidate.parent
    try:
        result = subprocess.run(
            ["git", "-C", str(candidate), "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RepositoryNotFoundError("Git is required but was not found") from exc
    if result.returncode != 0:
        raise RepositoryNotFoundError(f"not inside a Git repository: {candidate}")
    root_text = result.stdout.strip()
    if not root_text:
        raise RepositoryNotFoundError(f"Git did not report a worktree root for: {candidate}")
    return Path(root_text).resolve()


def canonical_fact_json(fact: FactBase) -> str:
    """Serialize one fact to the sole accepted on-disk JSON representation."""

    return json.dumps(
        fact.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _artifact_paths(fact: AttackFact) -> Iterator[str]:
    if fact.artifact.path is not None:
        yield fact.artifact.path
    for option in fact.artifact.options:
        if option.path is not None:
            yield option.path


def _validate_case_artifact_path(path: str, case_id: str) -> None:
    if not path.startswith(f"cases/{case_id}/"):
        raise LedgerValidationError(
            f"case artifact path must be beneath cases/{case_id}/: {path}"
        )


def _require_prior(
    by_id: Mapping[str, Fact], reference: str, expected_type: type[FactBase], label: str
) -> FactBase:
    target = by_id.get(reference)
    if target is None:
        raise LedgerValidationError(f"unknown {label}: {reference}")
    if not isinstance(target, expected_type):
        raise LedgerValidationError(f"{label} {reference} has kind {target.kind}")
    return target


def validate_fact_sequence(facts: Sequence[Fact]) -> None:
    """Validate all reference, case, and supersession invariants in append order."""

    by_id: dict[str, Fact] = {}
    case_roots: dict[str, IntentFact] = {}
    active_intents: dict[str, set[str]] = {}
    active_rulings: dict[str, RulingFact] = {}
    amendment_rulings: dict[str, RulingFact] = {}
    amendment_intents: dict[str, IntentFact] = {}

    for position, fact in enumerate(facts):
        if fact.id in by_id:
            raise LedgerValidationError(f"duplicate fact id: {fact.id}")

        is_root = isinstance(fact, IntentFact) and fact.source == "user"
        if is_root:
            if fact.case_id in case_roots:
                raise LedgerValidationError(f"duplicate root intent for case: {fact.case_id}")
            case_roots[fact.case_id] = fact
            active_intents[fact.case_id] = {fact.id}
        else:
            root = case_roots.get(fact.case_id)
            if root is None:
                raise LedgerValidationError(f"unknown case_id: {fact.case_id}")

        if isinstance(fact, IntentFact) and fact.source == "amendment":
            supersedes = cast(str, fact.supersedes)
            source_ruling_id = cast(str, fact.source_ruling_id)
            target = _require_prior(by_id, supersedes, IntentFact, "supersedes intent")
            if target.case_id != fact.case_id:
                raise LedgerValidationError("superseded intent must belong to the same case")
            if supersedes not in active_intents[fact.case_id]:
                raise LedgerValidationError(
                    f"amendment must supersede an active intent: {supersedes}"
                )

            ruling = _require_prior(by_id, source_ruling_id, RulingFact, "source ruling")
            if ruling.case_id != fact.case_id:
                raise LedgerValidationError("source ruling must belong to the same case")
            if ruling.verdict != "amend":
                raise LedgerValidationError("source ruling must have verdict amend")
            if ruling.amendment_text != fact.text:
                raise LedgerValidationError(
                    "amendment intent text must equal the ruling amendment_text"
                )
            source_attack = cast(AttackFact, by_id[ruling.attack_id])
            if supersedes not in source_attack.targets:
                raise LedgerValidationError(
                    "amendment must supersede an intent targeted by its attack"
                )
            if source_ruling_id in amendment_intents:
                raise LedgerValidationError(
                    f"source ruling already has an amendment intent: {source_ruling_id}"
                )
            amendment_intents[source_ruling_id] = fact
            active_intents[fact.case_id].remove(supersedes)
            active_intents[fact.case_id].add(fact.id)

        elif isinstance(fact, AttackFact):
            for target_id in fact.targets:
                target = _require_prior(by_id, target_id, IntentFact, "attack target")
                if target.case_id != fact.case_id:
                    raise LedgerValidationError("attack target must belong to the same case")
            for path in _artifact_paths(fact):
                _validate_case_artifact_path(path, fact.case_id)

        elif isinstance(fact, RulingFact):
            target_attack = _require_prior(by_id, fact.attack_id, AttackFact, "attack")
            if target_attack.case_id != fact.case_id:
                raise LedgerValidationError("ruling attack must belong to the same case")

            option_keys = {option.key for option in target_attack.artifact.options}
            if option_keys and fact.verdict in {"intended", "forbidden"}:
                if fact.choice is None:
                    raise LedgerValidationError(
                        "option-bearing intended/forbidden ruling requires --choice"
                    )
                if fact.choice not in option_keys:
                    raise LedgerValidationError(
                        f"unknown option {fact.choice!r}; expected one of {sorted(option_keys)}"
                    )
            elif not option_keys and fact.choice is not None:
                raise LedgerValidationError("attack does not have options; choice is not valid")

            current = active_rulings.get(fact.attack_id)
            if current is None:
                if fact.supersedes is not None:
                    raise LedgerValidationError(
                        "first ruling for an attack cannot supersede a ruling"
                    )
            elif fact.supersedes != current.id:
                raise LedgerValidationError(
                    f"re-ruling must supersede active ruling {current.id}"
                )
            active_rulings[fact.attack_id] = fact
            if fact.verdict == "amend":
                amendment_rulings[fact.id] = fact

        elif isinstance(fact, DerivationFact):
            if position == 0 or fact.ledger_head != facts[position - 1].id:
                expected = facts[position - 1].id if position else "<none>"
                raise LedgerValidationError(
                    f"derivation ledger_head must equal current ledger head {expected}"
                )
            _validate_case_artifact_path(fact.brief_path, fact.case_id)
            for path in fact.test_stub_paths:
                _validate_case_artifact_path(path, fact.case_id)

        elif isinstance(fact, OutcomeFact) and fact.attack_id is not None:
            outcome_attack = _require_prior(by_id, fact.attack_id, AttackFact, "outcome attack")
            if outcome_attack.case_id != fact.case_id:
                raise LedgerValidationError("outcome attack must belong to the same case")

        by_id[fact.id] = fact

    missing_amendments = set(amendment_rulings).difference(amendment_intents)
    if missing_amendments:
        missing = min(missing_amendments)
        raise LedgerValidationError(f"amend ruling requires a linked amendment intent: {missing}")


def _option_states(attack: AttackFact, ruling: RulingFact) -> dict[str, str]:
    states = {option.key: "unruled" for option in attack.artifact.options}
    if ruling.choice is None:
        return states
    if ruling.verdict == "intended":
        states = {key: "not_intended" for key in states}
        states[ruling.choice] = "intended"
    elif ruling.verdict == "forbidden":
        states[ruling.choice] = "forbidden"
    return states


def derive_case_state(facts: Sequence[Fact], case_id: str) -> dict[str, object]:
    """Derive a case's active intents, active rulings, and open attacks."""

    case_facts = [fact for fact in facts if fact.case_id == case_id]
    roots = [
        fact
        for fact in case_facts
        if isinstance(fact, IntentFact) and fact.source == "user" and fact.id == case_id
    ]
    if not roots:
        raise LedgerValidationError(f"unknown case: {case_id}")

    superseded_intents = {
        fact.supersedes
        for fact in case_facts
        if isinstance(fact, IntentFact) and fact.supersedes is not None
    }
    intents = [
        fact.model_dump(mode="json")
        for fact in case_facts
        if isinstance(fact, IntentFact) and fact.id not in superseded_intents
    ]
    attacks = [fact for fact in case_facts if isinstance(fact, AttackFact)]
    active_rulings: dict[str, RulingFact] = {}
    for fact in case_facts:
        if isinstance(fact, RulingFact):
            active_rulings[fact.attack_id] = fact

    ruling_rows: list[dict[str, object]] = []
    for attack in attacks:
        ruling = active_rulings.get(attack.id)
        if ruling is None:
            continue
        row = ruling.model_dump(mode="json")
        row["attack_class"] = attack.klass
        row["option_states"] = _option_states(attack, ruling)
        ruling_rows.append(row)

    open_attacks = [
        attack.model_dump(mode="json") for attack in attacks if attack.id not in active_rulings
    ]
    outcomes = [
        fact.model_dump(mode="json") for fact in case_facts if isinstance(fact, OutcomeFact)
    ]
    derivations = [
        fact.model_dump(mode="json") for fact in case_facts if isinstance(fact, DerivationFact)
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "ledger_head": facts[-1].id if facts else None,
        "case_head": case_facts[-1].id,
        "intents": intents,
        "rulings": ruling_rows,
        "open_attacks": open_attacks,
        "outcomes": outcomes,
        "derivations": derivations,
        "rounds_used": sorted({attack.round for attack in attacks}),
    }


@contextmanager
def _file_lock(path: Path, *, exclusive: bool) -> Iterator[None]:
    """Hold a process-safe advisory lock on the ledger's sibling lock file."""

    if path.is_symlink():
        raise LedgerValidationError(f"lock path must not be a symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as lock_file:
        if os.name == "nt":  # pragma: no cover - exercised on Windows CI
            import msvcrt

            lock_file.seek(0, os.SEEK_END)
            if lock_file.tell() == 0:
                lock_file.write(b"\0")
                lock_file.flush()
            lock_file.seek(0)
            mode = msvcrt.LK_LOCK
            msvcrt.locking(lock_file.fileno(), mode, 1)
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            fcntl.flock(lock_file.fileno(), mode)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


class Ledger:
    """One repository's single append-only Falsiq fact ledger."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.state_dir = self.root / ".falsiq"
        self.path = self.state_dir / "ledger.jsonl"
        self.lock_path = self.state_dir / ".ledger.lock"

    @classmethod
    def initialize(cls, start: str | os.PathLike[str] | None = None) -> Ledger:
        root = discover_repository(start)
        ledger = cls(root)
        if ledger.state_dir.is_symlink():
            raise LedgerValidationError(".falsiq must not be a symlink")
        ledger.state_dir.mkdir(exist_ok=True)
        cases = ledger.state_dir / "cases"
        if cases.is_symlink():
            raise LedgerValidationError(".falsiq/cases must not be a symlink")
        cases.mkdir(exist_ok=True)
        if ledger.path.is_symlink():
            raise LedgerValidationError("ledger path must not be a symlink")
        try:
            ledger.path.open("xb").close()
        except FileExistsError:
            if not ledger.path.is_file():
                raise LedgerValidationError(
                    f"ledger is not a regular file: {ledger.path}"
                ) from None
        return ledger

    @classmethod
    def open(cls, start: str | os.PathLike[str] | None = None) -> Ledger:
        ledger = cls(discover_repository(start))
        if not ledger.state_dir.is_dir() or not ledger.path.is_file():
            raise LedgerNotInitializedError(
                f"Falsiq is not initialized in {ledger.root}; run `falsiq init`"
            )
        if ledger.state_dir.is_symlink() or ledger.path.is_symlink():
            raise LedgerValidationError("Falsiq ledger paths must not be symlinks")
        return ledger

    def _read_unlocked(self) -> tuple[Fact, ...]:
        try:
            raw = self.path.read_bytes()
        except OSError as exc:
            raise LedgerIntegrityError(f"could not read ledger: {exc}") from exc
        if not raw:
            return ()
        if not raw.endswith(b"\n"):
            line_number = raw.count(b"\n") + 1
            raise LedgerIntegrityError(
                f"ledger line {line_number} is truncated (missing final newline)"
            )

        facts: list[Fact] = []
        for line_number, encoded_line in enumerate(raw.splitlines(keepends=True), start=1):
            if not encoded_line.endswith(b"\n"):
                raise LedgerIntegrityError(f"ledger line {line_number} is truncated")
            encoded = encoded_line[:-1]
            try:
                fact = parse_fact(encoded)
            except (ValidationError, ValueError) as exc:
                raise LedgerIntegrityError(f"invalid ledger line {line_number}: {exc}") from exc
            canonical = canonical_fact_json(fact).encode("utf-8")
            if encoded != canonical:
                raise LedgerIntegrityError(f"ledger line {line_number} is not canonical JSON")
            facts.append(fact)

        try:
            validate_fact_sequence(facts)
        except LedgerValidationError as exc:
            raise LedgerIntegrityError(f"ledger references are invalid: {exc}") from exc
        return tuple(facts)

    def read(self) -> tuple[Fact, ...]:
        with _file_lock(self.lock_path, exclusive=False):
            return self._read_unlocked()

    def append(self, fact: FactBase | Mapping[str, object]) -> Fact:
        return self.append_batch([fact])[0]

    def append_batch(
        self, facts: Sequence[FactBase | Mapping[str, object]]
    ) -> tuple[Fact, ...]:
        if not facts:
            raise LedgerValidationError("cannot append an empty fact batch")
        proposed: list[Fact] = []
        for position, value in enumerate(facts, start=1):
            try:
                if isinstance(value, FactBase):
                    parsed = parse_fact(value.model_dump(mode="json"))
                else:
                    parsed = parse_fact(value)
            except (ValidationError, ValueError, TypeError) as exc:
                raise LedgerValidationError(f"invalid fact {position} in batch: {exc}") from exc
            proposed.append(parsed)

        encoded = "".join(canonical_fact_json(fact) + "\n" for fact in proposed).encode()
        with _file_lock(self.lock_path, exclusive=True):
            existing = self._read_unlocked()
            validate_fact_sequence([*existing, *proposed])
            try:
                with self.path.open("r+b") as ledger_file:
                    ledger_file.seek(0, os.SEEK_END)
                    original_size = ledger_file.tell()
                    try:
                        written = ledger_file.write(encoded)
                        if written != len(encoded):
                            raise OSError(
                                f"short ledger write: wrote {written} of {len(encoded)} bytes"
                            )
                        ledger_file.flush()
                        os.fsync(ledger_file.fileno())
                    except BaseException:
                        ledger_file.seek(original_size)
                        ledger_file.truncate()
                        ledger_file.flush()
                        os.fsync(ledger_file.fileno())
                        raise
            except OSError as exc:
                raise LedgerValidationError(f"could not append ledger batch: {exc}") from exc
        return tuple(proposed)

    def log(
        self, *, kind: FactKind | None = None, case_id: str | None = None
    ) -> tuple[Fact, ...]:
        if kind is not None and kind not in _FACT_KINDS:
            raise LedgerValidationError(f"unknown fact kind: {kind}")
        return tuple(
            fact
            for fact in self.read()
            if (kind is None or fact.kind == kind)
            and (case_id is None or fact.case_id == case_id)
        )

    def state(self, case_id: str | None = None) -> dict[str, object]:
        facts = self.read()
        if case_id is not None:
            return derive_case_state(facts, case_id)
        root_ids = [
            fact.id
            for fact in facts
            if isinstance(fact, IntentFact) and fact.source == "user"
        ]
        return {
            "schema_version": SCHEMA_VERSION,
            "ledger_head": facts[-1].id if facts else None,
            "cases": [derive_case_state(facts, root_id) for root_id in root_ids],
        }


__all__ = [
    "FalsiqError",
    "Ledger",
    "LedgerIntegrityError",
    "LedgerNotInitializedError",
    "LedgerValidationError",
    "RepositoryNotFoundError",
    "canonical_fact_json",
    "derive_case_state",
    "discover_repository",
    "validate_fact_sequence",
]
