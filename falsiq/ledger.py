"""Append-only storage, integrity validation, and deterministic case state."""

from __future__ import annotations

import base64
import binascii
import errno
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
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
_TRANSACTION_VERSION = 1
_TRANSACTION_FIELDS = frozenset(
    {
        "append_b64",
        "append_sha256",
        "append_size",
        "original_size",
        "prefix_sha256",
        "version",
    }
)
_HEX_DIGITS = frozenset("0123456789abcdef")
_MANAGED_IGNORE_ENTRIES = (
    b"/sandbox/",
    b"/.ledger.lock",
    b"/.ledger.txn",
    b"/.ledger.txn.*",
    b"/cases/*/derived/.derive.lock",
)


class _ExpectedHeadOmitted:
    pass


_EXPECTED_HEAD_OMITTED = _ExpectedHeadOmitted()


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


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json_line(value: Mapping[str, object]) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _write_all(file_descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(file_descriptor, view)
        if written <= 0:
            raise OSError(f"short write: wrote {written} of {len(view)} remaining bytes")
        view = view[written:]


def _fsync_directory(path: Path) -> None:
    """Durably order a directory change where the platform supports it."""

    if os.name == "nt":  # Windows does not support opening directories for fsync.
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


def _ensure_managed_ignores(state_dir: Path) -> None:
    """Preserve user ignore rules while adding Falsiq's runtime sidecars."""

    path = state_dir / ".gitignore"
    if path.is_symlink():
        raise LedgerValidationError(".falsiq/.gitignore must not be a symlink")
    existed = path.exists()
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    try:
        file_descriptor = os.open(path, flags, 0o644)
    except OSError as exc:
        raise LedgerValidationError(f"could not manage .falsiq/.gitignore: {exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
            raise LedgerValidationError(".falsiq/.gitignore must be a regular file")
        os.lseek(file_descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while chunk := os.read(file_descriptor, 64 * 1024):
            chunks.append(chunk)
        current = b"".join(chunks)
        present = set(current.splitlines())
        missing = [entry for entry in _MANAGED_IGNORE_ENTRIES if entry not in present]
        if not missing:
            return
        separator = b"" if not current or current.endswith((b"\n", b"\r")) else b"\n"
        _write_all(file_descriptor, separator + b"\n".join(missing) + b"\n")
        os.fsync(file_descriptor)
    except OSError as exc:
        raise LedgerValidationError(f"could not manage .falsiq/.gitignore: {exc}") from exc
    finally:
        os.close(file_descriptor)
    if not existed:
        _fsync_directory(state_dir)


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
        raise LedgerValidationError(f"case artifact path must be beneath cases/{case_id}/: {path}")


def _is_canonical_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value).issubset(_HEX_DIGITS)
    )


def _validate_derivation_commitments(fact: DerivationFact) -> None:
    expected_brief = f"cases/{fact.case_id}/derived/IMPLEMENTATION_BRIEF.md"
    if fact.brief_path != expected_brief:
        raise LedgerValidationError(
            f"derivation brief_path must equal {expected_brief}: {fact.brief_path}"
        )
    if not _is_canonical_sha256(fact.brief_sha256):
        raise LedgerValidationError("derivation brief_sha256 is not canonical SHA-256")

    paths = fact.test_stub_paths
    digest_paths = set(fact.test_stub_sha256)
    if len(paths) != len(set(paths)) or set(paths) != digest_paths:
        raise LedgerValidationError(
            "derivation test stub paths and digest keys must match exactly"
        )
    expected_prefix = f"cases/{fact.case_id}/derived/tests/"
    for path in paths:
        filename = path.removeprefix(expected_prefix)
        if path == filename or not filename or "/" in filename:
            raise LedgerValidationError(
                "derivation test stub must be directly beneath "
                f"{expected_prefix.removesuffix('/')}: {path}"
            )
        if re.fullmatch(r"test_[a-z0-9_]+\.py", filename) is None:
            raise LedgerValidationError(
                f"derivation test stub has an invalid filename: {path}"
            )
        if not _is_canonical_sha256(fact.test_stub_sha256[path]):
            raise LedgerValidationError(
                f"derivation test stub digest is not canonical SHA-256: {path}"
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
                raise LedgerValidationError(f"re-ruling must supersede active ruling {current.id}")
            active_rulings[fact.attack_id] = fact
            if fact.verdict == "amend":
                amendment_rulings[fact.id] = fact

        elif isinstance(fact, DerivationFact):
            if position == 0 or fact.ledger_head != facts[position - 1].id:
                expected = facts[position - 1].id if position else "<none>"
                raise LedgerValidationError(
                    f"derivation ledger_head must equal current ledger head {expected}"
                )
            _validate_derivation_commitments(fact)

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
    case_positions = {fact.id: position for position, fact in enumerate(case_facts)}
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
        row["age_facts"] = len(case_facts) - case_positions[ruling.id] - 1
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
        self.journal_path = self.state_dir / ".ledger.txn"

    @classmethod
    def initialize(cls, start: str | os.PathLike[str] | None = None) -> Ledger:
        root = discover_repository(start)
        ledger = cls(root)
        if ledger.state_dir.is_symlink():
            raise LedgerValidationError(".falsiq must not be a symlink")
        ledger.state_dir.mkdir(exist_ok=True)
        _ensure_managed_ignores(ledger.state_dir)
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

    @staticmethod
    def _open_flags(flags: int) -> int:
        return flags | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)

    @staticmethod
    def _ensure_regular_file(file_descriptor: int, *, label: str) -> None:
        if not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
            raise LedgerIntegrityError(f"{label} is not a regular file")

    def _read_ledger_bytes_unlocked(self) -> bytes:
        if self.path.is_symlink():
            raise LedgerIntegrityError(f"ledger path must not be a symlink: {self.path}")
        try:
            file_descriptor = os.open(self.path, self._open_flags(os.O_RDONLY))
        except OSError as exc:
            raise LedgerIntegrityError(f"could not read ledger: {exc}") from exc
        try:
            self._ensure_regular_file(file_descriptor, label="ledger path")
            chunks: list[bytes] = []
            while chunk := os.read(file_descriptor, 1024 * 1024):
                chunks.append(chunk)
            return b"".join(chunks)
        except OSError as exc:
            raise LedgerIntegrityError(f"could not read ledger: {exc}") from exc
        finally:
            os.close(file_descriptor)

    @staticmethod
    def _parse_ledger_bytes(raw: bytes) -> tuple[Fact, ...]:
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

    def _read_unlocked(self) -> tuple[Fact, ...]:
        return self._parse_ledger_bytes(self._read_ledger_bytes_unlocked())

    def _transaction_journal_bytes(self, prefix: bytes, pending: bytes) -> bytes:
        payload: dict[str, object] = {
            "append_b64": base64.b64encode(pending).decode("ascii"),
            "append_sha256": _sha256(pending),
            "append_size": len(pending),
            "original_size": len(prefix),
            "prefix_sha256": _sha256(prefix),
            "version": _TRANSACTION_VERSION,
        }
        return _canonical_json_line(payload)

    def _load_transaction_journal_unlocked(self) -> tuple[int, str, bytes] | None:
        try:
            journal_stat = self.journal_path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise LedgerIntegrityError(f"could not inspect transaction journal: {exc}") from exc
        if stat.S_ISLNK(journal_stat.st_mode):
            raise LedgerIntegrityError(
                f"transaction journal must not be a symlink: {self.journal_path}"
            )
        if not stat.S_ISREG(journal_stat.st_mode):
            raise LedgerIntegrityError(
                f"transaction journal is not a regular file: {self.journal_path}"
            )

        try:
            file_descriptor = os.open(self.journal_path, self._open_flags(os.O_RDONLY))
        except OSError as exc:
            raise LedgerIntegrityError(f"could not read transaction journal: {exc}") from exc
        try:
            self._ensure_regular_file(file_descriptor, label="transaction journal")
            chunks: list[bytes] = []
            while chunk := os.read(file_descriptor, 1024 * 1024):
                chunks.append(chunk)
            raw = b"".join(chunks)
        except OSError as exc:
            raise LedgerIntegrityError(f"could not read transaction journal: {exc}") from exc
        finally:
            os.close(file_descriptor)

        if not raw.endswith(b"\n"):
            raise LedgerIntegrityError("transaction journal is truncated")
        try:
            payload = json.loads(raw[:-1])
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise LedgerIntegrityError(f"transaction journal is invalid JSON: {exc}") from exc
        if not isinstance(payload, dict) or set(payload) != _TRANSACTION_FIELDS:
            raise LedgerIntegrityError("transaction journal has an invalid schema")
        if raw != _canonical_json_line(payload):
            raise LedgerIntegrityError("transaction journal is not canonical JSON")

        version = payload["version"]
        original_size = payload["original_size"]
        append_size = payload["append_size"]
        prefix_digest = payload["prefix_sha256"]
        append_digest = payload["append_sha256"]
        encoded_append = payload["append_b64"]
        if type(version) is not int or version != _TRANSACTION_VERSION:
            raise LedgerIntegrityError("transaction journal has an unsupported version")
        if type(original_size) is not int or original_size < 0:
            raise LedgerIntegrityError("transaction journal has an invalid original_size")
        if type(append_size) is not int or append_size <= 0:
            raise LedgerIntegrityError("transaction journal has an invalid append_size")
        for label, digest in (
            ("prefix", prefix_digest),
            ("append", append_digest),
        ):
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or not set(digest).issubset(_HEX_DIGITS)
            ):
                raise LedgerIntegrityError(f"transaction journal has an invalid {label} digest")
        if not isinstance(encoded_append, str):
            raise LedgerIntegrityError("transaction journal has an invalid append payload")
        try:
            pending = base64.b64decode(encoded_append, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise LedgerIntegrityError(
                f"transaction journal has an invalid append payload: {exc}"
            ) from exc
        if len(pending) != append_size or _sha256(pending) != append_digest:
            raise LedgerIntegrityError("transaction journal append digest does not match payload")
        if not pending.endswith(b"\n"):
            raise LedgerIntegrityError("transaction journal append payload is truncated")
        return original_size, prefix_digest, pending

    def _write_transaction_journal_unlocked(self, prefix: bytes, pending: bytes) -> None:
        if not pending:
            raise LedgerValidationError("cannot journal an empty ledger append")
        try:
            existing = self.journal_path.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise LedgerIntegrityError(f"could not inspect transaction journal: {exc}") from exc
        else:
            label = "symlink" if stat.S_ISLNK(existing.st_mode) else "existing file"
            raise LedgerIntegrityError(f"transaction journal has an unexpected {label}")

        journal_bytes = self._transaction_journal_bytes(prefix, pending)
        file_descriptor, temporary_name = tempfile.mkstemp(
            dir=self.state_dir,
            prefix=".ledger.txn.",
        )
        temporary_path = Path(temporary_name)
        installed = False
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(file_descriptor, 0o600)
            _write_all(file_descriptor, journal_bytes)
            os.fsync(file_descriptor)
            os.close(file_descriptor)
            file_descriptor = -1
            if self.journal_path.is_symlink() or self.journal_path.exists():
                raise LedgerIntegrityError("transaction journal appeared while preparing append")
            os.replace(temporary_path, self.journal_path)
            installed = True
            _fsync_directory(self.state_dir)
        finally:
            if file_descriptor >= 0:
                os.close(file_descriptor)
            if not installed:
                temporary_path.unlink(missing_ok=True)

    def _remove_transaction_journal_unlocked(self) -> None:
        try:
            journal_stat = self.journal_path.lstat()
        except FileNotFoundError:
            _fsync_directory(self.state_dir)
            return
        if stat.S_ISLNK(journal_stat.st_mode):
            raise LedgerIntegrityError("transaction journal became a symlink")
        if not stat.S_ISREG(journal_stat.st_mode):
            raise LedgerIntegrityError("transaction journal is not a regular file")
        self.journal_path.unlink()
        _fsync_directory(self.state_dir)

    def _read_open_file(self, file_descriptor: int) -> bytes:
        os.lseek(file_descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while chunk := os.read(file_descriptor, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)

    def _append_transaction_bytes_unlocked(self, original_size: int, pending: bytes) -> None:
        journal = self._load_transaction_journal_unlocked()
        if journal is None:
            raise LedgerIntegrityError("transaction journal disappeared before ledger append")
        journal_size, prefix_digest, journal_pending = journal
        if journal_size != original_size or journal_pending != pending:
            raise LedgerIntegrityError("transaction journal changed before ledger append")

        try:
            file_descriptor = os.open(self.path, self._open_flags(os.O_RDWR))
        except OSError as exc:
            raise LedgerIntegrityError(f"could not open ledger for append: {exc}") from exc
        try:
            self._ensure_regular_file(file_descriptor, label="ledger path")
            prefix = self._read_open_file(file_descriptor)
            if len(prefix) != original_size or _sha256(prefix) != prefix_digest:
                raise LedgerIntegrityError("ledger prefix changed before append")
            os.lseek(file_descriptor, 0, os.SEEK_END)
            _write_all(file_descriptor, pending)
            os.fsync(file_descriptor)
        finally:
            os.close(file_descriptor)

    def _truncate_ledger_unlocked(self, original_size: int, observed: bytes) -> None:
        try:
            file_descriptor = os.open(self.path, self._open_flags(os.O_RDWR))
        except OSError as exc:
            raise LedgerIntegrityError(f"could not open ledger for recovery: {exc}") from exc
        try:
            self._ensure_regular_file(file_descriptor, label="ledger path")
            if self._read_open_file(file_descriptor) != observed:
                raise LedgerIntegrityError("ledger changed while recovering transaction")
            os.ftruncate(file_descriptor, original_size)
            os.fsync(file_descriptor)
        except OSError as exc:
            raise LedgerIntegrityError(f"could not recover ledger transaction: {exc}") from exc
        finally:
            os.close(file_descriptor)

    def _sync_ledger_unlocked(self, observed: bytes) -> None:
        try:
            file_descriptor = os.open(self.path, self._open_flags(os.O_RDWR))
        except OSError as exc:
            raise LedgerIntegrityError(f"could not open ledger for recovery: {exc}") from exc
        try:
            self._ensure_regular_file(file_descriptor, label="ledger path")
            if self._read_open_file(file_descriptor) != observed:
                raise LedgerIntegrityError("ledger changed while recovering transaction")
            os.fsync(file_descriptor)
        except OSError as exc:
            raise LedgerIntegrityError(
                f"could not sync recovered ledger transaction: {exc}"
            ) from exc
        finally:
            os.close(file_descriptor)

    def _recover_transaction_unlocked(self) -> None:
        journal = self._load_transaction_journal_unlocked()
        if journal is None:
            return
        original_size, prefix_digest, pending = journal
        raw = self._read_ledger_bytes_unlocked()
        if len(raw) < original_size:
            raise LedgerIntegrityError(
                "ledger is shorter than the transaction journal original_size"
            )
        if _sha256(raw[:original_size]) != prefix_digest:
            raise LedgerIntegrityError("transaction journal prefix digest does not match ledger")

        tail = raw[original_size:]
        if not tail:
            self._remove_transaction_journal_unlocked()
            return
        if len(tail) < len(pending) and tail == pending[: len(tail)]:
            self._truncate_ledger_unlocked(original_size, raw)
            self._remove_transaction_journal_unlocked()
            return
        if tail.startswith(pending):
            self._sync_ledger_unlocked(raw)
            self._remove_transaction_journal_unlocked()
            return
        raise LedgerIntegrityError(
            "ledger bytes after transaction prefix do not match the pending append"
        )

    def read(self) -> tuple[Fact, ...]:
        with _file_lock(self.lock_path, exclusive=True):
            self._recover_transaction_unlocked()
            return self._read_unlocked()

    def append(self, fact: FactBase | Mapping[str, object]) -> Fact:
        return self.append_batch([fact])[0]

    def append_batch(
        self,
        facts: Sequence[FactBase | Mapping[str, object]],
        *,
        expected_head: str | None | _ExpectedHeadOmitted = _EXPECTED_HEAD_OMITTED,
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
            self._recover_transaction_unlocked()
            existing_raw = self._read_ledger_bytes_unlocked()
            existing = self._parse_ledger_bytes(existing_raw)
            current_head = existing[-1].id if existing else None
            if expected_head is not _EXPECTED_HEAD_OMITTED and current_head != expected_head:
                expected = expected_head if expected_head is not None else "<empty>"
                current = current_head if current_head is not None else "<empty>"
                raise LedgerValidationError(
                    f"ledger head changed: expected {expected}, found {current}; retry the command"
                )
            validate_fact_sequence([*existing, *proposed])
            try:
                self._write_transaction_journal_unlocked(existing_raw, encoded)
            except OSError as exc:
                raise LedgerValidationError(f"could not prepare ledger transaction: {exc}") from exc
            try:
                self._append_transaction_bytes_unlocked(len(existing_raw), encoded)
            except BaseException as append_error:
                try:
                    self._recover_transaction_unlocked()
                except BaseException as recovery_error:
                    raise LedgerIntegrityError(
                        "ledger append failed and automatic transaction recovery failed"
                    ) from recovery_error
                if isinstance(append_error, OSError):
                    raise LedgerValidationError(
                        f"could not append ledger batch: {append_error}"
                    ) from append_error
                raise
            try:
                self._remove_transaction_journal_unlocked()
            except OSError as exc:
                raise LedgerValidationError(
                    f"ledger batch was committed but transaction journal cleanup failed: {exc}"
                ) from exc
        return tuple(proposed)

    def log(self, *, kind: FactKind | None = None, case_id: str | None = None) -> tuple[Fact, ...]:
        if kind is not None and kind not in _FACT_KINDS:
            raise LedgerValidationError(f"unknown fact kind: {kind}")
        return tuple(
            fact
            for fact in self.read()
            if (kind is None or fact.kind == kind) and (case_id is None or fact.case_id == case_id)
        )

    def state(self, case_id: str | None = None) -> dict[str, object]:
        facts = self.read()
        if case_id is not None:
            return derive_case_state(facts, case_id)
        root_ids = [
            fact.id for fact in facts if isinstance(fact, IntentFact) and fact.source == "user"
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
