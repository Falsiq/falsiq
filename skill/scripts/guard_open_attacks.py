#!/usr/bin/env python3
"""Fail closed unless a case is ready for implementation from its current brief."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from pathlib import Path, PurePosixPath

from pydantic import TypeAdapter, ValidationError

from falsiq.facts import AttackFact, DerivationFact, IntentFact, RulingFact, Ulid
from falsiq.ledger import FalsiqError, Ledger, LedgerValidationError, derive_case_state


class GuardError(ValueError):
    """The human-ruling or derivation barrier has not been satisfied."""


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="guard Falsiq's human-ruling and derived-brief barrier"
    )
    parser.add_argument("--case", dest="case_id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ledger, brief = ready_brief(args.case_id)
    except (FalsiqError, GuardError, OSError, ValidationError, ValueError) as exc:
        if isinstance(exc, ValidationError):
            message = exc.errors(include_url=False)[0]["msg"]
        else:
            message = str(exc)
        print(f"error: {message}", file=sys.stderr)
        return 2
    print(brief.relative_to(ledger.root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
