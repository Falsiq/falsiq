#!/usr/bin/env python3
"""Fail closed unless a case is ready for implementation from its current brief."""

from __future__ import annotations

import argparse
import stat
import sys
from pathlib import Path, PurePosixPath

from pydantic import TypeAdapter, ValidationError

from falsiq.facts import AttackFact, DerivationFact, IntentFact, RulingFact, Ulid
from falsiq.ledger import FalsiqError, Ledger, LedgerValidationError, derive_case_state


class GuardError(ValueError):
    """The human-ruling or derivation barrier has not been satisfied."""


def _require_safe_brief(ledger: Ledger, relative: str) -> Path:
    path = ledger.state_dir
    parts = PurePosixPath(relative).parts
    for index, part in enumerate(parts):
        path = path / part
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise GuardError(f"derived brief is unavailable: {path}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise GuardError(f"derived brief path must not contain a symlink: {path}")
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise GuardError(f"derived brief parent is not a directory: {path}")
        if index == len(parts) - 1 and not stat.S_ISREG(metadata.st_mode):
            raise GuardError(f"derived brief is not a regular file: {path}")
    return path


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
    return ledger, _require_safe_brief(ledger, current.brief_path)


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
