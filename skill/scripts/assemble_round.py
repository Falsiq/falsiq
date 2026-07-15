#!/usr/bin/env python3
"""Normalize exactly five attacker batches into a deterministic round envelope."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from pydantic import TypeAdapter, ValidationError

from falsiq.attacks import AttackCandidateBatch, build_selection_envelope
from falsiq.facts import Ulid

_ATTACKERS = ("boundary", "consequence", "prototype", "conflict", "omission")
_MAX_BATCH_BYTES = 1_000_000


class AssemblyError(ValueError):
    """An attacker batch cannot safely participate in deterministic selection."""


def _read_regular_file(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AssemblyError(f"cannot inspect batch {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise AssemblyError(f"batch input must not be a symlink: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise AssemblyError(f"batch input must be a regular file: {path}")
    if metadata.st_size > _MAX_BATCH_BYTES:
        raise AssemblyError(f"batch input exceeds {_MAX_BATCH_BYTES} bytes: {path}")

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
            if size > _MAX_BATCH_BYTES:
                raise AssemblyError(f"batch input exceeds {_MAX_BATCH_BYTES} bytes: {path}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def assemble(case_id: str, round_number: int, paths: list[Path]) -> str:
    """Return canonical JSON for one complete, model-free selection envelope."""

    if len(paths) != len(_ATTACKERS):
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

    missing = sorted(set(_ATTACKERS).difference(batches))
    if missing:
        raise AssemblyError(f"missing attacker batches: {', '.join(missing)}")

    candidates = [
        candidate for attacker in _ATTACKERS for candidate in batches[attacker].candidates
    ]
    envelope = build_selection_envelope(case_id, round_number, candidates)
    return json.dumps(
        envelope.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="assemble five strict Falsiq attacker batches")
    parser.add_argument("--case", dest="case_id", required=True)
    parser.add_argument("--round", dest="round_number", type=int, choices=(1, 2), required=True)
    parser.add_argument("batches", nargs="*", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rendered = assemble(args.case_id, args.round_number, args.batches)
    except (AssemblyError, OSError, ValidationError, ValueError) as exc:
        if isinstance(exc, ValidationError):
            message = exc.errors(include_url=False)[0]["msg"]
        else:
            message = str(exc)
        print(f"error: {message}", file=sys.stderr)
        return 2
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
