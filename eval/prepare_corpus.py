"""Prepare an approved public/private benchmark corpus release."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from falsiq.corpus import CorpusError, prepare_corpus_release, read_owner_secret_file


def _require_secret_outside_repository(path: Path, *, repository: Path, label: str) -> None:
    try:
        inside = path.resolve(strict=True).is_relative_to(repository)
    except OSError as exc:
        raise CorpusError(f"could not verify {label} file location") from exc
    if inside:
        raise CorpusError(f"{label} file must be outside the repository")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Materialize a human-approved corpus without exposing holdout bodies."
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    parser.add_argument("--private-output", type=Path, required=True)
    parser.add_argument("--corpus-version", required=True)
    parser.add_argument(
        "--seed-file",
        type=Path,
        required=True,
        help="owner-only UTF-8 file containing the split seed (never printed)",
    )
    parser.add_argument(
        "--salt-file",
        type=Path,
        required=True,
        help="owner-only binary file containing the manifest salt (never printed)",
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    repository_root = Path(__file__).resolve().parents[1]
    try:
        seed_bytes = read_owner_secret_file(arguments.seed_file, label="seed")
        _require_secret_outside_repository(
            arguments.seed_file, repository=repository_root, label="seed"
        )
        try:
            seed = seed_bytes.decode("utf-8")
        except UnicodeError as exc:
            raise CorpusError("seed file must contain UTF-8") from exc
        seed = seed.removesuffix("\n").removesuffix("\r")
        salt = read_owner_secret_file(arguments.salt_file, label="salt")
        _require_secret_outside_repository(
            arguments.salt_file, repository=repository_root, label="salt"
        )
        plan = prepare_corpus_release(
            source=arguments.source,
            public_output=arguments.public_output,
            private_output=arguments.private_output,
            repository_root=repository_root,
            corpus_version=arguments.corpus_version,
            seed=seed,
            salt=salt,
            dry_run=arguments.dry_run,
        )
    except CorpusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(plan.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
