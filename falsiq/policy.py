"""Digest-pinned runtime policy for durable Falsiq facts."""

from __future__ import annotations

import hashlib
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class PolicyError(ValueError):
    """A policy file or policy-governed operation is invalid."""


class FalsiqPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    max_rounds: int = Field(default=2, ge=1, le=100)


@dataclass(frozen=True, slots=True)
class LoadedPolicy:
    policy: FalsiqPolicy
    digest: str
    source: Path | None


DEFAULT_POLICY = LoadedPolicy(
    policy=FalsiqPolicy(),
    digest=hashlib.sha256(b"max_rounds = 2\n").hexdigest(),
    source=None,
)


def _read_regular_file(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PolicyError(f"could not inspect policy: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise PolicyError("policy path must not be a symbolic link")
    if not stat.S_ISREG(metadata.st_mode):
        raise PolicyError("policy path must be a regular file")
    if metadata.st_size > 64 * 1024:
        raise PolicyError("policy file exceeds 65536 bytes")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise PolicyError(f"could not read policy: {exc}") from exc


def load_policy(path: Path | None = None) -> LoadedPolicy:
    if path is None:
        return DEFAULT_POLICY
    raw = _read_regular_file(path)
    try:
        decoded = tomllib.loads(raw.decode("utf-8"))
        policy = FalsiqPolicy.model_validate(decoded)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValidationError) as exc:
        raise PolicyError(f"invalid policy: {exc}") from exc
    return LoadedPolicy(
        policy=policy,
        digest=hashlib.sha256(raw).hexdigest(),
        source=path.resolve(),
    )


def validate_round(round_number: int, policy: FalsiqPolicy) -> None:
    if isinstance(round_number, bool) or not isinstance(round_number, int) or round_number < 1:
        raise PolicyError("round must be a positive integer")
    if round_number > policy.max_rounds:
        raise PolicyError(f"round {round_number} exceeds policy max_rounds={policy.max_rounds}")


__all__ = [
    "DEFAULT_POLICY",
    "FalsiqPolicy",
    "LoadedPolicy",
    "PolicyError",
    "load_policy",
    "validate_round",
]
