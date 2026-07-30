"""Digest-pinned domain profiles shipped as inert TOML data."""

from __future__ import annotations

import hashlib
import importlib.resources
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class ProfileError(ValueError):
    """A domain profile is missing or malformed."""


class DomainProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    name: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    artifact_label: str = Field(min_length=1, max_length=80)
    backend: Literal["git-worktree", "tmpdir"]
    verification_renderers: list[Literal["pytest", "command", "assertion", "checklist"]] = Field(
        min_length=1
    )
    collision_term: str = Field(min_length=1, max_length=80)


@dataclass(frozen=True, slots=True)
class LoadedProfile:
    profile: DomainProfile
    digest: str
    raw: bytes
    source: str


def _parse_profile(raw: bytes, *, source: str) -> LoadedProfile:
    if len(raw) > 64 * 1024:
        raise ProfileError("domain profile exceeds 65536 bytes")
    try:
        value = tomllib.loads(raw.decode("utf-8"))
        profile = DomainProfile.model_validate(value)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValidationError) as exc:
        raise ProfileError(f"invalid domain profile {source}: {exc}") from exc
    if len(profile.verification_renderers) != len(set(profile.verification_renderers)):
        raise ProfileError("verification_renderers must not contain duplicates")
    return LoadedProfile(
        profile=profile,
        digest=hashlib.sha256(raw).hexdigest(),
        raw=raw,
        source=source,
    )


def load_profile(name: str = "coding", *, path: Path | None = None) -> LoadedProfile:
    if path is None:
        resource = importlib.resources.files("falsiq").joinpath("profiles", f"{name}.toml")
        try:
            raw = resource.read_bytes()
        except (FileNotFoundError, OSError) as exc:
            raise ProfileError(f"unknown packaged domain profile: {name}") from exc
        loaded = _parse_profile(raw, source=f"packaged:{name}")
    else:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ProfileError(f"could not inspect domain profile: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ProfileError("domain profile path must not be a symbolic link")
        if not stat.S_ISREG(metadata.st_mode):
            raise ProfileError("domain profile path must be a regular file")
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise ProfileError(f"could not read domain profile: {exc}") from exc
        loaded = _parse_profile(raw, source=str(path.resolve()))
    if loaded.profile.name != name:
        raise ProfileError(
            f"domain profile name mismatch: expected {name}, got {loaded.profile.name}"
        )
    return loaded


__all__ = [
    "DomainProfile",
    "LoadedProfile",
    "ProfileError",
    "load_profile",
]
