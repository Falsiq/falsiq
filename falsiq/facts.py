"""Strict, versioned models for Falsiq's durable JSONL facts."""

from __future__ import annotations

import re
import secrets
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import PurePosixPath, PureWindowsPath
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    field_validator,
    model_validator,
)

from .constraints import validate_consequence_artifact

SCHEMA_VERSION = 1

_CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_VALUES = {character: index for index, character in enumerate(_CROCKFORD_ALPHABET)}
_ULID_PATTERN = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}(?:\d{3})?Z$")

Ulid = Annotated[str, StringConstraints(pattern=r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
OptionKey = Annotated[
    str,
    StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$"),
]


def new_ulid(*, timestamp_ms: int | None = None, randomness: bytes | None = None) -> str:
    """Return a canonical Crockford-base32 ULID using only the standard library.

    The optional inputs make the encoding testable; production callers normally omit
    both and receive the current UTC millisecond plus 80 cryptographically random bits.
    """

    if timestamp_ms is None:
        timestamp_ms = time.time_ns() // 1_000_000
    if isinstance(timestamp_ms, bool) or not isinstance(timestamp_ms, int):
        raise TypeError("timestamp_ms must be an integer")
    if not 0 <= timestamp_ms < 1 << 48:
        raise ValueError("timestamp_ms must fit in 48 bits")

    if randomness is None:
        randomness = secrets.token_bytes(10)
    if not isinstance(randomness, bytes):
        raise TypeError("randomness must be bytes")
    if len(randomness) != 10:
        raise ValueError("randomness must contain exactly 10 bytes")

    value = (timestamp_ms << 80) | int.from_bytes(randomness, "big")
    encoded = ["0"] * 26
    for index in range(25, -1, -1):
        encoded[index] = _CROCKFORD_ALPHABET[value & 31]
        value >>= 5
    return "".join(encoded)


def ulid_timestamp_ms(value: str) -> int:
    """Extract the 48-bit millisecond timestamp from a canonical ULID."""

    if not isinstance(value, str) or _ULID_PATTERN.fullmatch(value) is None:
        raise ValueError("value is not a canonical ULID")
    timestamp = 0
    for character in value[:10]:
        timestamp = (timestamp << 5) | _CROCKFORD_VALUES[character]
    return timestamp


def utc_timestamp() -> str:
    """Return a canonical millisecond-precision ISO 8601 UTC timestamp."""

    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _validate_timestamp(value: str) -> str:
    if _TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise ValueError("timestamp must be canonical ISO 8601 UTC with milliseconds")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ValueError("timestamp is not a valid calendar time") from exc
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError("timestamp must be UTC")
    return value


def _validate_safe_path(value: str) -> str:
    if not value or "\0" in value or "\\" in value:
        raise ValueError("path must be a non-empty POSIX relative path")
    if PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute():
        raise ValueError("path must be relative")
    if PureWindowsPath(value).drive:
        raise ValueError("path must not contain a drive")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("path must be normalized and must not traverse parents")
    if PurePosixPath(value).as_posix() != value:
        raise ValueError("path must be normalized")
    return value


SafePath = Annotated[str, AfterValidator(_validate_safe_path)]


def _require_nonblank(value: str, *, name: str) -> str:
    if not value.strip():
        raise ValueError(f"{name} must not be blank")
    return value


def _require_unique(values: list[str], *, name: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{name} must not contain duplicates")
    return values


class StrictFactModel(BaseModel):
    """Shared strictness for facts and their nested durable values."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ArtifactOption(StrictFactModel):
    """One keyed observable behavior within a forced-choice artifact."""

    key: OptionKey
    body: str | None = None
    path: SafePath | None = None

    @field_validator("body")
    @classmethod
    def body_must_be_concrete(cls, value: str | None) -> str | None:
        if value is not None:
            return _require_nonblank(value, name="option body")
        return value

    @model_validator(mode="after")
    def body_or_path_is_required(self) -> ArtifactOption:
        if self.body is None and self.path is None:
            raise ValueError("artifact option requires body or path")
        return self


class Artifact(StrictFactModel):
    """A concrete artifact presented to the principal, optionally with choices."""

    type: Literal["transcript", "scenario", "diff", "rivals", "input"]
    body: str | None = None
    path: SafePath | None = None
    options: list[ArtifactOption] = Field(default_factory=list)

    @field_validator("body")
    @classmethod
    def body_must_be_concrete(cls, value: str | None) -> str | None:
        if value is not None:
            return _require_nonblank(value, name="artifact body")
        return value

    @model_validator(mode="after")
    def artifact_is_concrete(self) -> Artifact:
        if self.body is None and self.path is None and not self.options:
            raise ValueError("artifact requires body, path, or options")
        if self.options and len(self.options) < 2:
            raise ValueError("an option-bearing artifact requires at least two options")
        _require_unique([option.key for option in self.options], name="artifact option keys")
        return self


class FactBase(StrictFactModel):
    """Fields present on every line of the versioned ledger."""

    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    id: Ulid = Field(default_factory=new_ulid)
    ts: str = Field(default_factory=utc_timestamp)
    kind: str
    case_id: Ulid

    @field_validator("ts")
    @classmethod
    def timestamp_is_canonical(cls, value: str) -> str:
        return _validate_timestamp(value)


class IntentFact(FactBase):
    kind: Literal["intent"] = "intent"
    text: str
    source: Literal["user", "amendment"]
    supersedes: Ulid | None = None
    source_ruling_id: Ulid | None = None

    @field_validator("text")
    @classmethod
    def text_is_nonempty_but_verbatim(cls, value: str) -> str:
        return _require_nonblank(value, name="intent text")

    @model_validator(mode="after")
    def provenance_is_complete(self) -> IntentFact:
        if self.source == "user":
            if self.supersedes is not None or self.source_ruling_id is not None:
                raise ValueError("user intents cannot carry amendment provenance")
            if self.case_id != self.id:
                raise ValueError("root intent case_id must equal its id")
        elif self.supersedes is None or self.source_ruling_id is None:
            raise ValueError("amendment intents require supersedes and source_ruling_id")
        return self


class AttackFact(FactBase):
    kind: Literal["attack"] = "attack"
    klass: Literal["boundary", "consequence", "prototype", "conflict", "omission"]
    targets: list[Ulid] = Field(min_length=1)
    artifact: Artifact
    settles: list[str] = Field(min_length=1)
    silent_settles: list[str] = Field(default_factory=list)
    hate_scenario: str
    render_cost: Literal["trivial", "cheap", "expensive"]
    round: int = Field(ge=1, le=2)

    @field_validator("targets")
    @classmethod
    def targets_are_unique(cls, values: list[str]) -> list[str]:
        return _require_unique(values, name="targets")

    @field_validator("settles", "silent_settles")
    @classmethod
    def decisions_are_nonblank_and_unique(cls, values: list[str], info: object) -> list[str]:
        for value in values:
            _require_nonblank(value, name="decision")
        field_name = getattr(info, "field_name", "decisions")
        return _require_unique(values, name=field_name)

    @field_validator("hate_scenario")
    @classmethod
    def hate_scenario_is_concrete(cls, value: str) -> str:
        return _require_nonblank(value, name="hate_scenario")

    @model_validator(mode="after")
    def silent_decisions_are_settled(self) -> AttackFact:
        validate_consequence_artifact(
            klass=self.klass,
            artifact_type=self.artifact.type,
            body=self.artifact.body,
        )
        missing = set(self.silent_settles).difference(self.settles)
        if missing:
            raise ValueError("silent_settles must be a subset of settles")
        return self


class RulingFact(FactBase):
    kind: Literal["ruling"] = "ruling"
    attack_id: Ulid
    verdict: Literal["intended", "forbidden", "dont_care", "amend"]
    choice: OptionKey | None = None
    amendment_text: str | None = None
    supersedes: Ulid | None = None

    @field_validator("amendment_text")
    @classmethod
    def amendment_is_nonblank(cls, value: str | None) -> str | None:
        if value is not None:
            return _require_nonblank(value, name="amendment_text")
        return value

    @model_validator(mode="after")
    def conditional_fields_match_verdict(self) -> RulingFact:
        if self.verdict == "amend":
            if self.amendment_text is None:
                raise ValueError("amend verdict requires amendment_text")
            if self.choice is not None:
                raise ValueError("amend verdict cannot select an option")
        else:
            if self.amendment_text is not None:
                raise ValueError("amendment_text is only valid for amend verdicts")
            if self.verdict == "dont_care" and self.choice is not None:
                raise ValueError("dont_care cannot select an option")
        return self


class DerivationFact(FactBase):
    kind: Literal["derivation"] = "derivation"
    ledger_head: Ulid
    brief_path: SafePath
    brief_sha256: Sha256Digest
    test_stub_paths: list[SafePath] = Field(default_factory=list)
    test_stub_sha256: dict[SafePath, Sha256Digest]

    @field_validator("test_stub_paths")
    @classmethod
    def stub_paths_are_unique(cls, values: list[str]) -> list[str]:
        return _require_unique(values, name="test_stub_paths")

    @model_validator(mode="after")
    def commitments_have_exact_case_scoped_paths(self) -> DerivationFact:
        expected_brief = f"cases/{self.case_id}/derived/IMPLEMENTATION_BRIEF.md"
        if self.brief_path != expected_brief:
            raise ValueError(f"derivation brief_path must equal {expected_brief}")

        expected_parent = f"cases/{self.case_id}/derived/tests"
        for path in self.test_stub_paths:
            parsed = PurePosixPath(path)
            if parsed.parent.as_posix() != expected_parent:
                raise ValueError(
                    f"derivation test stub must be directly beneath {expected_parent}: {path}"
                )
            if re.fullmatch(r"test_[a-z0-9_]+\.py", parsed.name) is None:
                raise ValueError(f"derivation test stub has an invalid filename: {path}")

        paths = set(self.test_stub_paths)
        digested_paths = set(self.test_stub_sha256)
        if paths != digested_paths:
            missing = sorted(paths.difference(digested_paths))
            extra = sorted(digested_paths.difference(paths))
            raise ValueError(
                "derivation test stub paths and digest keys must match exactly; "
                f"missing={missing}, extra={extra}"
            )
        return self


class OutcomeFact(FactBase):
    kind: Literal["outcome"] = "outcome"
    otype: Literal["rework", "accepted", "abandoned"]
    trace: Literal["elicited", "missable", "novel", "n/a"]
    attack_id: Ulid | None = None
    notes: str

    @model_validator(mode="after")
    def trace_matches_outcome(self) -> OutcomeFact:
        if self.otype == "rework":
            if self.trace == "n/a":
                raise ValueError("rework requires an elicited, missable, or novel trace")
            if (self.trace == "elicited") != (self.attack_id is not None):
                raise ValueError("only elicited rework requires an attack_id")
        elif self.trace != "n/a" or self.attack_id is not None:
            raise ValueError("accepted and abandoned outcomes require trace n/a and no attack_id")
        return self


Fact = Annotated[
    IntentFact | AttackFact | RulingFact | DerivationFact | OutcomeFact,
    Field(discriminator="kind"),
]
_FACT_ADAPTER = TypeAdapter(Fact)


def parse_fact(value: str | bytes | Mapping[str, object]) -> Fact:
    """Validate one serialized or decoded fact using the discriminated union."""

    if isinstance(value, (str, bytes)):
        return _FACT_ADAPTER.validate_json(value)
    return _FACT_ADAPTER.validate_python(value)


__all__ = [
    "SCHEMA_VERSION",
    "Artifact",
    "ArtifactOption",
    "AttackFact",
    "DerivationFact",
    "Fact",
    "FactBase",
    "IntentFact",
    "OutcomeFact",
    "RulingFact",
    "SafePath",
    "Sha256Digest",
    "Ulid",
    "new_ulid",
    "parse_fact",
    "ulid_timestamp_ms",
    "utc_timestamp",
]
