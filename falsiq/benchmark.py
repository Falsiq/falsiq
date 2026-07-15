"""Versioned hidden-intent benchmark contracts and leakage checks."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

_TASK_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_REQUIREMENT_ID_PATTERN = re.compile(r"^LR[1-9][0-9]*$")
_CHOICE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def _nonblank(value: str, *, field: str) -> str:
    if not value.strip():
        raise ValueError(f"{field} must not be blank")
    return value


def _safe_relative_path(value: str) -> str:
    if not value or "\0" in value or "\\" in value:
        raise ValueError("repo_fixture must be a POSIX relative path")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if posix.is_absolute() or windows.is_absolute() or windows.drive:
        raise ValueError("repo_fixture must be relative")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("repo_fixture must be normalized without traversal")
    return value


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class TaskContext(ContractModel):
    repo_fixture: str
    notes: str = ""

    @field_validator("repo_fixture")
    @classmethod
    def fixture_is_safe(cls, value: str) -> str:
        return _safe_relative_path(value)


class LatentRequirement(ContractModel):
    id: str
    text: str
    discriminator: str
    severity: Literal["rework", "cosmetic"]

    @field_validator("id")
    @classmethod
    def id_is_stable(cls, value: str) -> str:
        if _REQUIREMENT_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("latent requirement ID must use LR<number>")
        return value

    @field_validator("text", "discriminator")
    @classmethod
    def hidden_text_is_concrete(cls, value: str, info: object) -> str:
        return _nonblank(value, field=getattr(info, "field_name", "hidden text"))


class TaskProvenance(ContractModel):
    source_urls: list[HttpUrl] = Field(min_length=1)
    source_revision: str
    license: str
    curator_notes: str

    @field_validator("source_revision", "license", "curator_notes")
    @classmethod
    def provenance_is_complete(cls, value: str, info: object) -> str:
        return _nonblank(value, field=getattr(info, "field_name", "provenance"))


class PublicTask(ContractModel):
    schema_version: Literal[1] = 1
    task_id: str
    stratum: Literal["synthetic", "mined", "control"]
    vague_prompt: str
    context: TaskContext
    annoyance_budget: int


class EvalTask(ContractModel):
    schema_version: Literal[1] = 1
    task_id: str
    stratum: Literal["synthetic", "mined", "control"]
    vague_prompt: str
    context: TaskContext
    latent_requirements: list[LatentRequirement]
    annoyance_budget: int = Field(ge=1, le=2)
    human_curated: bool
    provenance: TaskProvenance | None = None

    @field_validator("task_id")
    @classmethod
    def task_id_is_stable(cls, value: str) -> str:
        if _TASK_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("task_id must be a stable lowercase token")
        return value

    @field_validator("vague_prompt")
    @classmethod
    def prompt_is_nonblank(cls, value: str) -> str:
        return _nonblank(value, field="vague_prompt")

    @model_validator(mode="after")
    def task_contract_is_consistent(self) -> EvalTask:
        requirement_ids = [requirement.id for requirement in self.latent_requirements]
        if len(requirement_ids) != len(set(requirement_ids)):
            raise ValueError("latent requirement IDs must be unique")
        if self.stratum == "control" and len(self.latent_requirements) > 1:
            raise ValueError("control tasks may contain at most one latent requirement")
        if self.stratum == "mined" and self.provenance is None:
            raise ValueError("mined tasks require provenance")
        return self

    def public_projection(self) -> PublicTask:
        return PublicTask(
            task_id=self.task_id,
            stratum=self.stratum,
            vague_prompt=self.vague_prompt,
            context=self.context,
            annoyance_budget=self.annoyance_budget,
        )


class PrincipalRuling(ContractModel):
    request_id: str
    verdict: Literal["intended", "forbidden", "dont_care", "amend"]
    choice: str | None = None
    amendment_text: str | None = None
    implicated_requirement_ids: list[str] = Field(default_factory=list)

    @field_validator("request_id")
    @classmethod
    def request_id_is_nonblank(cls, value: str) -> str:
        return _nonblank(value, field="request_id")

    @field_validator("choice")
    @classmethod
    def choice_is_stable(cls, value: str | None) -> str | None:
        if value is not None and _CHOICE_PATTERN.fullmatch(value) is None:
            raise ValueError("choice must be a stable token")
        return value

    @field_validator("amendment_text")
    @classmethod
    def amendment_is_nonblank(cls, value: str | None) -> str | None:
        if value is not None:
            return _nonblank(value, field="amendment_text")
        return value

    @model_validator(mode="after")
    def forced_choice_contract(self) -> PrincipalRuling:
        if len(self.implicated_requirement_ids) != len(set(self.implicated_requirement_ids)):
            raise ValueError("implicated requirement IDs must be unique")
        if self.verdict in {"intended", "forbidden"}:
            if self.choice is None or self.amendment_text is not None:
                raise ValueError("intended and forbidden rulings require only a choice")
        elif self.verdict == "amend":
            if self.amendment_text is None or self.choice is not None:
                raise ValueError("amend rulings require only amendment_text")
        elif self.choice is not None or self.amendment_text is not None:
            raise ValueError("dont_care accepts neither choice nor amendment_text")
        return self


def load_task(path: Path) -> EvalTask:
    return EvalTask.model_validate_json(path.read_text(encoding="utf-8"))


def canonical_task_hash(task: EvalTask, *, salt: bytes) -> str:
    if not salt:
        raise ValueError("salt must not be empty")
    canonical = json.dumps(
        task.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(salt + b"\0" + canonical).hexdigest()


def _normalized_text(value: str) -> str:
    return " ".join(value.casefold().split())


def detect_principal_leaks(task: EvalTask, response: PrincipalRuling) -> tuple[str, ...]:
    """Detect verbatim hidden text from requirements not implicated by the attack."""

    known = {requirement.id for requirement in task.latent_requirements}
    implicated = set(response.implicated_requirement_ids)
    unknown = implicated.difference(known)
    if unknown:
        raise ValueError(f"unknown latent requirement: {sorted(unknown)[0]}")
    rendered = _normalized_text(response.model_dump_json())
    leaked: list[str] = []
    for requirement in task.latent_requirements:
        if requirement.id in implicated:
            continue
        protected = (
            _normalized_text(requirement.text),
            _normalized_text(requirement.discriminator),
        )
        if any(text and text in rendered for text in protected):
            leaked.append(requirement.id)
    return tuple(leaked)


__all__ = [
    "EvalTask",
    "LatentRequirement",
    "PrincipalRuling",
    "PublicTask",
    "TaskContext",
    "TaskProvenance",
    "canonical_task_hash",
    "detect_principal_leaks",
    "load_task",
]
