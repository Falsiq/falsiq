"""Transient attack selection and deterministic collision rendering.

Raw candidates and selector envelopes are deliberately not ledger facts.  Only the
selected candidates are materialized as :class:`AttackFact` values, and callers hand
that complete tuple to the ledger's atomic batch append operation.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from fractions import Fraction
from itertools import combinations
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import quote

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .facts import (
    SCHEMA_VERSION,
    Artifact,
    AttackFact,
    RulingFact,
    Ulid,
    new_ulid,
    utc_timestamp,
)

AttackClass = Literal["boundary", "consequence", "prototype", "conflict", "omission"]
RenderCost = Literal["trivial", "cheap", "expensive"]
CandidateDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

_COST_UNITS: dict[str, int] = {"trivial": 1, "cheap": 3, "expensive": 9}
_MAX_CANDIDATES = 20
_MAX_SELECTED = 3


def _nonblank(value: str, *, field_name: str) -> str:
    if not value.strip():
        raise ValueError(f"{field_name} must not be blank")
    return value


def _unique(values: list[str], *, field_name: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} must not contain duplicates")
    return values


class StrictTransientModel(BaseModel):
    """Strict values exchanged between agents but never appended to the ledger."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class AttackCandidate(StrictTransientModel):
    """One disposable attack proposal before selector policy is applied."""

    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    klass: AttackClass
    targets: list[Ulid] = Field(min_length=1)
    artifact: Artifact
    settles: list[str] = Field(min_length=1)
    silent_settles: list[str] = Field(default_factory=list)
    hate_scenario: str
    render_cost: RenderCost

    @field_validator("targets")
    @classmethod
    def targets_are_unique(cls, values: list[str]) -> list[str]:
        return _unique(values, field_name="targets")

    @field_validator("settles", "silent_settles")
    @classmethod
    def decisions_are_concrete(cls, values: list[str], info: object) -> list[str]:
        field_name = getattr(info, "field_name", "decisions")
        for value in values:
            _nonblank(value, field_name="decision")
        return _unique(values, field_name=field_name)

    @field_validator("hate_scenario")
    @classmethod
    def hate_scenario_is_concrete(cls, value: str) -> str:
        return _nonblank(value, field_name="hate_scenario")

    @model_validator(mode="after")
    def silent_decisions_are_also_settled(self) -> AttackCandidate:
        if set(self.silent_settles).difference(self.settles):
            raise ValueError("silent_settles must be a subset of settles")
        return self


def _candidate_artifact_paths(candidate: AttackCandidate) -> tuple[str, ...]:
    paths: list[str] = []
    if candidate.artifact.path is not None:
        paths.append(candidate.artifact.path)
    paths.extend(
        option.path for option in candidate.artifact.options if option.path is not None
    )
    return tuple(paths)


def _validate_case_paths(case_id: str, candidates: Sequence[AttackCandidate]) -> None:
    prefix = f"cases/{case_id}/"
    for candidate in candidates:
        for path in _candidate_artifact_paths(candidate):
            if not path.startswith(prefix):
                raise ValueError(f"case artifact path must be beneath {prefix}: {path}")


class AttackCandidateBatch(StrictTransientModel):
    """The bounded output contract for one class-specific attacker agent."""

    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    case_id: Ulid
    attacker: AttackClass
    candidates: list[AttackCandidate] = Field(default_factory=list, max_length=4)

    @model_validator(mode="after")
    def one_attacker_emits_one_class(self) -> AttackCandidateBatch:
        if any(candidate.klass != self.attacker for candidate in self.candidates):
            raise ValueError("an attacker must emit only its own class")
        _validate_case_paths(self.case_id, self.candidates)
        return self


def _canonical_candidate_bytes(candidate: AttackCandidate) -> bytes:
    payload = candidate.model_dump(mode="json")
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def candidate_digest(candidate: AttackCandidate) -> str:
    """Return the candidate's canonical SHA-256 content identity."""

    return hashlib.sha256(_canonical_candidate_bytes(candidate)).hexdigest()


def candidate_score(candidate: AttackCandidate) -> Fraction:
    """Compute exact constraint/cost score with silent decisions weighted twice."""

    constraint = len(candidate.settles) + len(candidate.silent_settles)
    return Fraction(constraint, _COST_UNITS[candidate.render_cost])


class CandidateRecord(StrictTransientModel):
    """A normalized candidate carrying the digest a selector copies by reference."""

    digest: CandidateDigest
    candidate: AttackCandidate

    @model_validator(mode="after")
    def digest_matches_content(self) -> CandidateRecord:
        if self.digest != candidate_digest(self.candidate):
            raise ValueError("candidate digest does not match canonical content")
        return self


def _composition_is_valid(records: Sequence[CandidateRecord]) -> bool:
    if len(records) > _MAX_SELECTED:
        return False
    classes = [record.candidate.klass for record in records]
    if len(records) > 1 and len(set(classes)) < 2:
        return False
    if classes.count("prototype") > 1:
        return False
    return classes.count("omission") <= 2


def _ranked(records: Sequence[CandidateRecord]) -> list[CandidateRecord]:
    return sorted(records, key=lambda record: (-candidate_score(record.candidate), record.digest))


def _select_records(records: Sequence[CandidateRecord]) -> list[CandidateRecord]:
    """Choose the largest valid top-three set, maximizing exact total score."""

    maximum = min(_MAX_SELECTED, len(records))
    for size in range(maximum, 0, -1):
        valid = [
            selection
            for selection in combinations(records, size)
            if _composition_is_valid(selection)
        ]
        if not valid:
            continue
        best_score = max(
            sum((candidate_score(record.candidate) for record in selection), Fraction())
            for selection in valid
        )
        best = [
            selection
            for selection in valid
            if sum(
                (candidate_score(record.candidate) for record in selection), Fraction()
            )
            == best_score
        ]
        chosen = min(
            best,
            key=lambda selection: tuple(sorted(record.digest for record in selection)),
        )
        return _ranked(chosen)
    return []


class SelectionEnvelope(StrictTransientModel):
    """One selector-approved round, including disposable candidates and selected refs."""

    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    case_id: Ulid
    round: int = Field(ge=1, le=2)
    candidates: list[CandidateRecord] = Field(default_factory=list, max_length=_MAX_CANDIDATES)
    selected: list[CandidateDigest] = Field(default_factory=list, max_length=_MAX_SELECTED)

    @model_validator(mode="after")
    def selection_is_canonical_and_policy_compliant(self) -> SelectionEnvelope:
        _validate_case_paths(
            self.case_id,
            [record.candidate for record in self.candidates],
        )
        digests = [record.digest for record in self.candidates]
        if len(digests) != len(set(digests)):
            raise ValueError("duplicate candidate content is not allowed")
        if len(self.selected) != len(set(self.selected)):
            raise ValueError("selected candidate digests must be unique")
        if set(self.selected).difference(digests):
            raise ValueError("selected digest is not present in candidates")
        expected = [record.digest for record in _select_records(self.candidates)]
        if self.selected != expected:
            raise ValueError("selected digests do not match deterministic selection policy")
        return self

    @property
    def selected_records(self) -> tuple[CandidateRecord, ...]:
        by_digest = {record.digest: record for record in self.candidates}
        return tuple(by_digest[digest] for digest in self.selected)


def build_selection_envelope(
    case_id: str,
    round_number: int,
    candidates: Sequence[AttackCandidate],
) -> SelectionEnvelope:
    """Normalize candidate output and derive the only policy-valid selection."""

    records = [
        CandidateRecord(digest=candidate_digest(candidate), candidate=candidate)
        for candidate in candidates
    ]
    records.sort(key=lambda record: record.digest)
    selected = [record.digest for record in _select_records(records)]
    return SelectionEnvelope(
        case_id=case_id,
        round=round_number,
        candidates=records,
        selected=selected,
    )


def selection_rationale(envelope: SelectionEnvelope) -> tuple[str, ...]:
    """Derive auditable rationale without accepting or persisting agent prose."""

    return tuple(
        (
            f"{record.digest}: {record.candidate.klass}; "
            f"score={candidate_score(record.candidate)}; "
            f"settles={len(record.candidate.settles)}; "
            f"silent={len(record.candidate.silent_settles)}; "
            f"cost={_COST_UNITS[record.candidate.render_cost]}"
        )
        for record in envelope.selected_records
    )


class RoundGateError(ValueError):
    """A selector envelope violates the per-case two-round annoyance budget."""


def validate_round_gate(
    round_number: int,
    *,
    existing_attacks: Sequence[AttackFact],
    active_rulings: Mapping[str, RulingFact],
    case_id: str | None = None,
) -> None:
    """Validate one-batch-per-round and the evidence-based round-two gate."""

    cases = {attack.case_id for attack in existing_attacks}
    if len(cases) > 1 or (case_id is not None and cases.difference({case_id})):
        raise RoundGateError("round gate context must contain attacks from one case")
    if round_number not in {1, 2}:
        raise RoundGateError("attack rounds are capped at 2")
    if any(attack.round == round_number for attack in existing_attacks):
        raise RoundGateError(f"attack round {round_number} already exists")
    if round_number == 1:
        if existing_attacks:
            raise RoundGateError("round 1 must be the first attack batch")
        return

    round_one = [attack for attack in existing_attacks if attack.round == 1]
    if not round_one:
        raise RoundGateError("round 2 requires round 1 attacks")
    open_ids = [attack.id for attack in round_one if attack.id not in active_rulings]
    if open_ids:
        raise RoundGateError("round 1 is still open")
    for attack in round_one:
        ruling = active_rulings[attack.id]
        if ruling.attack_id != attack.id or ruling.case_id != attack.case_id:
            raise RoundGateError("active ruling does not match its round 1 attack")
    if not any(
        active_rulings[attack.id].verdict in {"amend", "forbidden"} for attack in round_one
    ):
        raise RoundGateError("round 2 requires an amend or forbidden round 1 ruling")


def _materialize_selected(
    envelope: SelectionEnvelope,
    *,
    id_factory: Callable[[], str],
    timestamp_factory: Callable[[], str],
) -> tuple[AttackFact, ...]:
    facts = tuple(
        AttackFact(
            id=id_factory(),
            ts=timestamp_factory(),
            case_id=envelope.case_id,
            round=envelope.round,
            **record.candidate.model_dump(mode="python"),
        )
        for record in envelope.selected_records
    )
    if len({fact.id for fact in facts}) != len(facts):
        raise ValueError("id_factory returned duplicate attack ids")
    return facts


def append_attack_round(
    envelope: SelectionEnvelope,
    *,
    existing_attacks: Sequence[AttackFact],
    active_rulings: Mapping[str, RulingFact],
    append_batch: Callable[[tuple[AttackFact, ...]], object],
    id_factory: Callable[[], str] = new_ulid,
    timestamp_factory: Callable[[], str] = utc_timestamp,
) -> tuple[AttackFact, ...]:
    """Materialize selected attacks and submit them in one atomic ledger call."""

    validate_round_gate(
        envelope.round,
        existing_attacks=existing_attacks,
        active_rulings=active_rulings,
        case_id=envelope.case_id,
    )
    facts = _materialize_selected(
        envelope,
        id_factory=id_factory,
        timestamp_factory=timestamp_factory,
    )
    if facts:
        append_batch(facts)
    return facts


def _escape_inline(value: str) -> str:
    return html.escape(value, quote=True).replace("\n", "&#10;")


def _render_body(value: str) -> list[str]:
    escaped = html.escape(value, quote=True).replace("#", "&#x23;")
    return ["<pre>", escaped, "</pre>"]


def _artifact_link(path: str, *, label: str) -> str:
    relative_url = quote(f"../../../{path}", safe="/._~-")
    return f"[{label}]({relative_url}) — <code>{_escape_inline(path)}</code>"


def _rule_commands(attack: AttackFact) -> list[str]:
    commands: list[str] = []
    if attack.artifact.options:
        for option in attack.artifact.options:
            commands.append(f"falsiq rule {attack.id} intended --choice {option.key}")
        for option in attack.artifact.options:
            commands.append(f"falsiq rule {attack.id} forbidden --choice {option.key}")
    else:
        commands.extend(
            [
                f"falsiq rule {attack.id} intended",
                f"falsiq rule {attack.id} forbidden",
            ]
        )
    commands.append(f"falsiq rule {attack.id} dont_care")
    amend = f'falsiq rule {attack.id} amend --text "<replacement intent>"'
    if len(attack.targets) > 1:
        amend += " --intent <active-target-id>"
    commands.append(amend)
    return commands


_ARTIFACT_TITLES = {
    "transcript": "Transcript",
    "scenario": "Scenario",
    "diff": "Observable diff",
    "rivals": "Rival behaviors",
    "input": "Input",
}


def render_collision_markdown(case_id: str, attacks: Sequence[AttackFact]) -> str:
    """Render one case round in a stable, injection-resistant Markdown format."""

    if not attacks:
        raise ValueError("collision rendering requires at least one attack")
    if any(attack.case_id != case_id for attack in attacks):
        raise ValueError("all attacks must belong to the requested case")
    rounds = {attack.round for attack in attacks}
    if len(rounds) != 1:
        raise ValueError("a collision file contains exactly one round")
    ids = [attack.id for attack in attacks]
    if len(ids) != len(set(ids)):
        raise ValueError("collision batch contains a duplicate attack")

    ordered = sorted(attacks, key=lambda attack: attack.id)
    round_number = next(iter(rounds))
    lines = [
        "# Falsiq collision",
        "",
        f"- Case: <code>{case_id}</code>",
        f"- Round: {round_number}",
        f"- Attacks: {len(ordered)}",
        "",
        "Rule every attack with exactly one command shown below.",
        "",
    ]
    for position, attack in enumerate(ordered, start=1):
        target_lines: list[str] = []
        if len(attack.targets) > 1:
            target_lines = [
                "**Amendment targets**",
                "",
                *[f"- <code>{target}</code>" for target in attack.targets],
                "",
            ]
        lines.extend(
            [
                f"## A{position} [{attack.klass}]",
                "",
                *target_lines,
                "**Settles**",
                "",
                *[f"- <code>{_escape_inline(decision)}</code>" for decision in attack.settles],
                "",
                f"### {_ARTIFACT_TITLES[attack.artifact.type]}",
                "",
            ]
        )
        if attack.artifact.body is not None:
            lines.extend([*_render_body(attack.artifact.body), ""])
        if attack.artifact.path is not None:
            lines.extend([_artifact_link(attack.artifact.path, label="Open artifact"), ""])
        if attack.artifact.options:
            lines.extend(["### Forced choices", ""])
            for option in attack.artifact.options:
                lines.extend([f"#### Choice {_escape_inline(option.key)}", ""])
                if option.body is not None:
                    lines.extend([*_render_body(option.body), ""])
                if option.path is not None:
                    lines.extend([_artifact_link(option.path, label="Open choice artifact"), ""])
        lines.extend(
            [
                "### Hate scenario",
                "",
                *_render_body(attack.hate_scenario),
                "",
                "### Legal rulings",
                "",
                "```console",
                *_rule_commands(attack),
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def collision_file_path(repo_root: Path, case_id: str, round_number: int) -> Path:
    """Return the canonical case-scoped collision file path."""

    return repo_root / ".falsiq" / "cases" / case_id / "collisions" / f"{round_number}.md"


def _prepare_collision_directory(repo_root: Path, case_id: str) -> Path:
    root = repo_root.resolve()
    components = [
        root / ".falsiq",
        root / ".falsiq" / "cases",
        root / ".falsiq" / "cases" / case_id,
        root / ".falsiq" / "cases" / case_id / "collisions",
    ]
    for component in components:
        if component.is_symlink():
            raise OSError(f"collision directory must not be a symlink: {component}")
        component.mkdir(exist_ok=True)
        if not component.is_dir():
            raise OSError(f"collision path is not a directory: {component}")
    return components[-1]


def write_collision_file(
    repo_root: Path,
    case_id: str,
    attacks: Sequence[AttackFact],
) -> Path:
    """Atomically publish a deterministic collision file beneath its case directory."""

    rendered = render_collision_markdown(case_id, attacks)
    round_number = attacks[0].round
    collision_directory = _prepare_collision_directory(repo_root, case_id)
    destination = collision_directory / f"{round_number}.md"
    temporary_path: str | None = None
    try:
        descriptor, temporary_path = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            Path(temporary_path).unlink(missing_ok=True)
    return destination


__all__ = [
    "AttackCandidate",
    "AttackCandidateBatch",
    "CandidateRecord",
    "RoundGateError",
    "SelectionEnvelope",
    "append_attack_round",
    "build_selection_envelope",
    "candidate_digest",
    "candidate_score",
    "collision_file_path",
    "render_collision_markdown",
    "selection_rationale",
    "validate_round_gate",
    "write_collision_file",
]
