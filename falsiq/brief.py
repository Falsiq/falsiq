"""Deterministic machine-consumable obligation bundles."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .derive import DeriverResponse, deriver_prompt_hash, validate_deriver_response
from .facts import AttackFact, Fact, IntentFact, ReviewRoundFact, RulingFact

CONTRACT_VERSION = "1.0.0"


class BriefModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class IntentContract(BriefModel):
    text: str
    amended_from: str | None


class EvidenceContract(BriefModel):
    attack_id: str
    ruling_id: str
    klass: Literal["boundary", "consequence", "prototype", "conflict", "omission"]
    choice: str | None
    artifact_excerpt: str
    hate_scenario: str


class VerificationContract(BriefModel):
    expressible: bool
    renderer: Literal["pytest", "command", "assertion", "checklist"] | None = None
    strength: Literal["executable", "attested"] | None = None
    artifact_path: str | None = None
    reason: str | None = None


class ObligationContract(BriefModel):
    obligation_id: str
    kind: Literal["required", "forbidden"]
    statement: str
    settles: list[str] = Field(min_length=1)
    evidence: EvidenceContract
    verification: VerificationContract


class DiscretionEvidence(BriefModel):
    attack_id: str
    ruling_id: str


class DiscretionContract(BriefModel):
    decision: str
    evidence: DiscretionEvidence


class OpenAmbiguityContract(BriefModel):
    decision: str
    reason: str


class ProvenanceContract(BriefModel):
    attacker_versions: dict[str, str]
    deriver_version: str
    policy: dict[str, int]
    profile: dict[str, str] | None = None


class BriefContract(BriefModel):
    contract_version: Literal[CONTRACT_VERSION] = CONTRACT_VERSION
    case_id: str
    ledger_head: str
    intent: IntentContract
    obligations: list[ObligationContract]
    discretion: list[DiscretionContract]
    open_ambiguities: list[OpenAmbiguityContract]
    provenance: ProvenanceContract


def _active_intent(facts: Sequence[Fact], case_id: str) -> IntentFact:
    superseded = {
        fact.supersedes
        for fact in facts
        if isinstance(fact, IntentFact) and fact.case_id == case_id and fact.supersedes is not None
    }
    active = [
        fact
        for fact in facts
        if isinstance(fact, IntentFact) and fact.case_id == case_id and fact.id not in superseded
    ]
    if len(active) != 1:
        raise ValueError(f"case {case_id} must have exactly one active intent")
    return active[0]


def _active_rulings(facts: Sequence[Fact], case_id: str) -> dict[str, RulingFact]:
    active: dict[str, RulingFact] = {}
    for fact in facts:
        if isinstance(fact, RulingFact) and fact.case_id == case_id:
            active[fact.attack_id] = fact
    return active


def _artifact_excerpt(attack: AttackFact, ruling: RulingFact) -> str:
    if ruling.choice is not None:
        option = next(
            (option for option in attack.artifact.options if option.key == ruling.choice),
            None,
        )
        if option is not None:
            value = option.body if option.body is not None else option.path
            if value is not None:
                return value[:500]
    value = attack.artifact.body if attack.artifact.body is not None else attack.artifact.path
    return (value or ", ".join(attack.settles))[:500]


def _statement(attack: AttackFact, ruling: RulingFact) -> str:
    excerpt = _artifact_excerpt(attack, ruling)
    prefix = "Require" if ruling.verdict == "intended" else "Forbid"
    return f"{prefix}: {excerpt}"


def _verification(
    response: DeriverResponse,
    ruling: RulingFact,
    *,
    case_id: str,
) -> VerificationContract:
    by_ruling = {item.ruling_id: item for item in response.forbidden_tests}
    item = by_ruling.get(ruling.id)
    if item is None:
        return VerificationContract(
            expressible=False,
            reason="No deterministic verification artifact was derived.",
        )
    if item.content is None or item.filename is None:
        return VerificationContract(
            expressible=False,
            reason=item.unexpressible_reason or "Not expressible.",
        )
    return VerificationContract(
        expressible=True,
        renderer="pytest",
        strength="executable",
        artifact_path=f"cases/{case_id}/derived/tests/{item.filename}",
    )


def render_brief_contract(
    facts: Sequence[Fact],
    response: DeriverResponse,
) -> BriefContract:
    request = validate_deriver_response(facts, response.case_id, response)
    intent = _active_intent(facts, response.case_id)
    active_rulings = _active_rulings(facts, response.case_id)
    attacks = [
        fact
        for fact in facts
        if isinstance(fact, AttackFact)
        and fact.case_id == response.case_id
        and fact.id in active_rulings
    ]

    obligations: list[ObligationContract] = []
    discretion: list[DiscretionContract] = []
    for attack in attacks:
        ruling = active_rulings[attack.id]
        if ruling.verdict in {"intended", "forbidden"}:
            obligations.append(
                ObligationContract(
                    obligation_id=ruling.id,
                    kind="required" if ruling.verdict == "intended" else "forbidden",
                    statement=_statement(attack, ruling),
                    settles=list(attack.settles),
                    evidence=EvidenceContract(
                        attack_id=attack.id,
                        ruling_id=ruling.id,
                        klass=attack.klass,
                        choice=ruling.choice,
                        artifact_excerpt=_artifact_excerpt(attack, ruling),
                        hate_scenario=attack.hate_scenario,
                    ),
                    verification=_verification(
                        response,
                        ruling,
                        case_id=response.case_id,
                    ),
                )
            )
        elif ruling.verdict == "dont_care":
            discretion.extend(
                DiscretionContract(
                    decision=decision,
                    evidence=DiscretionEvidence(
                        attack_id=attack.id,
                        ruling_id=ruling.id,
                    ),
                )
                for decision in attack.settles
            )

    rounds = [
        fact
        for fact in facts
        if isinstance(fact, ReviewRoundFact) and fact.case_id == response.case_id
    ]
    prompt_versions: dict[str, str] = {}
    ambiguities: list[OpenAmbiguityContract] = []
    profile: dict[str, str] | None = None
    max_rounds = max((round_fact.max_rounds for round_fact in rounds), default=2)
    for round_fact in rounds:
        prompt_versions.update(round_fact.prompt_versions)
        ambiguities.extend(
            OpenAmbiguityContract(
                decision=item.decision,
                reason=item.reason,
            )
            for item in round_fact.open_ambiguities
        )
        profile = {
            "name": round_fact.profile_name,
            "digest": round_fact.profile_digest,
        }
    for attack in attacks:
        if attack.attacker_version is not None:
            prompt_versions.setdefault(attack.klass, attack.attacker_version)

    return BriefContract(
        case_id=response.case_id,
        ledger_head=request.ledger_head,
        intent=IntentContract(
            text=intent.text,
            amended_from=intent.supersedes,
        ),
        obligations=obligations,
        discretion=discretion,
        open_ambiguities=ambiguities,
        provenance=ProvenanceContract(
            attacker_versions=dict(sorted(prompt_versions.items())),
            deriver_version=deriver_prompt_hash(),
            policy={"max_rounds": max_rounds},
            profile=profile,
        ),
    )


def canonical_brief_json(value: BriefContract | Mapping[str, object]) -> str:
    payload = value.model_dump(mode="json") if isinstance(value, BriefContract) else dict(value)
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


__all__ = [
    "CONTRACT_VERSION",
    "BriefContract",
    "canonical_brief_json",
    "render_brief_contract",
]
