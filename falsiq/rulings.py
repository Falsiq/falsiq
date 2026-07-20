"""Deterministic construction of ruling, amendment, and outcome facts."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from .facts import (
    AttackFact,
    Fact,
    IntentFact,
    OutcomeFact,
    RulingFact,
    new_ulid,
    utc_timestamp,
)


class RulingCommandError(ValueError):
    """User input cannot be applied to the observed ledger state."""


def _attack_by_id(facts: Sequence[Fact], attack_id: str) -> AttackFact:
    for fact in facts:
        if isinstance(fact, AttackFact) and fact.id == attack_id:
            return fact
    raise RulingCommandError(f"unknown review: {attack_id}")


def _active_intent_ids(facts: Sequence[Fact], case_id: str) -> set[str]:
    superseded = {
        fact.supersedes
        for fact in facts
        if isinstance(fact, IntentFact) and fact.case_id == case_id and fact.supersedes is not None
    }
    return {
        fact.id
        for fact in facts
        if isinstance(fact, IntentFact) and fact.case_id == case_id and fact.id not in superseded
    }


def build_ruling_batch(
    facts: Sequence[Fact],
    *,
    attack_id: str,
    verdict: str,
    choice: str | None,
    amendment_text: str | None,
    intent_id: str | None,
    id_factory: Callable[[], str] = new_ulid,
    timestamp_factory: Callable[[], str] = utc_timestamp,
) -> tuple[RulingFact | IntentFact, ...]:
    """Build one ruling and, for amend, its linked verbatim intent fact."""

    attack = _attack_by_id(facts, attack_id)
    if intent_id is not None and verdict != "amend":
        raise RulingCommandError("--intent is only valid for an amend ruling")

    active_ruling = next(
        (
            fact
            for fact in reversed(facts)
            if isinstance(fact, RulingFact) and fact.attack_id == attack.id
        ),
        None,
    )
    ruling = RulingFact(
        id=id_factory(),
        ts=timestamp_factory(),
        case_id=attack.case_id,
        attack_id=attack.id,
        verdict=verdict,
        choice=choice,
        amendment_text=amendment_text,
        supersedes=active_ruling.id if active_ruling is not None else None,
    )
    if verdict != "amend":
        return (ruling,)

    if len(attack.targets) > 1 and intent_id is None:
        raise RulingCommandError("multi-target amendment requires --intent")
    active_targets = _active_intent_ids(facts, attack.case_id).intersection(attack.targets)
    selected_intent = intent_id
    if selected_intent is None:
        if len(active_targets) != 1:
            raise RulingCommandError("amendment requires exactly one active review target")
        selected_intent = next(iter(active_targets))
    if selected_intent not in active_targets:
        raise RulingCommandError(
            f"--intent must name an active review target; received {selected_intent}"
        )

    amended = IntentFact(
        id=id_factory(),
        ts=timestamp_factory(),
        case_id=attack.case_id,
        text=ruling.amendment_text,
        source="amendment",
        supersedes=selected_intent,
        source_ruling_id=ruling.id,
    )
    return (ruling, amended)


def build_outcome(
    facts: Sequence[Fact],
    *,
    case_id: str,
    otype: str,
    trace: str,
    attack_id: str | None,
    notes: str,
    id_factory: Callable[[], str] = new_ulid,
    timestamp_factory: Callable[[], str] = utc_timestamp,
) -> OutcomeFact:
    """Build one outcome after checking its case and optional review reference."""

    case_exists = any(
        isinstance(fact, IntentFact) and fact.source == "user" and fact.id == case_id
        for fact in facts
    )
    if not case_exists:
        raise RulingCommandError(f"unknown case: {case_id}")
    if attack_id is not None:
        attack = _attack_by_id(facts, attack_id)
        if attack.case_id != case_id:
            raise RulingCommandError("outcome review must belong to the same case")
    return OutcomeFact(
        id=id_factory(),
        ts=timestamp_factory(),
        case_id=case_id,
        otype=otype,
        trace=trace,
        attack_id=attack_id,
        notes=notes,
    )


__all__ = ["RulingCommandError", "build_outcome", "build_ruling_batch"]
