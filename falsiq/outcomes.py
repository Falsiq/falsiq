"""Deterministic attribution reports over durable Falsiq outcomes."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Sequence

from .facts import (
    AttackFact,
    Fact,
    IntentFact,
    OutcomeFact,
    ReviewRoundFact,
    RulingFact,
)


def build_outcomes_report(
    facts: Sequence[Fact],
    *,
    since: str | None = None,
) -> dict[str, object]:
    def included_outcome(fact: Fact) -> bool:
        return isinstance(fact, OutcomeFact) and (since is None or fact.ts >= since)

    attacks = {fact.id: fact for fact in facts if isinstance(fact, AttackFact)}
    active_rulings: dict[str, RulingFact] = {}
    for fact in facts:
        if isinstance(fact, RulingFact):
            active_rulings[fact.attack_id] = fact

    by_class: dict[str, dict[str, object]] = {}
    for klass in ("boundary", "consequence", "prototype", "conflict", "omission"):
        class_attacks = [attack for attack in attacks.values() if attack.klass == klass]
        rulings = [
            active_rulings[attack.id] for attack in class_attacks if attack.id in active_rulings
        ]
        elicited = sum(
            included_outcome(fact)
            and isinstance(fact, OutcomeFact)
            and fact.trace == "elicited"
            and fact.attack_id in {attack.id for attack in class_attacks}
            for fact in facts
        )
        missable = sum(
            included_outcome(fact)
            and isinstance(fact, OutcomeFact)
            and fact.trace == "missable"
            and fact.missable_class == klass
            for fact in facts
        )
        by_class[klass] = {
            "attacks_fired": len(class_attacks),
            "ruling_verdicts": dict(sorted(Counter(item.verdict for item in rulings).items())),
            "obligations_produced": sum(
                item.verdict in {"intended", "forbidden"} for item in rulings
            ),
            "reworks_elicited": elicited,
            "reworks_missable": missable,
            "waste_rate": (
                sum(item.verdict == "dont_care" for item in rulings) / len(rulings)
                if rulings
                else 0.0
            ),
        }

    cases: dict[str, dict[str, object]] = {}
    case_ids = sorted(
        {fact.case_id for fact in facts if isinstance(fact, IntentFact) and fact.source == "user"}
    )
    for case_id in case_ids:
        case_attacks = [attack for attack in attacks.values() if attack.case_id == case_id]
        rulings = [
            active_rulings[attack.id] for attack in case_attacks if attack.id in active_rulings
        ]
        outcomes = [
            fact.otype
            for fact in facts
            if included_outcome(fact) and isinstance(fact, OutcomeFact) and fact.case_id == case_id
        ]
        round_facts = [
            fact for fact in facts if isinstance(fact, ReviewRoundFact) and fact.case_id == case_id
        ]
        cases[case_id] = {
            "rounds_used": sorted(
                {attack.round for attack in case_attacks}
                | {round_fact.round for round_fact in round_facts}
            ),
            "obligations": sum(item.verdict in {"intended", "forbidden"} for item in rulings),
            "discretion": sum(item.verdict == "dont_care" for item in rulings),
            "open_ambiguities": [
                ambiguity.model_dump(mode="json")
                for round_fact in round_facts
                for ambiguity in round_fact.open_ambiguities
            ],
            "outcomes": outcomes,
        }

    prompt_stats: dict[str, Counter[str]] = defaultdict(Counter)
    for attack in attacks.values():
        if attack.attacker_version is not None:
            prompt_stats[attack.attacker_version]["attacks_fired"] += 1
            ruling = active_rulings.get(attack.id)
            if ruling is not None:
                prompt_stats[attack.attacker_version][f"verdict_{ruling.verdict}"] += 1
    for fact in facts:
        if (
            included_outcome(fact)
            and isinstance(fact, OutcomeFact)
            and fact.trace == "missable"
            and fact.prompt_version is not None
        ):
            prompt_stats[fact.prompt_version]["reworks_missable"] += 1

    return {
        "schema_version": 1,
        "by_class": by_class,
        "cases": cases,
        "prompt_versions": {
            digest: dict(sorted(counts.items())) for digest, counts in sorted(prompt_stats.items())
        },
    }


__all__ = ["build_outcomes_report"]
