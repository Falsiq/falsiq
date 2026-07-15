"""Pure evaluation metrics for Falsiq benchmark runs."""

from __future__ import annotations

import random
from dataclasses import dataclass
from statistics import fmean
from typing import Literal

Severity = Literal["rework", "cosmetic"]
Verdict = Literal["intended", "forbidden", "dont_care", "amend"]

_SEVERITY_WEIGHTS: dict[Severity, int] = {"rework": 3, "cosmetic": 1}


@dataclass(frozen=True, slots=True)
class LatentRequirement:
    id: str
    severity: Severity

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("latent requirement ID must not be empty")
        if self.severity not in _SEVERITY_WEIGHTS:
            raise ValueError(f"unknown severity: {self.severity}")


@dataclass(frozen=True, slots=True)
class AttackEvaluation:
    attack_id: str
    round: int
    requirement_ids: frozenset[str] = frozenset()
    amended: bool = False
    verdict: Verdict | None = None

    def __post_init__(self) -> None:
        if not self.attack_id:
            raise ValueError("attack ID must not be empty")
        if self.round < 1:
            raise ValueError("round must be at least 1")


@dataclass(frozen=True, slots=True)
class RequirementScore:
    requirement_id: str
    score: float

    def __post_init__(self) -> None:
        if not self.requirement_id:
            raise ValueError("requirement ID must not be empty")
        if self.score not in {0.0, 0.5, 1.0}:
            raise ValueError("requirement score must be 0, 0.5, or 1")


@dataclass(frozen=True, slots=True)
class BootstrapInterval:
    mean_delta: float
    low: float
    high: float
    confidence: float
    samples: int
    seed: int


def _requirement_weights(requirements: tuple[LatentRequirement, ...]) -> dict[str, int]:
    weights: dict[str, int] = {}
    for requirement in requirements:
        if requirement.id in weights:
            raise ValueError(f"duplicate latent requirement: {requirement.id}")
        weights[requirement.id] = _SEVERITY_WEIGHTS[requirement.severity]
    return weights


def severity_weighted_recall(
    requirements: tuple[LatentRequirement, ...],
    attacks: tuple[AttackEvaluation, ...],
    *,
    through_round: int,
) -> float | None:
    """Return cumulative severity-weighted recall through a round."""

    if through_round < 1:
        raise ValueError("through_round must be at least 1")
    weights = _requirement_weights(requirements)
    for attack in attacks:
        unknown = attack.requirement_ids.difference(weights)
        if unknown:
            raise ValueError(f"unknown latent requirement mapping: {sorted(unknown)[0]}")
    denominator = sum(weights.values())
    if denominator == 0:
        return None
    elicited = {
        requirement_id
        for attack in attacks
        if attack.round <= through_round
        for requirement_id in attack.requirement_ids
    }
    return sum(weights[requirement_id] for requirement_id in elicited) / denominator


def waste_rate(attacks: tuple[AttackEvaluation, ...]) -> float:
    """Return the fraction of attacks that mapped to no LR and caused no amendment."""

    if not attacks:
        return 0.0
    wasted = sum(not attack.requirement_ids and not attack.amended for attack in attacks)
    return wasted / len(attacks)


def licensed_discretion_rate(attacks: tuple[AttackEvaluation, ...]) -> float:
    if not attacks:
        return 0.0
    return sum(attack.verdict == "dont_care" for attack in attacks) / len(attacks)


def interaction_cost(attacks: tuple[AttackEvaluation, ...]) -> int:
    return len(attacks)


def weighted_conformance(
    requirements: tuple[LatentRequirement, ...],
    scores: tuple[RequirementScore, ...],
) -> float | None:
    """Return severity-weighted implementation conformance on a 0-100 scale."""

    weights = _requirement_weights(requirements)
    denominator = sum(weights.values())
    if denominator == 0:
        return None
    by_id: dict[str, float] = {}
    for result in scores:
        if result.requirement_id in by_id:
            raise ValueError(f"duplicate requirement score: {result.requirement_id}")
        if result.requirement_id not in weights:
            raise ValueError(f"unknown latent requirement score: {result.requirement_id}")
        by_id[result.requirement_id] = result.score
    weighted = sum(
        weights[requirement_id] * by_id.get(requirement_id, 0.0)
        for requirement_id in weights
    )
    return 100.0 * weighted / denominator


def paired_bootstrap_interval(
    candidate: tuple[float, ...],
    baseline: tuple[float, ...],
    *,
    seed: int,
    samples: int = 10_000,
    confidence: float = 0.95,
) -> BootstrapInterval:
    """Return a deterministic percentile interval for paired score deltas."""

    if not candidate:
        raise ValueError("paired bootstrap requires at least one pair")
    if len(candidate) != len(baseline):
        raise ValueError("candidate and baseline must have the same length")
    if samples < 1:
        raise ValueError("samples must be positive")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be between 0 and 1")

    deltas = tuple(left - right for left, right in zip(candidate, baseline, strict=True))
    generator = random.Random(seed)
    bootstrapped = sorted(
        fmean(deltas[generator.randrange(len(deltas))] for _ in deltas) for _ in range(samples)
    )
    tail = (1.0 - confidence) / 2.0

    def percentile(probability: float) -> float:
        index = round((len(bootstrapped) - 1) * probability)
        return bootstrapped[index]

    return BootstrapInterval(
        mean_delta=fmean(deltas),
        low=percentile(tail),
        high=percentile(1.0 - tail),
        confidence=confidence,
        samples=samples,
        seed=seed,
    )
