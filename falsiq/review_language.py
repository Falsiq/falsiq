"""Neutral external vocabulary for model-facing case state."""

from __future__ import annotations

from typing import Any

_REVIEW_KEYS = {
    "attack_id": "review_id",
    "open_attacks": "open_reviews",
    "hate_scenario": "risk_scenario",
}


def neutralize_review_state(value: Any) -> Any:
    """Return a JSON-compatible state copy using reviewer-facing names."""

    if isinstance(value, dict):
        converted = {
            _REVIEW_KEYS.get(key, key): neutralize_review_state(item) for key, item in value.items()
        }
        if converted.get("kind") == "attack":
            converted["kind"] = "review"
        return converted
    if isinstance(value, list):
        return [neutralize_review_state(item) for item in value]
    return value


__all__ = ["neutralize_review_state"]
