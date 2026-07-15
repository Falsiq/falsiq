"""Cross-contract limits that must agree in durable and transient schemas."""

from __future__ import annotations

CONSEQUENCE_WORD_LIMIT = 150


def validate_consequence_artifact(
    *,
    klass: str,
    artifact_type: str,
    body: str | None,
) -> None:
    """Require consequence attacks to be bounded, inline scenario narratives."""

    if klass != "consequence":
        return
    if artifact_type != "scenario":
        raise ValueError("consequence artifact must have type scenario")
    if body is None:
        raise ValueError("consequence scenario must have an inline narrative body")
    if len(body.split()) > CONSEQUENCE_WORD_LIMIT:
        raise ValueError(
            f"consequence scenario must contain at most {CONSEQUENCE_WORD_LIMIT} words"
        )
