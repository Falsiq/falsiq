"""Load the production agent prompts shipped with the Falsiq package."""

from __future__ import annotations

import hashlib
from importlib.resources import files

REVIEW_PROMPT_NAMES = {
    "boundary": "reviewer_boundary.md",
    "consequence": "reviewer_consequence.md",
    "prototype": "reviewer_prototype.md",
    "conflict": "reviewer_conflict.md",
    "omission": "reviewer_omission.md",
}


def load_production_prompt(name: str) -> str:
    """Return one canonical UTF-8 production prompt from package data."""

    if name == "deriver":
        filename = "deriver.md"
    else:
        try:
            filename = REVIEW_PROMPT_NAMES[name]
        except KeyError:
            raise ValueError(f"unknown production prompt: {name}") from None
    return files("falsiq").joinpath("prompts", filename).read_text(encoding="utf-8")


def production_prompt_digests() -> dict[str, str]:
    """Return content identities for every canonical reviewer prompt."""

    return {
        name: hashlib.sha256(load_production_prompt(name).encode("utf-8")).hexdigest()
        for name in REVIEW_PROMPT_NAMES
    }


__all__ = ["REVIEW_PROMPT_NAMES", "load_production_prompt", "production_prompt_digests"]
