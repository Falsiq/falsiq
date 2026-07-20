"""Load the production agent prompts shipped with the Falsiq package."""

from __future__ import annotations

from importlib.resources import files

ATTACK_PROMPT_NAMES = {
    "boundary": "attacker_boundary.md",
    "consequence": "attacker_consequence.md",
    "prototype": "attacker_prototype.md",
    "conflict": "attacker_conflict.md",
    "omission": "attacker_omission.md",
}


def load_production_prompt(name: str) -> str:
    """Return one canonical UTF-8 production prompt from package data."""

    if name == "deriver":
        filename = "deriver.md"
    else:
        try:
            filename = ATTACK_PROMPT_NAMES[name]
        except KeyError:
            raise ValueError(f"unknown production prompt: {name}") from None
    return files("falsiq").joinpath("prompts", filename).read_text(encoding="utf-8")


__all__ = ["ATTACK_PROMPT_NAMES", "load_production_prompt"]
