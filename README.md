# Falsiq

Falsiq is an adversarial intent-elicitation layer that runs before a coding
agent implements a change. It records the user's intent and rulings in an
append-only JSONL ledger, then derives disposable implementation briefs from
that durable record.

The Python CLI is deterministic and never invokes a language model. Agent
prompts and the Claude Code skill call the CLI from outside that boundary.

## Development

```console
uv sync
uv run pytest
uv run ruff check .
```

The command can be run from the checkout with `uv run falsiq` or installed as
the `falsiq` console script.
