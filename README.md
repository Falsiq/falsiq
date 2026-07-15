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

## Executable agents

Agent execution is a separate `falsiq-agent` program so the `falsiq` plumbing
CLI remains model-free. Each agent is a fresh process that receives exactly one
JSONL request on standard input and must emit exactly one JSONL response:

```json
{"role":"attacker.boundary","request_id":"r1","payload":{"case_id":"c1"}}
{"request_id":"r1","response":{"attacks":[]}}
```

Replay is the normal mode. It requires the incoming request to match the whole
recorded request, then atomically captures a fresh private transcript:

```console
falsiq-agent run --replay recording.json --transcript captured.json < request.jsonl
```

Live commands are argv after `--`; no shell is used. They additionally require
`--live`, a task or case ID, a fixed model ID, a local allowlist, and a non-CI
environment:

```json
{
  "schema_version": 1,
  "task_ids": ["t001"],
  "case_ids": ["01CASE"],
  "models": {"attacker.boundary": "provider/model-2026-07-15"}
}
```

```console
falsiq-agent run --live --allowlist .falsiq/live-allowlist.json \
  --case-id 01CASE --model-id provider/model-2026-07-15 \
  --transcript .falsiq/transcripts/r1.json -- agent-executable --flag \
  < request.jsonl
```

The approved model and subject are passed to the adapter as
`FALSIQ_MODEL_ID` and `FALSIQ_TASK_ID` or `FALSIQ_CASE_ID`. Keep provider
credentials in the adapter environment, never in argv. Transcripts deliberately
exclude argv, environment variables, stdout diagnostics, and stderr logs.

## Attack rounds

Class-specific attackers emit strict disposable candidate batches. After
normalization and selection, append one machine-verified round envelope and
render its open collisions:

```console
falsiq attack add -f selector-round.json
falsiq collide --case 01ARZ3NDEKTSV4RRFFQ69G5FAV
```

The selector envelope contains at most 20 canonical candidate records and up to
three selected content digests. The CLI recomputes exact scores and composition,
then appends all selected attacks as one ledger batch. No candidate or free-form
selection rationale is persisted. Round two is accepted only after every
round-one attack is ruled and at least one verdict is `amend` or `forbidden`.

## Offline evaluation

The evaluation harness replays strict role-specific agent recordings, captures
owner-private resumable transcripts, and writes redacted JSON, CSV, and
Markdown metrics. It compares Falsiq collisions with a naive-question baseline
under the same maximum rounds and interactions. There is no live execution path
in the harness itself.

```console
uv run python eval/run.py \
  --task path/to/task.json \
  --recordings /private/recordings \
  --private-run-dir /private/run \
  --reports reports
```

Use `--resume` to reuse an exact captured request/response transcript. Smoke
tasks under `tests/fixtures/eval/` are test data, not benchmark candidates.
