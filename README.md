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

## Rulings and outcomes

Record rulings with the exact commands rendered in the collision file. An amend
prints both the ruling ID and linked amendment-intent ID:

```console
falsiq rule ATTACK_ID intended --choice A
falsiq rule ATTACK_ID amend --text "Reject empty input" --intent INTENT_ID
```

Record post-implementation feedback separately:

```console
falsiq outcome rework --case CASE_ID --trace elicited --attack ATTACK_ID --notes "..."
falsiq outcome accepted --case CASE_ID --trace n/a
```

## Prototype sandboxes

Initialize Falsiq before creating a prototype worktree. Initialization manages
the exact `/sandbox/` entry in `.falsiq/.gitignore` while preserving every
existing ignore rule.

```console
falsiq init
falsiq sandbox new [01ARZ3NDEKTSV4RRFFQ69G5FAV]
falsiq sandbox reap
```

The optional ID is a canonical ULID allocated with the same generator used for
facts. It is a transient prototype ID, not proof that a durable attack fact
already exists: prototypes may be rendered before candidate selection. The
command does not infer or accept a case selector. Evidence chosen for a durable
attack must be copied or linked through a case-scoped
`cases/<case-id>/...` artifact path before selection is persisted.

Creation uses only `.falsiq/sandbox/<id>` on `falsiq/proto/<id>`. Normal reap
leaves dirty prototype worktrees and their manifest entries in place; use
`falsiq sandbox reap --force` only when those changes may be discarded. Reap
does not remove unrelated worktrees or branches.

Concurrent create and reap operations serialize through the ignored
`.falsiq/sandbox/.lock` sidecar. Manifest files are flushed, atomically
replaced, and followed by a directory fsync where the platform supports it.
Windows uses its byte-range advisory lock and file flush; directory fsync is a
documented no-op because Windows does not expose the required operation.

## Derivation handoff

The CLI never invokes a model. Emit a canonical request, give that JSON to the
external deriver described by `agents/deriver.md`, then submit its strict JSON
response:

```console
falsiq derive --case CASE_ID
falsiq derive --case CASE_ID --submit response.json
```

Requests are stored at
`.falsiq/cases/<case>/derived/<ledger-head>/request.json`. Submission rejects
open attacks, stale heads, mismatched request IDs, unsafe or duplicate test
names, and incomplete forbidden-ruling coverage. On success it prints the path
to `.falsiq/cases/<case>/derived/IMPLEMENTATION_BRIEF.md`, replaces the derived
pytest-stub set, and appends one derivation fact. Intent and amendment text in the
brief always comes verbatim from the ledger; response-authored text is confined
to the clearly labeled Agent discretion and test-expressibility sections.

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

The package API also exposes `run_conformance_evaluation` for replaying three
isolated builder conditions and condition-blind judges. Callers supply a visible
fixture root, an owner-private workspace root, and a hidden-test callback. Every
builder finishes before that callback runs, so hidden corpus content is never
mounted into a builder workspace during construction. Reports use a fixed seed
and paired bootstrap intervals and retain only per-task numeric conformance.
