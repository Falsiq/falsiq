# Falsiq user stories

Falsiq helps a coding agent discover consequential intent before it edits a
repository. It records the user's original words and later rulings in an
append-only ledger, while treating collision files, derivation requests,
implementation briefs, and test scaffolds as regenerable artifacts.

This guide describes the current `0.1.0` workflow. The
[README](../README.md) covers package internals and evaluation, while the
[skill contract](../skill/SKILL.md) is the normative orchestration procedure.

## The three participants

| Participant | What it does | What it does not do |
| --- | --- | --- |
| Human | States the change, reacts to concrete collisions, and explicitly rules each selected review. | Does not need to author candidate JSON or maintain a specification document. |
| External coding-agent skill | Inspects the target repository, runs five fresh reviewer agents in parallel, presents collisions, stops for human rulings, calls an external deriver, and implements only after handoff. | Must not invent a ruling, auto-select a human preference, or edit the target before the guard passes. |
| `falsiq` CLI | Deterministically validates, selects, records, renders, derives state, verifies artifacts, and manages prototype worktrees. | Never calls a model and does not generate reviewer or deriver responses on its own. |

Installing only the CLI therefore provides plumbing, not autonomous intent
elicitation. A normal interactive workflow also needs the external skill and
its agent host. Conversely, the skill expects the separately installed CLI; it
does not install or repair the target project's dependencies.

## Story 1: enable Falsiq in a target repository

> As a repository maintainer, I want Falsiq installed outside my project's
> dependency graph so that intent elicitation does not change the software I am
> asking an agent to modify.

The target must be a Git worktree. It does not need to be a Python project.
The copied skill directory shown below goes under a skill discovery root:
`.agents/skills/` for Cursor, Codex, and other generic agents, or
`.claude/skills/` for Claude Code. Claude Code 2.1.203 or newer is required
only for the source checkout's symlinked skill discovery; a target may use the
copied regular skill directory shown below.

From an operator environment that has the Falsiq checkout:

```console
$ uv tool install /absolute/path/to/falsiq
$ mkdir -p /absolute/path/to/target/.agents/skills
$ cp -R /absolute/path/to/falsiq/skill \
    /absolute/path/to/target/.agents/skills/falsiq
$ cd /absolute/path/to/target
$ falsiq --version
falsiq 0.1.0
$ sh .agents/skills/falsiq/scripts/require_cli.sh
```

The prerequisite script is silent on success. It stops with an actionable
message when `falsiq` is absent, unusable, or does not report the declared
compatible version.

Initialize the ledger once from anywhere inside the Git worktree:

```console
$ falsiq init
Initialized /absolute/path/to/target/.falsiq
```

Initialization creates `.falsiq/ledger.jsonl` and manages
`.falsiq/.gitignore`. The ledger is durable and is not one of the ignored
runtime sidecars. Sandbox data, locks, transaction journals, and derivation
locks are ignored.

Discovery and initialization do not activate the skill. A request opts in only
when it explicitly invokes `/falsiq` or contains the phrase `with falsiq`, for
example `Add bounded retries with falsiq`. An existing `.falsiq/` directory
never activates the workflow by itself. The exact standalone message
`skip falsiq` invokes only the bypass-recording path.

## Story 2: take a change from request to implementation

> As a feature owner, I want to react to concrete failure modes before coding
> starts so that the implementation reflects choices I actually made.

Suppose the user asks:

```text
Add bounded retries to the request helper without delaying ordinary failures,
with falsiq.
```

### 1. Intake preserves the request

Before an implementation edit, the skill verifies the CLI and opens one case
from the untouched request:

```console
$ CASE=$(falsiq intent "$VERBATIM_REQUEST")
$ falsiq state --json --case "$CASE"
```

`falsiq intent` prints the new case ID. The first durable fact contains the
user's text verbatim. On a resumed conversation, the skill recovers this case
instead of appending a duplicate root intent.

Useful inspection commands are:

```console
$ falsiq state --json --case "$CASE"  # active intent, rulings, open reviews
$ falsiq state --json                 # all cases, used by the conflict reviewer
$ falsiq log --case "$CASE"           # canonical durable facts for this case
```

### 2. External reviewers propose; the CLI selects

The external skill first asks the CLI for one self-contained request per review
class. Each request contains the canonical role prompt, relevant ledger state,
the exact response schema, and valid empty and populated examples. Boundary,
consequence, prototype, and omission receive case state; conflict receives
global state so it can compare the new request with earlier cases. The skill
then launches exactly five fresh agents as one parallel group. Their raw and
prepared candidate batches live in a private temporary directory outside the
worktree.

The commands below are normally issued by the skill, not typed by the user:

```console
$ falsiq review request --case "$CASE" --reviewer boundary \
    > "$TMP/boundary-request.json"
$ falsiq review prepare --case "$CASE" --reviewer boundary \
    --file "$TMP/boundary-raw.json" > "$TMP/boundary.json"
# Repeat request and prepare for consequence, prototype, conflict, and omission.
$ falsiq review assemble --case "$CASE" --round 1 \
    "$TMP/boundary.json" "$TMP/consequence.json" \
    "$TMP/prototype.json" "$TMP/conflict.json" \
    "$TMP/omission.json" > "$TMP/round.json"
$ falsiq review add --file "$TMP/round.json"
```

`review prepare` validates one role's output as strict JSON with no duplicate
keys, checks the case and class, and normalizes valid output. Invalid output is
replaced by only that role's canonical empty batch with a warning; because a
role may honestly find zero reviews, fabricating a repair would add less safety
than this explicit degradation. The remaining roles and round continue.

`review assemble` requires one prepared batch from every class, normalizes the
candidates, and computes the only policy-valid selection. It can select up to
three candidates and recomputes the selection when `review add` validates the
envelope. Editing the `selected` array or substituting an agent's preference is
rejected. Only selected reviews become ledger facts; raw batches, prepared
batches, and the round envelope remain disposable.

### 3. A collision creates a real human stop

When selection is nonempty, the skill renders the open reviews:

```console
$ COLLISION=$(falsiq collide --case "$CASE")
```

The command prints a path such as:

```text
/absolute/path/to/target/.falsiq/cases/<case-id>/collisions/1.md
```

The file contains each concrete artifact, the decisions it settles, the risk
scenario, any forced-choice meanings, and the exact legal ruling commands. The
skill reads and presents the complete file, then emits exactly:

```text
STOP -- HUMAN RULING REQUIRED
No implementation has started. Reply with an explicit ruling for every displayed review.
```

That message ends the agent turn. Derivation, tests, and implementation do not
continue behind the checkpoint.

### 4. The human rules; the CLI records

The user responds only to the displayed alternatives. The skill maps explicit
statements to the commands printed in the collision. Depending on the artifact,
legal commands look like:

```console
$ falsiq rule REVIEW_ID intended --choice A
$ falsiq rule REVIEW_ID forbidden --choice B
$ falsiq rule REVIEW_ID dont_care
$ falsiq rule REVIEW_ID amend --text "Retry only idempotent methods."
```

For a review targeting more than one active intent, an amendment also needs
the target shown by the collision:

```console
$ falsiq rule REVIEW_ID amend \
    --text "Retry only idempotent methods." --intent INTENT_ID
```

The verdicts mean:

- `intended`: the selected behavior is a commitment;
- `forbidden`: the selected behavior must not occur and may create a test
  obligation during derivation;
- `dont_care`: the settled decision is explicitly licensed as agent
  discretion; and
- `amend`: the exact amendment text becomes a linked intent fact.

An omitted or ambiguous response produces no ruling. The skill checks state,
re-renders only unresolved reviews, repeats the stop barrier, and ends the turn
again. A later explicit change of mind appends a superseding ruling rather than
editing the earlier fact.

After all round-one reviews are ruled, round two occurs only when at least one
active verdict is `amend` or `forbidden`. It uses five new reviewers in
parallel against the updated state. All-`intended`/`dont_care` rulings proceed
directly to derivation. No case gets a third round.

### 5. An external deriver proposes; the CLI publishes

With no open reviews, the CLI emits a canonical derivation request:

```console
$ REQUEST_PATH=$(falsiq derive --case "$CASE")
$ cat "$REQUEST_PATH"
```

The request is stored at:

```text
.falsiq/cases/<case-id>/derived/<ledger-head>/request.json
```

The request contains the canonical deriver instructions and exact response
schema. The skill reads that regular file completely and gives the exact JSON
to one fresh external deriver. The deriver cannot rewrite intent, add rulings,
or add agent discretion. It may return exactly one forbidden-test entry per
active `forbidden` ruling: either inert pytest-shaped requirements scaffolding
or a reason the behavior cannot be expressed as a repository-level test.

The skill writes the strict response to a private temporary file and submits
it:

```console
$ falsiq derive --case "$CASE" --submit "$TMP/deriver-response.json"
```

On success, the command appends a derivation fact and prints the brief path:

```text
/absolute/path/to/target/.falsiq/cases/<case-id>/derived/IMPLEMENTATION_BRIEF.md
```

Any accepted scaffolds are placed directly beneath:

```text
.falsiq/cases/<case-id>/derived/tests/
```

The brief gets its verbatim intent, rulings, evidence, choice meanings, and
`dont_care` discretion from the ledger. The external response cannot smuggle
new requirements into those sections.

### 6. Guard, handoff, and TDD

Immediately before the first implementation edit, the skill runs:

```console
$ BRIEF=$(falsiq guard --case "$CASE")
```

The guard requires no open reviews, a derivation newer than the case's latest
intent/review/ruling, a regular non-symlinked brief, and an exact committed set
of derived scaffolds. It verifies SHA-256 commitments and rejects missing,
edited, symlinked, or extra artifacts.

Guard success proves ledger and artifact integrity, not executable safety or
repository conformance. The coding agent reads the entire brief and every
derived scaffold. The brief is the implementation requirements source;
discarded candidates are not reintroduced. The scaffolds are inert,
model-authored requirements data: never run, import, copy, or merge them. For
each forbidden behavior, the agent instead inspects the repository's
conventions, writes and reviews a new repository-native failing test, then
implements and verifies the change using normal TDD.

The explicit `skip falsiq` bypass described below is the only path that permits
implementation without this guard and brief.

### 7. Record what happened

After implementation and review, outcomes become durable feedback without
changing the case specification:

```console
$ falsiq outcome accepted --case "$CASE" --trace n/a \
    --notes "Change passed review and repository checks."
```

If implementation needs rework, classify why:

```console
# The selected review exposed this requirement; --review is required.
$ falsiq outcome rework --case "$CASE" --trace elicited \
    --review REVIEW_ID --notes "The forbidden behavior reappeared."

# An existing review class could reasonably have exposed it, but none did.
$ falsiq outcome rework --case "$CASE" --trace missable \
    --notes "The empty-state decision was never surfaced."

# It could not reasonably have been exposed during intent elicitation.
$ falsiq outcome rework --case "$CASE" --trace novel \
    --notes "A newly discovered platform limitation changed the solution."
```

`accepted` and `abandoned` require `--trace n/a` and no review reference.
Only `elicited` rework accepts and requires `--review`.

## Story 3: explicitly bypass the barrier

> As the user, I want an auditable escape hatch when I knowingly accept the
> risk of implementing without elicitation.

The current user message bypasses only when it contains a case-sensitive
standalone line which, after trimming surrounding whitespace, is exactly:

```text
skip falsiq
```

`Skip Falsiq`, `please skip falsiq`, and similar prose do not bypass. Before any
implementation edit, the skill ensures a case exists for the full untouched
request and records:

```console
$ falsiq outcome abandoned --case "$CASE" --trace n/a \
    --notes "User explicitly requested skip falsiq."
```

Only after that append succeeds may the coding agent implement from the
original request without a derived brief. The bypass does not delete the case
or rewrite its intent.

## Story 4: an already precise request produces no collision

> As the user, I do not want ceremony when five independent reviewers find no
> honest ambiguity.

All five reviewer agents still return their bounded batches. If the canonical
round contains no candidates, assembly produces an empty selection:

```console
$ falsiq review assemble --case "$CASE" --round 1 \
    "$TMP/boundary.json" "$TMP/consequence.json" \
    "$TMP/prototype.json" "$TMP/conflict.json" \
    "$TMP/omission.json" > "$TMP/round.json"
{"candidates":[],"selected":[],...}
```

The skill does not call `review add` or `collide`, so no empty review fact or
human stop is manufactured. It proceeds to the external derivation and guard
handoff. This is the normal degenerate path, not an error.

## Story 5: compare rival behavior in a disposable prototype

> As a user facing two plausible observable behaviors, I want to see a small
> comparison without turning the prototype into implementation work.

The prototype reviewer may make at most one one-shot attempt in a Falsiq-owned
Git worktree. After initialization, the skill can request one with an optional
canonical transient ID:

```console
$ falsiq sandbox new
{"review_id":"<id>","branch":"falsiq/proto/<id>","path":".falsiq/sandbox/<id>"}
```

The sandbox is created at `.falsiq/sandbox/<id>` on branch
`falsiq/proto/<id>`. It is not proof that a review with that ID was selected.
The sandbox has no Falsiq merge or push operation and must not become a second
development environment.

If prototype evidence is selected, the external agent first copies the
observable transcript or other required evidence into a case-scoped path
beneath `.falsiq/cases/<case-id>/`. Once the prototype changes are known to be
disposable:

```console
$ falsiq sandbox reap
```

Normal reap removes clean managed worktrees. It refuses to discard a dirty
prototype and leaves it available for inspection. After preserving any
selected evidence, an operator who intentionally accepts deletion may use:

```console
$ falsiq sandbox reap --force
```

Reap does not remove unrelated Git worktrees or branches.

## When Falsiq is useful

Falsiq is most useful when a small implementation decision could produce a
materially different outcome:

- retry, timeout, ordering, validation, empty-state, and compatibility policy;
- migrations, destructive operations, persistence, permissions, or concurrency;
- API changes where existing behavior or an earlier ruling may conflict;
- requests with two cheap, observable rival behaviors; and
- changes where `dont_care` is valuable because it explicitly delegates a
  decision instead of leaving accidental ambiguity.

It is usually not useful for:

- read-only explanation, status, diagnosis, or review;
- a spelling or formatting-only correction;
- asking the CLI to choose what the human wants—the CLI never does;
- replacing intent capture with speculative requirements or silently improving a prompt; or
- preserving prototype code as production implementation.

An explicit invocation is still honored for any task. A genuinely complete
request should naturally take the no-collision path rather than receive
invented questions.

Concrete examples:

| Request | Expected fit |
| --- | --- |
| “Add retry logic to the HTTP helper.” | Useful: status classes, exception types, method safety, attempt limits, and delay policy can produce materially different behavior. |
| “Migrate stored sessions to the new schema without downtime.” | Useful: compatibility, partial failure, rollback, concurrency, and old-reader behavior deserve concrete collisions. |
| “Rename this CLI flag but keep existing automation working.” | Useful: a conflict reviewer can compare compatibility expectations with current tests and earlier rulings. |
| “Show me compact and verbose output before we choose one.” | Useful: a one-shot prototype can render the rival observable behaviors without becoming production code. |
| “Explain how the parser handles empty input.” | Usually not useful: this is a read-only explanation, so the agent should inspect and report rather than open an intent case. |
| “Run the tests and summarize the failures.” | Usually not useful: this is read-only diagnosis, not authorization to change behavior. |
| “Fix `recieve` to `receive` in the comment.” | Usually not useful: this is a purely cosmetic correction unless the user explicitly invokes Falsiq. |
| “Implement exactly this supplied input/output table with falsiq.” | The explicit invocation runs Falsiq, but honest reviewers may return no candidates and take the degenerate path. |

## Artifact map

| Artifact | Purpose | Durable? |
| --- | --- | --- |
| `.falsiq/ledger.jsonl` | Canonical append-only intent, review, ruling, derivation, and outcome facts. | Yes |
| Private `$TMP/*.json` | Raw candidate batches, selection envelope, and external deriver response. | No; kept outside the worktree and deleted after handoff or failure |
| `.falsiq/cases/<case>/collisions/<round>.md` | Complete forced-choice collision and legal commands for the currently open round. | Derived case artifact; the ledger remains canonical |
| `.falsiq/cases/<case>/derived/<head>/request.json` | Canonical request bound to one ledger head and response schema. | Derived request artifact; the ledger remains canonical |
| `.falsiq/cases/<case>/derived/IMPLEMENTATION_BRIEF.md` | Current implementation handoff derived from ledger facts and validated external output. | Regenerable and hash-committed; do not edit |
| `.falsiq/cases/<case>/derived/tests/test_*.py` | Inert forbidden-behavior requirements scaffolds. | Regenerable and hash-committed; never execute or copy as tests |
| `.falsiq/sandbox/<id>` | Disposable prototype worktree. | No |

## Troubleshooting expectations

Falsiq fails closed. An error means the coding agent stops rather than working
around the barrier.

| Symptom | Meaning and expected response |
| --- | --- |
| `STOP -- FALSIQ CLI REQUIRED`, `CLI UNUSABLE`, or `CLI VERSION MISMATCH` | Install or repair the declared compatible tool outside the target project, then rerun the prerequisite. The skill must not do this silently. |
| `not inside a Git repository` | Move into the intended Git worktree or initialize Git before running Falsiq. |
| Ledger not initialized | Run `falsiq init` once in the target. Do not create ledger files by hand. |
| Malformed reviewer output, wrong case or role, duplicate keys, or unsafe response file | `review prepare` warns and emits that role's canonical empty batch. Continue the round with the other four prepared batches; never fabricate a candidate. |
| Duplicate prepared class, missing prepared batch, or edited selection | Discard the temporary round and regenerate its deterministic inputs. No partial review batch should be appended. |
| `STOP -- HUMAN RULING REQUIRED` from the guard | One or more reviews remain open. Inspect `falsiq state --json --case "$CASE"`, present the unresolved collision, and wait for explicit rulings. |
| Round two is rejected | Round one is missing, still open, already duplicated, or lacks an active `amend`/`forbidden` verdict. Follow the state-derived gate; do not force a round. |
| Derivation request or response is rejected | Resolve open reviews or ask a fresh external deriver to copy the request identity exactly and return only the allowed schema. Never weaken validation or hand-edit the request. |
| Guard reports no current derivation | Intent, reviews, or rulings changed after derivation, or no response was submitted. Emit a new request, obtain a fresh response, and submit again. |
| Guard reports missing, symlinked, edited, digest-mismatched, or extra derived artifacts | Treat the derived tree as disposable and regenerate it through `falsiq derive`; do not patch the brief or scaffolds manually. |
| `sandbox reap` reports a dirty prototype | Inspect it and preserve selected evidence first. Use `--force` only when discarding those changes is intentional. |
| Ledger integrity error | Stop and involve the repository operator. Do not delete, rewrite, or skip malformed durable facts. |

For recovery and audit, prefer deterministic reads:

```console
$ falsiq state --json
$ falsiq state --json --case "$CASE"
$ falsiq log --case "$CASE"
$ falsiq log --kind ruling --case "$CASE"
```

These commands do not ask an agent to reinterpret the ledger. They expose the
facts and current state that every external reviewer and deriver must respect.
