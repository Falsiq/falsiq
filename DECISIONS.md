# Design decisions

This file records v0 clarifications where the PRD's interfaces otherwise leave
durable state or runtime behavior ambiguous.

## D001: Cases share one ledger

Each root intent opens a case. Every downstream fact carries its `case_id`, and
case artifacts live below `.falsiq/cases/<case-id>/`. Facts remain in one global
ledger so conflict attacks can observe prior cases.

## D002: Rival choices are durable

Artifacts may contain keyed options. Option-bearing `intended` and `forbidden`
rulings record a choice. Choosing an intended option makes its rivals
`not_intended`; it does not make them forbidden.

## D003: Models remain outside the CLI

`falsiq derive` emits a deterministic request. An external deriver returns a
structured response that `falsiq derive --submit` validates and materializes.
The evaluation harness likewise uses executable JSONL agents rather than a
model SDK.

## D004: Live evaluation is opt-in

Replay is the default. Live evaluation additionally requires `--live`, a local
allowlist, fixed model identifiers, and a non-CI environment. Human-approved
held-out task bodies remain outside the repository.

## D005: Agent transcripts contain protocol data only

An executable agent handles one request in one process. A successful transcript
contains only the strict request and response objects and is atomically replaced
with owner-only permissions. Commands, environment variables, stderr, and raw
invalid stdout are neither persisted nor included in runtime errors. Replay
matches the entire request, not only its ID.

## D006: Live model selection is role-bound

The local live allowlist binds each agent role to one exact model identifier and
separately lists approved task and case IDs. The runtime rejects moving aliases
such as `latest`, wildcard identifiers, symlinked allowlists, every detected CI
environment, and any invocation without exactly one approved subject. The
approved subject must also be present in the request payload, and every nested
occurrence of its `task_id` or `case_id` field must match, so a caller cannot
authorize unrelated content by changing only the command-line flag.

## D007: Attack selection is machine-verifiable

Attacker batches and selector envelopes are transient. Candidates receive a
canonical SHA-256 content digest, and the CLI recomputes the exact rational score
and selected set before appending only the selected attacks. Selection first
maximizes the valid set size up to three, then total score; equal totals use the
lexicographically sorted digest set. Selector rationale is derived from these
inputs rather than accepted as agent-authored durable state.

Artifact fact paths are relative to `.falsiq/` and must remain below the owning
`cases/<case-id>/` directory. This keeps collision links relocatable while the
ledger rejects cross-case artifact references.

## D008: Evaluation outputs are split by sensitivity

Replay recordings and captured transcripts contain hidden task content and stay
in an owner-private run directory. Public JSON, CSV, and Markdown reports carry
only stable task IDs, strata, and numeric metrics. The replay-only harness has
no live-agent switch; authorized live recordings are captured separately before
evaluation.

## D009: Amendments name the intent they replace

An amend ruling and its linked verbatim intent are admitted as one expected-head
ledger batch. The superseded intent must still be active and must be one of the
attack's targets. Attacks carrying multiple targets require an explicit
`--intent`, even when only one target remains active, so historical targets never
make the amendment choice implicit. Re-rulings automatically supersede the
active earlier ruling without mutating its record.

## D010: Builder replays materialize explicit file updates

Builder responses contain complete UTF-8 file updates and deletions, allowing a
recorded response to reconstruct its isolated workspace without rerunning a
model. All three builders finish before hidden tests begin. Judges receive
opaque randomized candidate IDs, implementation changes, and visible and hidden
test results, but never an experimental condition label. Workspace cleanup is
limited to a dedicated owner-private root carrying a Falsiq marker; unmarked
directories are never reaped.

## D011: Prototype sandboxes use transient global IDs

A sandbox ID is a canonical ULID but need not identify a durable attack fact:
prototype candidates can be rendered before selected-only ledger persistence.
The command therefore allocates an ID when omitted and takes no case selector.
Selected evidence is copied or linked through the owning case's artifact path.
Creation is restricted to `.falsiq/sandbox/<id>` and `falsiq/proto/<id>`. Reap
is global, preserves every failure by default, and requires an explicit
`--force` before discarding dirty prototype worktrees.

The ignored manifest sidecar lock covers the complete manifest read, Git
mutation, and durable manifest update. POSIX directory entries are fsynced after
atomic replacement; Windows retains advisory locking and file flushes while
directory fsync remains a documented platform no-op.

## D012: Derivation is a head-bound external handoff

`derive` writes a canonical request below the observed ledger head. Its request
ID hashes the case state, bundled deriver prompt, and response schema. The strict
response can add only bounded agent-discretion entries and one safe test stub or
unexpressible reason per active forbidden ruling; intent and ruling sections are
always rendered from ledger facts. A ruling is not meaningful without its
collision, so the brief includes the source attack's concrete artifact, option
bodies, settled decisions, and hate scenario alongside the verdict and choice.

The current brief and test directory are disposable stable paths beneath the
case. They are staged and published before an expected-head derivation append;
confirmed failed admission restores any prior outputs byte-for-byte. If the
append raises after the fact committed or commit status cannot be read safely,
the new disposable outputs remain in place rather than contradicting a possibly
durable fact. Request files remain head-keyed so stale responses are auditable
and cannot overwrite current output.

A per-case advisory lock covers backup, publication, ledger admission, and
rollback at the stable brief and test paths. This prevents a losing concurrent
submission from deleting a different submission's committed artifacts.
