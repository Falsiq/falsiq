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

Agent stdout and stderr each have an 8 MiB acceptance limit. Both streams are
captured in temporary files rather than unbounded in-memory buffers. A monitor
kills and waits for a process that exceeds either limit; overflow content is
never parsed, echoed, or written to a transcript.

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

Managed ignore rules cover the sandbox, manifest and ledger locks, transaction
journal files, and per-case derivation locks without replacing user rules. The
durable ledger remains visible to Git. The manifest sidecar lock covers the
complete manifest read, Git mutation, and durable manifest update. POSIX
directory entries are fsynced after atomic replacement; Windows retains
advisory locking and file flushes while directory fsync remains a documented
platform no-op.

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

## D013: Corpus publication commits private state first

Corpus preparation requires exactly ten human-approved tasks per stratum before
the seeded 3/3/4 selection can run. The twenty development tasks and fixtures
may be materialized in a public output, while full holdout tasks and fixtures go
only to a private output outside the repository. The public manifest contains
only IDs, strata, seed metadata, and salted canonical-task hashes.
Manifest construction takes the complete approved corpus and derives the seeded
selection internally; no public API accepts a caller-chosen 3/3/4 subset.

Both output trees are completely staged beside their targets. Publication
renames the private tree first and treats the public tree as the final commit
point. Handled errors roll back both trees. A crash may therefore leave private
state alone, but never a public release that was committed before its private
counterpart. Existing outputs, symlinks, path aliases, and overlapping roots are
rejected instead of merged or overwritten.

## D014: Consequences are bounded by every attack contract

A consequence is useful only as a cheap day-30 narrative. Durable attack facts,
disposable production candidates, and evaluation candidates therefore share the
same executable rule: the artifact is an inline `scenario` body of at most 150
whitespace-delimited words. Path-only or differently typed artifacts are
rejected before selection or append rather than relying on prompt compliance.

## D015: Derivation facts commit exact artifact bytes

A derivation fact carries a canonical lowercase SHA-256 digest for the stable
brief and a path-to-digest mapping whose keys exactly equal its test-stub path
list. The brief path and every stub path have one case-scoped canonical form.
Submission hashes the same UTF-8 bytes it stages for publication, so the ledger
commitment and installed files cannot diverge through a second encoding step.

Derived output remains disposable but is not editable. Before implementation,
the skill guard verifies regular non-symlinked path components, the brief and
stub content digests, and the exact test-directory membership. Missing, changed,
symlinked, or extra artifacts require re-derivation; request directories and the
per-case derivation lock are outside the committed artifact set.

## D016: Ruling age is measured in later case facts

Wall-clock age would make identical ledgers derive different state over time.
Each active ruling instead carries the number of later facts in its case, and
the human state view renders that value. This stable ledger age highlights
commitments that survived substantial subsequent activity while retaining the
ruling's canonical timestamp for chronological inspection.

## D017: Heldout evaluation has an access-logged CLI mode

The evaluation runner has mutually exclusive task sources. `--task` is a
development-only path interface and is never an approved route to a private
holdout body. Heldout mode accepts manifest task IDs and requires the public
salted manifest, the release's owner-private `tasks/` directory, an owner-only
salt file, an owner-private access log, and nonblank actor and purpose metadata.

The runner strictly validates the manifest, reads the salt without placing it
on the command line, and obtains each body only through
`read_private_holdout_task`. Manifest membership is checked before logging;
after membership succeeds, a durable log append is required before the private
regular file is read and its canonical salted hash is verified. A logging
failure prevents the read. This preserves the distinction between an unknown
ID and a failed task-body attempt that burns holdout freshness.

## D018: The installed CLI and Claude Code skill are separate deliverables

The Python wheel packages deterministic plumbing only. An operator installs its
`falsiq` console script outside a target repository's dependency graph and
separately places the self-contained skill directory at
`.claude/skills/falsiq/`. The production skill checks its exact compatible CLI
version, invokes plain `falsiq`, and stops instead of installing or upgrading a
missing or mismatched tool. It never uses a target interpreter to import
Falsiq.

Round assembly and handoff guarding therefore live in package APIs exposed as
`falsiq attack assemble` and `falsiq guard`. Historical Python scripts are thin
source-checkout compatibility wrappers, not production skill dependencies. The
canonical agent prompts remain under `agents/`; byte-equal copies under
`skill/references/` make a placed skill portable without depending on the
Falsiq source tree. A valid guard proves committed artifact integrity, while
model-authored test stubs remain untrusted and require complete inspection
before execution or merge.

## D019: Corpus descriptor modes are portable best effort

POSIX release and access-log files are tightened through `fchmod` and verified
as owner-only where those mode bits exist. Platforms without descriptor-level
chmod retain exclusive creation, regular-file and symlink checks, and private
output separation without calling an unavailable API; their native ACL policy
remains an operator responsibility.

## D020: Transcript capture requires a real private directory

Replay and live transcripts can contain benchmark or case data. Capture walks
every directory component without following symlinks, creates missing
components owner-only, rejects a public final directory on POSIX, and refuses
symlinked or non-regular targets. Evaluation runtime setup uses the same guard,
so an unsafe private-run path fails before a response is captured or an outside
directory is chmodded.

## D021: Evaluation builders receive decision-bearing Falsiq handoffs

The end-to-end Falsiq condition is rendered only from the builder-visible
`PublicTask` and elicited `AttackCandidate`/`PublicRuling` contracts. Hidden
requirements, discriminators, scorer mappings, and principal-only metadata are
not inputs to the renderer. The original request remains verbatim context; in
the single-intent evaluation protocol, the latest amendment is the active
verbatim intent and earlier amendments remain clearly labeled superseded
evidence.

Every active ruling carries its attack class, round, artifact, option meanings,
settled decisions, hate scenario, verdict, and choice into the builder handoff.
Forbidden choices create explicit acceptance-test obligations when the visible
fixture can express them. Decisions settled by `dont_care` are separately
licensed as agent discretion instead of silently disappearing. This mirrors the
decision-bearing parts of the production brief without synthesizing test code
or consulting hidden corpus content. Existing deterministic request IDs and
condition-blind candidate labeling remain unchanged.
