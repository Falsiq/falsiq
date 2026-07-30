# Design decisions

This file records v0 clarifications where the PRD's interfaces otherwise leave
durable state or runtime behavior ambiguous.

## D027: Version 1 migration is an append-only writer switch

`falsiq migrate --to 2` is a dry run. `--apply` appends one global migration
fact; it never rewrites a schema-v1 line. Readers accept both versions forever,
while new facts use schema v2 after the marker. Round limits live in
digest-pinned TOML policy rather than the durable schema.

## D028: The public integration boundary is copied, not imported

External components depend only on `contract/`: its semantic version, JSON
Schemas, and byte-stable fixtures. The Python package remains an implementation
detail. `brief.json` commits stable obligation IDs, explicit discretion and open
ambiguities, plus prompt, policy, profile, and deriver provenance.

## D029: RPC is strict stdio over direct domain functions

`falsiq rpc` accepts newline-delimited JSON and emits exactly one response for
each input line. Operations accept structured values rather than filesystem
paths. The process invokes no model, agent, socket, or shell; external
orchestrators retain process ownership. `FALSIQ_STATE_ROOT` is the sole v1
cross-workspace federation mechanism.

## D030: Prompt improvement remains human-gated

Attack facts and complete review-round facts pin prompt content digests. Outcome
reports attribute elicited and missable rework to those identities, but Falsiq
does not edit prompts. A human must change a prompt and approve it against the
frozen benchmark before merge.

## D001: Cases share one ledger

Each root intent opens a case. Every downstream fact carries its `case_id`, and
case artifacts live below `.falsiq/cases/<case-id>/`. Facts remain in one global
ledger so conflict reviews can observe prior cases.

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

## D007: Review selection is machine-verifiable

Reviewer batches and selector envelopes are transient. Candidates receive a
canonical SHA-256 content digest, and the CLI recomputes the exact rational score
and selected set before appending only the selected reviews. Selection first
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
review's targets. Reviews carrying multiple targets require an explicit
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

A sandbox ID is a canonical ULID but need not identify a durable review fact:
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
response can add only one safe test stub or unexpressible reason per active
forbidden ruling; intent, ruling, and agent discretion sections are always
rendered from ledger facts. Every settled decision on an active `dont_care`
ruling is listed with ruling and review provenance, and the external deriver
cannot add or omit discretion. A ruling is not meaningful without its collision,
so the brief includes the source review's concrete artifact, option bodies,
settled decisions, and risk scenario alongside the verdict and choice.

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

## D014: Consequences are bounded by every review contract

A consequence is useful only as a cheap day-30 narrative. Durable review facts,
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

Round request generation, assembly, and handoff guarding therefore live in
package APIs exposed as `falsiq review request`, `falsiq review assemble`, and
`falsiq guard`. Historical Python scripts are thin source-checkout compatibility
wrappers, not production skill dependencies. Canonical production prompts live
once as package data under `falsiq/prompts/`; requests carry their exact prompt,
Pydantic-generated response schema, and valid examples, so a placed skill needs
no prompt copy or Falsiq source tree. A valid guard proves committed artifact
integrity, while model-authored test stubs remain untrusted and require complete
inspection before execution or merge.

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
`PublicTask` and elicited `ReviewCandidate`/`PublicRuling` contracts. Hidden
requirements, discriminators, scorer mappings, and principal-only metadata are
not inputs to the renderer. The original request remains verbatim context; in
the single-intent evaluation protocol, the latest amendment is the active
verbatim intent and earlier amendments remain clearly labeled superseded
evidence.

Every active ruling carries its review class, round, artifact, option meanings,
settled decisions, risk scenario, verdict, and choice into the builder handoff.
Forbidden choices create explicit acceptance-test obligations when the visible
fixture can express them. Decisions settled by `dont_care` are separately
licensed as agent discretion instead of silently disappearing. This mirrors the
decision-bearing parts of the production brief without synthesizing test code
or consulting hidden corpus content. Existing deterministic request IDs and
condition-blind candidate labeling remain unchanged.

## D022: Derived test stubs are inert requirements carriers

Model-authored forbidden-test output is never accepted as executable test code.
The validator permits only an optional literal module docstring followed by one
or more uniquely named, synchronous, undecorated, parameterless top-level
`test_[a-z0-9_]+` functions. A function may have only a `None` return annotation,
an optional literal docstring, and exactly one `pass` or
`raise NotImplementedError` placeholder with an optional literal message.
Source-encoding declarations, imports, module assignments and calls, async or
nested-only tests, fixtures, decorators, type comments, evaluated annotations,
assertions, and arbitrary function bodies are rejected.

These files carry a negative requirement across the derivation boundary; they
are not ready-to-run acceptance tests. The builder must read each file fully and
translate its requirement into a new repository-native failing test after
inspecting local conventions. It must never execute, import, copy, or merge the
derived file as-is.

## D023: Skill examples are executable gate contracts

The scripted transcript must carry the complete two-line human barrier and obey
the same round-two transition as the normative skill. A bypass is recognized
only by a case-sensitive standalone user-message line whose trimmed content is
exactly `skip falsiq`; prose, synonyms, and case variants do not qualify. The
prerequisite script checks the CLI's declared compatible version and is not a
binary identity attestation. Fresh-agent forward tests cover these claims in
addition to source-level unit tests.

## D024: The skill is host-agnostic and discovered through symlinked roots

The canonical skill directory is `skill/`. The source checkout exposes it
through two checked-in directory symlinks: `.claude/skills/falsiq` for Claude
Code and `.agents/skills/falsiq` for the cross-tool skills standard read by
Cursor, Codex, and other generic skill-aware hosts. Neither entry is a second
copy; a target repository may instead place a copied regular skill directory
under either discovery root.

`SKILL.md` references its bundled scripts only through `${SKILL_DIR}`, resolved
once per session as the directory containing the loaded `SKILL.md`. Production
prompts come from self-contained requests emitted by the installed CLI. Under
Claude Code `${SKILL_DIR}` is `${CLAUDE_SKILL_DIR}`; other hosts use the absolute
path of the discovered skill directory. The workflow itself is host-neutral:
it invokes only the separately installed `falsiq` console script and never a
host-specific runtime API, so barriers, round limits, and guard semantics are
identical across hosts.

## D025: Malformed reviewer output degrades only its own role

An external reviewer may honestly return zero candidates, so malformed output
has no safe semantic repair that is stronger than the same empty contribution.
Before round assembly, `falsiq review prepare` reads each untrusted response as
a bounded regular non-symlinked file, rejects invalid UTF-8, non-standard JSON,
duplicate keys, extra fields, wrong case or role, and every Pydantic schema
violation. A rejection emits a warning and the canonical empty batch for that
role; it does not abort or alter the other four roles.

This availability fallback never relaxes `review assemble` or `review add`.
Prepared batches and selection envelopes remain strictly validated, candidates
are never inferred from malformed bytes, and no partial durable batch is
appended. Self-contained reviewer requests reduce fallback frequency by carrying
the exact response schema and valid empty and populated examples alongside the
canonical prompt and ledger state.

## D026: Skill activation is explicit and external roles are reviewers

Skill discovery and repository state do not activate Falsiq. The current user
request must explicitly invoke `/falsiq` or contain the phrase `with falsiq`.
The exact standalone message `skip falsiq` remains a special invocation that
records only a bypass outcome. In particular, an existing `.falsiq/` directory
never causes automatic review rounds.

All model-facing roles, prompts, transient schemas, skill commands, and rendered
artifacts use neutral reviewer and review terminology. The CLI exposes `review`
as an exact alias for its canonical `attack` command. Existing durable ledger
facts retain their version-one wire representation so initialized repositories
remain readable; public state, logs, requests, and CLI arguments translate that
representation at the boundary.
