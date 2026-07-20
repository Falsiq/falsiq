# Contributing to Falsiq

Falsiq exists to move expensive intent mistakes ahead of implementation. It
records a user's original request and explicit rulings as durable facts, while
treating collision files, implementation briefs, test scaffolds, and reports as
derived artifacts. The central design rule is:

> Persist the record, derive the model, and formalize only commitments that must
> survive reinterpretation.

Changes should strengthen that distinction. Falsiq is not a prompt rewriter, a
clarifying-question chatbot, an automatic decision maker, or a model SDK.

## Start with the current contract

Before changing behavior, read the repository-owned sources together:

- [`DECISIONS.md`](DECISIONS.md) records repository-owned clarifications that
  make durable formats and runtime behavior precise.
- [`README.md`](README.md) documents the behavior users and operators can run
  today.
- [`docs/user-story.md`](docs/user-story.md) shows the end-to-end human, skill,
  and CLI workflow from setup through implementation feedback.
- The implementation and tests define the executable contract. A disagreement
  among these sources is a bug to resolve explicitly, not permission to choose
  one silently.

The original development workspace may also contain `../PRD.md`, which records
the thesis, core loop, success criteria, and v0 non-goals that started the
project. It is not part of this Git repository or wheel, so a normal clone does
not contain it. This guide carries the contributor-facing architecture and
motivation; do not introduce a runtime or packaging dependency on the outer
workspace document.

Record a new durable or security-relevant interpretation in `DECISIONS.md`.
Update the README when a user-facing command, artifact, prerequisite, or
operator workflow changes. Keep implementation, tests, prompts, skill material,
and evaluation contracts in the same logical change.

The current v0 implements deterministic ledger plumbing, external-agent
protocols, attack selection, ruling and derivation handoffs, prototype
sandboxes, replay-first evaluation, corpus release controls, and the agent
skill workflow for Claude Code, Cursor, Codex, and generic skill-aware hosts. It does **not** include a bundled provider adapter, invoke a language
model from the `falsiq` CLI, contain an approved held-out corpus, or establish
the PRD's held-out success thresholds. Do not claim those results without a
human-approved, access-logged official run.

## Architecture and data flow

The Python package and the agent layer have a hard direction of dependency:
agents call deterministic package interfaces; the plumbing CLI never calls an
agent or model.

```text
verbatim request
    -> intent fact / case
    -> five external attacker batches (transient)
    -> deterministic selection
    -> selected attack facts + collision artifact
    -> explicit human rulings
    -> head-bound derivation request
    -> external deriver response (untrusted)
    -> validated brief + inert test scaffolds + derivation fact
    -> integrity guard
    -> implementation outside Falsiq
    -> outcome fact
```

`falsiq init` discovers the target Git root and creates `.falsiq/`. One global
canonical JSONL ledger holds all cases so conflict attacks can observe prior
decisions. A root intent's ULID is also its case ID; case-scoped artifacts live
under `.falsiq/cases/<case-id>/`. Facts are never updated or deleted. Amendments
and re-rulings append new facts that supersede older ones, and current state is
derived by replaying the complete validated sequence.

Attacker requests and selection envelopes are disposable protocol values. The
installed CLI emits each request with its canonical prompt, relevant state,
exact response schema, and valid examples. It normalizes valid responses and
turns malformed output into only that role's canonical empty batch, then reads
exactly one prepared batch for each attack class, computes canonical content
digests and rational scores, and persists only the selected attacks as an
expected-head batch. Collision Markdown renders the ledger-owned artifacts as
forced choices. Only explicit human rulings may cross the next boundary; no
agent may infer or auto-submit one.

Derivation is a two-step external handoff. `falsiq derive --case CASE` writes a
canonical request bound to the current ledger head, prompt hash, and response
schema. `falsiq derive --case CASE --submit RESPONSE` validates untrusted output,
stages stable derived artifacts, and atomically coordinates publication with an
expected-head derivation append. The derivation fact commits the exact SHA-256
digest and path set. `falsiq guard --case CASE` then verifies that the rulings
are current and every committed artifact is regular, non-symlinked, present, and
byte-identical before implementation begins. Outcome facts record later
feedback but do not stale an otherwise current brief.

The separate `falsiq-agent` entry point implements a strict one-request,
one-response JSONL process boundary. Replay of an exact recorded request is the
normal path. Live executable adapters are opt-in and require a fixed role-bound
model ID, an allowlisted task or case, a matching subject throughout the request
payload, and a non-CI environment. The evaluation runner itself is replay-only.

## Component map

| Path | Responsibility |
| --- | --- |
| `falsiq/cli.py` | `argparse` plumbing for ledger, attack, ruling, derivation, guard, outcome, and sandbox commands |
| `falsiq/facts.py` | Strict Pydantic v2 schemas for append-only durable facts, ULIDs, timestamps, and safe artifact paths |
| `falsiq/ledger.py` | Git-root discovery, initialization, canonical JSONL validation, crash-recoverable atomic appends, expected-head concurrency, supersession, and derived state |
| `falsiq/constraints.py` | Limits shared across durable, transient, and evaluation contracts |
| `falsiq/attacks.py` | Transient attack schemas, content identities, deterministic selection, round gates, durable materialization, and collision rendering |
| `falsiq/rulings.py` | Deterministic ruling, amendment, re-ruling, and outcome batches |
| `falsiq/derive.py` | Head-bound request construction, deriver-response validation, inert scaffold grammar, brief rendering, publication, digest commitments, locking, and rollback |
| `falsiq/workflow.py` | Installed-skill helpers behind attacker request/preparation/assembly and `falsiq guard` |
| `falsiq/sandbox.py` | Manifest-owned disposable Git worktrees and conservative cleanup |
| `falsiq/agent_runtime.py` | Provider-neutral executable-agent protocol, exact replay, bounded process capture, private transcripts, and live authorization |
| `falsiq/prompts/` | Single packaged source for production attacker and deriver prompts |
| `falsiq/benchmark.py` | Versioned hidden-intent task contracts, salted task identity, and principal leakage checks |
| `falsiq/corpus.py` | Human-approval gates, deterministic holdout selection, redacted manifests, private-first release, access logging, and verified private reads |
| `falsiq/score.py` | Pure recall, waste, discretion, conformance, and paired-bootstrap calculations |
| `falsiq/evaluation.py` | Replay orchestration, role contracts, leakage checks, baseline comparison, isolated builder/judge conformance, and redacted reports |
| `eval/run.py` | Thin replay-evaluation command entry point |
| `eval/prepare_corpus.py` | Operator command for a reviewed public/private corpus release |
| `agents/` | Canonical versioned prompts for production and evaluation roles |
| `skill/` | Self-contained agent orchestration workflow (Claude Code, Cursor, Codex, and generic hosts), bundled production prompts, helper scripts, and executable transcript |
| `tests/` | Unit, CLI, integration, concurrency, failure-injection, portability, golden, prompt, and workflow contract tests |

`falsiq/__main__.py` exposes `python -m falsiq`. The wheel also installs two
console scripts from `pyproject.toml`: `falsiq` for deterministic plumbing and
`falsiq-agent` for the external process boundary. The wheel and `skill/` are
separate deliverables; the skill must work in a target repository with no
Python project or Falsiq source checkout.

## Set up the development environment

Falsiq supports Python 3.11 and newer. Runtime dependencies are deliberately
limited to Pydantic v2 plus the standard library; command parsing uses
`argparse`. Hatchling builds the package. Use the checked-in uv lockfile and do
not introduce another package manager.

```console
uv sync --locked
uv run falsiq --version
uv run python -m falsiq --version
```

Before adding a dependency, check whether the standard library or Pydantic
already covers the need. A new runtime dependency changes the portability and
trust boundary and should be justified explicitly.

The CLI operates on a Git repository, not necessarily this source checkout. For
manual experiments, use a disposable directory so `.falsiq/` test state does not
pollute the project:

```console
TARGET=$(mktemp -d)
git init -q "$TARGET"
cd "$TARGET"
uv run --project /absolute/path/to/falsiq falsiq init
```

The production skill uses a separately installed plain `falsiq` executable,
not `uv run` and not the target repository's interpreter. Keep source-checkout
debug commands distinct from portability tests.

## Make changes with tests

Keep commits small and logically reversible. Each behavior change should land
with its regression or contract tests in the same commit; do not squash
unrelated components together. Use TDD when practical:

1. Add the narrowest test that demonstrates the intended success, boundary, or
   failure behavior.
2. Run it and confirm that it fails for the expected reason.
3. Implement the smallest change that makes it pass.
4. Run the owning test module, then the full suite and static checks.

Examples:

```console
uv run pytest -q tests/test_ledger.py
uv run pytest -q tests/test_derivation.py::test_stale_response_is_rejected_before_publication
uv run pytest -q -x -vv tests/test_evaluation.py
uv run pytest -q
uv run pytest -q --cov=falsiq --cov-branch --cov-report=term-missing
uv run --python 3.11 pytest -q
uv run ruff check .
uv run ruff format --check .
```

There is no configured type checker or numeric coverage gate. Do not imply that
one ran. Coverage should nevertheless stay level or improve, especially on
validation, rollback, and authorization branches. Apply formatting to the files
you changed with `uv run ruff format PATH...`, then repeat the check commands.

Build and inspect the distributable when packaging, entry points, or import
layout changes:

```console
DIST=$(mktemp -d)
uv build --out-dir "$DIST"
unzip -Z1 "$DIST"/*.whl
```

The wheel should contain the `falsiq` package (including `falsiq/prompts/`) and
distribution metadata, not tests, evaluation-only prompts, evaluation corpora,
`.claude/`, `.agents/`, or the skill directory.

### Test by boundary

- Schema or state changes belong in `test_facts.py` and `test_ledger.py`, with
  malformed sequences, supersession, deterministic state, and no-write failure
  cases.
- Attack changes belong in `test_attacks.py` plus the CLI attack tests. Cover
  canonical identity, exact selection, diversity, budget gates, artifact path
  containment, and collision output. Update golden files only for intentional
  rendering changes.
- Ruling and derivation changes need CLI tests, anti-drift checks, stale-head and
  concurrent-publication tests, rollback behavior, and guard-integrity tests.
- Sandbox changes require real temporary Git repositories. Test dirty trees,
  foreign worktrees, manifest corruption, symlinks, concurrent operations, and
  partial Git failures without broadening cleanup authority.
- Agent runtime changes need protocol, timeout, output-limit, process-failure,
  transcript-permission, replay-identity, live-denial, and secret-redaction
  coverage.
- Evaluation changes need strict role contracts, leakage failures, equal-budget
  baselines, deterministic IDs/order, report redaction, workspace containment,
  hidden-test sequencing, and condition-blind judging.
- Corpus changes need human-gate, traversal/symlink, secret-file, split
  determinism, private-first publication, rollback, access-log ordering, and
  hash-verification tests.
- Skill changes need both source-level assertions and the installed-console
  workflow in `test_skill.py`, which exercises a copied skill in a non-Python
  target repository.

Tests commonly use `tmp_path` Git repositories, `monkeypatch.chdir`, `capsys`,
subprocesses, and controlled failure injection. Concurrency tests use real
threads or processes around the relevant lock. Prefer those techniques over
sleep-based timing. Assert not just the error but also the absence of partial
facts, artifacts, transcripts, or cleanup outside the owned root.

## Debugging techniques

Start from the narrowest observable boundary:

- `uv run falsiq log --case CASE` prints canonical durable facts.
- `uv run falsiq state --json --case CASE` shows the deterministic current
  interpretation after supersession.
- Re-run a CLI-focused test with `-vv -s` when captured output is relevant.
- Compare collision and brief render changes with `tests/golden/`; do not edit a
  golden file until the semantic change is understood.
- Reproduce agent protocol failures with the deterministic
  `tests/fixtures/fake_agent.py` or an exact replay transcript. Keep transcripts
  in an owner-private temporary directory and never paste hidden content or
  credentials into logs.
- Use monkeypatched filesystem/Git operations for crash points, then assert the
  durable ledger and stable artifact paths agree after recovery.

Do not repair a failing ledger by editing `ledger.jsonl`, its lock, or its
transaction journal. Reproduce the failure in a temporary repository and fix
the parser, validator, append protocol, or recovery path. Expected CLI failures
should be concise and secret-free; avoid leaking tracebacks, argv, environment
variables, invalid stdout, or child stderr through user-facing errors.

## Invariants and safety boundaries

Treat these as review blockers:

- The ledger is canonical, append-only, globally ordered, and validated as a
  complete sequence. Corrections use supersession; derived state is never
  persisted as a second source of truth.
- User intent and amendment text remain verbatim. Falsiq never silently rewrites
  them and never creates a human ruling.
- Only selected attacks become facts. Attacks require concrete artifacts,
  non-empty settled decisions, and a hate scenario. Consequences are inline
  scenarios of at most 150 whitespace-delimited words.
- Round and interaction limits are executable policy. The skill runs exactly
  five fresh class-specific attackers in parallel per attempted round, stops for
  explicit human rulings, and never runs a third round.
- Durable and derived paths remain case-scoped, relative, regular, and
  non-symlinked where required. Never weaken containment to make a fixture pass.
- Multi-fact operations use expected-head atomic batches. Publication and
  cleanup locks cover the complete state transition, including rollback.
- Derived outputs are disposable but not editable. Regenerate them from the
  ledger. A passing guard proves committed-byte integrity, not the safety or
  correctness of model-authored content.
- Derived pytest-shaped files are inert requirements carriers. Read them fully,
  then write a new repository-native failing test. Never execute, import, copy,
  or merge a derived scaffold as-is.
- Prototype worktrees are one-shot evidence. Sandbox code owns exact paths and
  branches, exposes no push/merge path, preserves dirty work by default, and
  requires explicit `--force` before discarding it.
- Replay and live agent streams are disk-backed and capped at 8 MiB each.
  Transcript directories and corpus private roots fail closed on unsafe modes,
  symlinks, aliases, or unexpected file types.
- Live execution remains separately authorized, role/model/subject bound, and
  disabled in CI. The evaluation harness does not grow a hidden live switch.
- Hidden task bodies, salts, recordings, transcripts, scorer mappings, and
  private reports never enter builder workspaces or public reports. Access to an
  approved holdout is logged before its body is read.
- Corpus schema validation is not human approval. Keep `human_curated: false`
  until every task and fixture passes the documented review; rotate any holdout
  inspected during development.

On platforms without POSIX descriptor modes or directory fsync, retain the
documented best-effort behavior and the remaining exclusive-creation,
regular-file, symlink, and private-root checks. Do not claim POSIX guarantees on
platforms that cannot provide them.

## Keeping docs, prompts, evaluation, and the skill synchronized

Prompt and workflow files are executable contracts, not informal prose.

- Canonical production prompts live only in `falsiq/prompts/` and ship as package
  data. `falsiq attack request` combines them with the Pydantic-generated schema
  and role-bound examples; the derivation request embeds its prompt and schema.
  Do not add mirrors under `agents/` or `skill/`. Run `tests/test_skill.py` and
  `tests/test_derivation.py` after prompt changes.
- Canonical evaluation prompts also live in `agents/`. Keep their frontmatter
  contract version and strict JSON instructions aligned with the Pydantic models
  in `benchmark.py` and `evaluation.py`; run `tests/test_eval_prompts.py` and the
  relevant evaluation protocol tests.
- `skill/SKILL.md` is the canonical skill. `.claude/skills/falsiq` and
  `.agents/skills/falsiq` must remain checked-in `../../skill` directory
  symlinks rather than generated second copies. A skill installed into another
  repository may be a copied directory under either discovery root. The skill
  references its own scripts and prompts only through the tool-agnostic
  `${SKILL_DIR}` convention, which resolves to `${CLAUDE_SKILL_DIR}` under
  Claude Code and to the loaded skill directory under Cursor, Codex, or a
  generic host; keep that convention and its test assertions synchronized.
- Workflow transitions, bypass wording, CLI prerequisites, or human barriers
  require matching changes to `skill/fixtures/workflow_transcript.md` and its
  executable assertions. The only bypass phrase is a case-sensitive standalone
  line whose trimmed content is exactly `skip falsiq`.
- A CLI version change must synchronize `pyproject.toml`,
  `falsiq/__init__.py`, `skill/SKILL.md`, `skill/scripts/require_cli.sh`, README
  installation examples, and version/portability tests.
- Rendering changes may require `tests/golden/collision.md` or
  `tests/golden/implementation_brief.md`. Review the diff as product output; do
  not mechanically bless it.
- Corpus schema or release changes require corresponding updates to
  [`eval/README.md`](eval/README.md), operator scripts, privacy tests, and access
  controls. Smoke data under `tests/fixtures/eval/` is test data, never a
  benchmark candidate or holdout.
- A design change that departs from the original PRD must be explicit in
  `DECISIONS.md`, with the implementation, regression test, and user-facing
  documentation in the same atomic series.

## Good contribution areas

Useful focused contributions include stronger ledger recovery and cross-platform
durability tests; clearer collision rendering without weakening forced choices;
new attack-quality fixtures; sandbox containment and portability; stricter
derivation and guard validation; replay protocol hardening; evaluation leakage
tests; deterministic metrics; corpus review and release tooling; and skill
portability or documentation fixes.

Keep v0 non-goals out of incidental changes: multi-principal rulings,
non-coding-domain workflows, IDE UI, auto-ruling, persistent semantic models,
retroactive ledgers, and issue-tracker integration need an explicit product
decision before implementation.

## Before handing off a change

- Confirm the change is the smallest coherent behavior or documentation block.
- Include success, material edge cases, and at least one failure path where
  applicable.
- Run the narrow tests, full suite, Ruff lint, Ruff format check, and coverage or
  Python 3.11 checks appropriate to the risk.
- Inspect `git diff --check` and the complete diff for generated files, secrets,
  private task content, and unrelated changes.
- Update `DECISIONS.md`, README, eval docs, prompts, bundled references, skill
  transcript, and goldens wherever the contract moved.
- Keep each commit atomic with its tests so it can be reverted or bisected
  independently.
- State honestly which checks were run, what remains unverified, and whether any
  file needs manual review.
