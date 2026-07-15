# Benchmark corpus release

Corpus drafts and their fixtures stay outside this repository until a human has
reviewed every task. Passing schema validation is necessary, but it is not
approval. Set `human_curated` to `true` only after the reviewer has checked that:

- there are exactly ten unique tasks in each of the synthetic, mined, and
  control strata;
- the public prompt does not reveal a latent requirement or discriminator;
- each latent requirement and severity is concrete and testable;
- mined tasks trace to primary issue, review, fix-commit, and license evidence;
- controls are fully specified and contain no hidden decision; and
- every referenced fixture is deterministic, offline, sufficient, and free of
  credentials, symbolic links, special files, and answer-revealing content.

After approval, `prepare_corpus.py` applies the precommitted seeded 3/3/4
holdout split. It writes twenty complete development tasks and their fixtures to
an explicit public output. It writes the ten complete holdout tasks and fixtures
only to an explicit owner-private output outside the repository. The public
output also contains `holdout-manifest.json`, whose entries are limited to task
IDs, strata, and salted hashes; it contains no prompts or latent requirements.
The public `build_holdout_manifest` API also accepts only the full approved
10/10/10 corpus and derives this split itself; callers cannot bless an arbitrary
3/3/4 selection with the same seed metadata.

The tool enforces that the reviewed source, private output, seed, and salt are
outside the repository. Put the seed and salt in separate owner-only files;
their contents are never accepted as command-line arguments and are never
printed. Both output parents must already exist, and both target directories
must be absent. First validate the redacted plan:

```console
chmod 600 /owner-private/falsiq-seed /owner-private/falsiq-salt
uv run python eval/prepare_corpus.py \
  --source /reviewed/falsiq-corpus \
  --public-output "$PWD/eval/corpus-v0" \
  --private-output /owner-private/falsiq-corpus-v0-holdout \
  --corpus-version v0-approved-1 \
  --seed-file /owner-private/falsiq-seed \
  --salt-file /owner-private/falsiq-salt \
  --dry-run
```

Have the reviewer confirm the plan, then repeat without `--dry-run`. All source
data is validated and both trees are staged beside their destinations before
publication. The private directory is renamed first; the public directory and
manifest are the final commit point. A handled publication error rolls both
back. A process or machine crash between the two renames can leave a private
directory without a public release, but cannot leave a public release that
preceded its private counterpart. Inspect such private state before retrying;
the tool deliberately refuses to overwrite any existing output.

Pass `PRIVATE_OUTPUT/tasks` as the private task store. Every attempted read of a
manifest-listed task uses its owner-private access log. Official heldout runs use
the dedicated manifest mode; repeat `--holdout-task-id` for each selected task:

```console
uv run python eval/run.py \
  --holdout-task-id synthetic_01 \
  --holdout-manifest "$PWD/eval/corpus-v0/holdout-manifest.json" \
  --private-task-store /owner-private/falsiq-corpus-v0-holdout/tasks \
  --holdout-salt-file /owner-private/falsiq-salt \
  --holdout-access-log /owner-private/falsiq-corpus-v0-access.jsonl \
  --holdout-actor "$USER" \
  --holdout-purpose "official v0 scoring" \
  --recordings /owner-private/falsiq-recordings \
  --private-run-dir /owner-private/falsiq-run \
  --reports "$PWD/eval/reports-v0"
```

The salt file must be an owner-only regular file. The manifest and task store
must not be symbolic links, and the access log must have an existing real
parent directory. Membership is checked before an access event is written.
After membership succeeds, the runner must durably append the event before it
reads the task body; if logging fails, the body is not read. The body is then
checked against its canonical salted hash. Consequently an unknown ID does not
create an access event, while a missing, unsafe, or hash-mismatched task body
burns freshness and does create one.

The path-oriented `eval/run.py --task` interface is development-only and must
never receive a private holdout path. The two task-source modes and their inputs
cannot be mixed. If a holdout is inspected to guide a fix, rotate it before
future official scoring. Do not report heldout success thresholds until human
approval and an access-logged official run have actually occurred.

## End-to-end builder handoffs

The Falsiq conformance condition does not hand builders a lossy conversation
summary. It deterministically renders the original public request, active
verbatim amendment, complete elicited ruling evidence, expressible forbidden
acceptance-test obligations, and explicitly licensed `dont_care` discretion.
The renderer accepts only the public task plus public attack and ruling
contracts; hidden requirements and scorer mappings remain available only to
principal-simulator, scorer, and judge roles. Builder request IDs and blinded
candidate labels keep their existing deterministic derivation.
