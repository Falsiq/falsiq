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

Pass `PRIVATE_OUTPUT/tasks` as the `store` argument to
`read_private_holdout_task`; every attempted read must use its owner-private
access log. The path-oriented `eval/run.py --task` interface is development-only
and must never receive a private holdout path; official holdout orchestration
must load each task through the logged API and pass the verified in-memory task
to `run_evaluation`. Hardening the development CLI with a dedicated manifest
mode is separate work. If a holdout is inspected to guide a fix, rotate it
before future official scoring. Do not report heldout success thresholds until
human approval and an access-logged official run have actually occurred.
