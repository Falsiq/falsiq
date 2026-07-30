# Falsiq implementation state

Updated: 2026-07-29

## Current status

Branch: `feature/falsiq-v1-runtime`

Falsiq v1's runtime and public integration surface are implemented. Existing
schema-v1 ledger bytes remain readable; migration appends a writer-switch marker
and future facts carry schema-v2 prompt, policy, and profile provenance.

Implemented:

- policy-owned review budgets, including `max_rounds = 3` without a schema bump;
- deterministic `brief.json` with digest commitments and stable obligations;
- `contract/` schemas, semantic version, changelog, and byte-stable fixtures;
- strict newline-delimited stdio RPC and external `FALSIQ_STATE_ROOT`;
- outcome attribution by case, attack class, and prompt digest;
- packaged coding/writing domain profiles, tmpdir backend primitives, and four
  acceptance-check renderer strengths;
- Python 3.13+ uv/Hatchling packaging and operator/integration documentation.

Deferred by explicit project decision:

- corpus curation fixes and the official live/replay benchmark run;
- publication of kill-criterion numbers;
- automated prompt optimization, which remains a non-goal.

## Human reviewer instructions

1. Review `contract/` first; it is the downstream compatibility boundary.
2. Verify `SchemaMigrationFact` admission and dual-version serialization in
   `falsiq/facts.py` and `falsiq/ledger.py`.
3. Review `falsiq/rpc.py` for the no-path/no-model/no-network boundary.
4. Inspect prompt/profile/policy provenance on v2 attack append and the
   deterministic `brief.json` renderer.
5. Confirm no private corpus, salt, recording, transcript, or benchmark claim is
   included.

## Next steps

Automated:

- run the full tests and branch coverage on Python 3.13;
- run the full tests on Python 3.14;
- run Ruff check/format and build wheel/sdist with `uv build`;
- run the shared Conductor black-box harness against the contract fixtures.

Manual:

- perform a non-Git writing-profile smoke through a private external state root;
- inspect the golden contract fixture diff as a product/API change;
- curate and human-gate the corpus before any official benchmark run;
- record benchmark evidence and prompt-change decisions in `DECISIONS.md`.
