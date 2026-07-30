# Falsiq implementation state

Updated: 2026-07-30

## Current status

Repository status: v1 implementation is merged on `main`.

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
- high-level architecture and five-reviewer SVGs linked from the public
  documentation;
- Python 3.13+ uv/Hatchling packaging and operator/integration documentation.

Deferred by explicit project decision:

- corpus curation fixes and the official live/replay benchmark run;
- publication of kill-criterion numbers;
- automated prompt optimization, which remains a non-goal.

## Verification

Verified locally on 2026-07-30 with uv-managed CPython 3.13.5 and 3.14.3:

- Python 3.13: 525 tests passed with 84% total branch-aware coverage;
- Python 3.14: 525 tests passed;
- `ruff check .` and `ruff format --check .`: passed;
- `uv build`: wheel and source distribution built successfully;
- both SVGs parsed as XML and rendered without clipping at an 850-pixel
  documentation width;
- the representative brief fixture is digest-pinned in the Conductor
  compatibility suite;
- a non-Git writing-profile flow through a private external state root passed.

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

- keep the Python 3.13/3.14, Ruff, build, and contract-compatibility matrix in CI;
- add consumer-owned negative fixtures when the public contract changes;
- run the official replay/live benchmark only after its corpus is approved.

Manual:

- inspect the golden contract fixture diff as a product/API change;
- curate and human-gate the corpus before any official benchmark run;
- record benchmark evidence and prompt-change decisions in `DECISIONS.md`.
