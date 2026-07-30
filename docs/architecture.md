# Falsiq v1 architecture

Falsiq owns intent elicitation, not execution. It records verbatim intent,
selected adversarial artifacts, explicit human rulings, derived obligation
commitments, and outcome attribution. It does not store plans, tool traces,
agent memory, usage history, or implementation state.

## Boundaries

1. External reviewers receive transient role-specific requests.
2. Falsiq verifies and selects candidates deterministically.
3. Selected attacks and one complete review-round provenance fact append
   atomically.
4. A human records rulings.
5. An external deriver may contribute only inert verification stubs.
6. Falsiq renders Markdown and `brief.json` from durable facts and commits both
   digests in a derivation fact.
7. A caller pins obligation IDs and reports implementation outcomes later.

Durable facts are canonical JSONL under the configured state root. Schema-v1
facts remain valid. One append-only migration marker switches future writes to
schema v2. Policy, profile, and prompt content digests make the interpretation
of each v2 round reproducible.

## Runtime surfaces

- `falsiq` is deterministic CLI plumbing.
- `falsiq rpc` is a long-lived, newline-delimited stdio adapter over the same
  domain functions.
- `falsiq-agent` is the separate one-shot external-agent boundary.
- `contract/` is the public cross-component API.

The only runtime dependency is Pydantic v2; all storage, hashing, TOML parsing,
locking, RPC transport, and report aggregation use the Python standard library.
