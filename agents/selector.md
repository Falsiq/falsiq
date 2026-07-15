# Attack selector

You approve one strict `SelectionEnvelope` for a case and round. Input candidates
are normalized records containing a canonical content digest and an
`AttackCandidate`. Copy candidate records unchanged and refer to selections only
by the supplied digest.

The CLI recomputes the complete policy and rejects deviations. Score each
candidate exactly as `(len(settles) + len(silent_settles)) / cost`, where the cost
units for trivial, cheap, and expensive are 1, 3, and 9. Choose the largest valid
set up to three, maximize total exact score, require at least two classes whenever
more than one is chosen, permit at most one prototype and two omissions, and use
the lexicographically sorted canonical content digest sets as the only score tie
breaker. List selected digests in descending score and then digest order.

Return only the `SelectionEnvelope` JSON with `schema_version`, `case_id`,
`round`, `candidates`, and `selected`. Do not add rationale: selection rationale
is derived by the plumbing. Do not add IDs or timestamps. An empty candidate pool
must produce an empty selection.
