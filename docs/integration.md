# Falsiq integration guide

Consumers should copy and validate [`../contract`](../contract), not import the
`falsiq` package. Pin `contract/VERSION` and run the copied golden fixtures in
the consumer's conformance suite.

## Black-box process contract

Launch `falsiq rpc` as a child process with a private existing
`FALSIQ_STATE_ROOT`. Write compact JSON requests terminated by `\n`, then read
exactly one response line. Supported operations are `state`, `brief`, `intent`,
`attack.assemble`, `rule`, `derive.request`, `derive.submit`, and `outcome`.

Requests have `id`, `op`, and `params`. Responses echo `id` and contain either
`{"ok":true,"result":...}` or
`{"ok":false,"error":{"code":"...","message":"..."}}`.

No RPC operation accepts an arbitrary filesystem path. Reviewer batches and
deriver responses are passed as structured JSON. Falsiq never starts an agent
or model and never opens a network listener.

## Obligation handoff

After the human closes all selected attacks and an external derivation response
is admitted, request `brief` or run `falsiq brief --case CASE --json`. A caller
should persist:

- `contract_version`;
- `case_id` and `ledger_head`;
- every `obligation_id` it claims to satisfy;
- unresolved `open_ambiguities`;
- prompt, policy, profile, and deriver provenance.

Falsiq cannot prevent obligation laundering. The downstream planner/executor
must prove that its plan covers every pinned required and forbidden obligation.
Later rework should be sent through `outcome` so Falsiq can attribute misses
without absorbing run history.
