# Falsiq elicitation contract

This directory is the complete public integration boundary. Consumers may copy
the JSON Schemas and fixtures, but must not import Falsiq's Python internals.

`VERSION` uses `elicitation-contract/<semver>`. Additive fields require a minor
version bump. Removing a field or changing its meaning requires a major bump.
Golden fixtures are intentionally byte-stable and tested as downstream
compatibility canaries.

The RPC transport is newline-delimited JSON over standard input/output. Each
request receives exactly one response. An `ok: false` response is scoped to that
line; the process continues serving later requests.
