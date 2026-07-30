# Falsiq v1 operations

## Install and verify

Use Python 3.13 or newer and the checked-in uv lock:

```console
uv sync --locked
uv run --python 3.13 falsiq --version
uv run --python 3.13 pytest -q
```

## State placement and migration

Without an override, Falsiq discovers a Git worktree and uses `.falsiq/`. For a
non-Git or multi-workspace run, create a private state directory and export its
absolute path:

```console
mkdir -m 700 /absolute/path/to/falsiq-state
export FALSIQ_STATE_ROOT=/absolute/path/to/falsiq-state
falsiq init
```

The target must already exist and must not be a symlink. Preview then apply the
v2 writer switch:

```console
falsiq migrate --to 2
falsiq migrate --to 2 --apply
```

Back up `ledger.jsonl` before manual disaster recovery. Never edit a fact in
place. Derived case artifacts may be regenerated from the ledger.

## Policy and profiles

The default policy is `max_rounds = 2`. To change the annoyance budget, pass a
bounded regular TOML file to `review add`:

```toml
max_rounds = 3
```

Packaged `coding` and `writing` profiles select Git-worktree and temporary
render backends respectively. External profiles are accepted only by explicit
CLI path and are digest-pinned in the opening intent.

## RPC

Start `falsiq rpc` with the desired `FALSIQ_STATE_ROOT`. Send one JSON object per
line. Keep request IDs unique in the caller. An error response does not stop the
server. Restarting is safe because mutations use append locks and expected-head
checks.

## Incident checks

- Run `falsiq state --json` to prove the ledger is readable.
- Run `falsiq guard --case CASE_ID` before implementation handoff.
- Treat a digest mismatch as artifact tampering or corruption; re-derive.
- Treat a ledger integrity error as a stop condition; preserve the exact bytes
  for review rather than attempting automatic repair.
