# Implementation brief

- Case: `00000000010000000000000001`
- Ledger head: `00000000050000000000000005`
- Request: `c0d1b0650b3a90b26f79de414ff35ff63738471c735c491a05fa7ca512f6be1a`

## Intent (verbatim)

### Intent `00000000010000000000000001`

```text
  Add retries <without> retrying 4xx.
```

## Rulings

| Ruling | Review | Class | Verdict | Choice |
| --- | --- | --- | --- | --- |
| `00000000030000000000000003` | `00000000020000000000000002` | boundary | forbidden | — |
| `00000000050000000000000005` | `00000000040000000000000004` | omission | dont_care | — |

## Ruling evidence (ledger)

### Review `00000000020000000000000002` → ruling `00000000030000000000000003`

- Class: `boundary`
- Verdict: `forbidden`
- Choice: —
- Targets:
  - `00000000010000000000000001`
- Settles:
  - <code>retryable status behavior</code>

#### Artifact (`scenario`)

```text
Concrete scenario 2
```

#### Risk scenario

```text
Bad outcome 2
```

### Review `00000000040000000000000004` → ruling `00000000050000000000000005`

- Class: `omission`
- Verdict: `dont_care`
- Choice: —
- Targets:
  - `00000000010000000000000001`
- Settles:
  - <code>retry log wording</code>

#### Artifact (`scenario`)

```text
Concrete scenario 4
```

#### Risk scenario

```text
Bad outcome 4
```

## Forbidden → test stubs

- Ruling `00000000030000000000000003` (review `00000000020000000000000002`): [test_forbidden_retry_on_4xx.py](tests/test_forbidden_retry_on_4xx.py)

## Agent discretion

- **retry log wording** — explicitly licensed by active `dont_care` ruling `00000000050000000000000005` for review `00000000040000000000000004`.
