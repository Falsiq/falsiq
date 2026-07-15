# Implementation brief

- Case: `00000000010000000000000001`
- Ledger head: `00000000050000000000000005`
- Request: `1e135545b4565b39b2e231c705f21f4c8fa33e33b9332f570fc46aa2424605ae`

## Intent (verbatim)

### Intent `00000000010000000000000001`

```text
  Add retries <without> retrying 4xx.
```

## Rulings

| Ruling | Attack | Class | Verdict | Choice |
| --- | --- | --- | --- | --- |
| `00000000030000000000000003` | `00000000020000000000000002` | boundary | forbidden | — |
| `00000000050000000000000005` | `00000000040000000000000004` | omission | dont_care | — |

## Ruling evidence (ledger)

### Attack `00000000020000000000000002` → ruling `00000000030000000000000003`

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

#### Hate scenario

```text
Bad outcome 2
```

### Attack `00000000040000000000000004` → ruling `00000000050000000000000005`

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

#### Hate scenario

```text
Bad outcome 4
```

## Forbidden → test stubs

- Ruling `00000000030000000000000003` (attack `00000000020000000000000002`): [test_forbidden_retry_on_4xx.py](tests/test_forbidden_retry_on_4xx.py)

## Agent discretion

- **Choose the exact retry log wording&#46;** — The principal explicitly ruled this don&#x27;t&#45;care&#46;
