# Implementation brief

- Case: `00000000010000000000000001`
- Ledger head: `00000000050000000000000005`
- Request: `5106acdd492b871f47359bc42f9dab0ff3b9b9f1da1546b92cc45a378f389553`

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

## Forbidden → test stubs

- Ruling `00000000030000000000000003` (attack `00000000020000000000000002`): [test_forbidden_retry_on_4xx.py](tests/test_forbidden_retry_on_4xx.py)

## Agent discretion

- **Choose the exact retry log wording&#46;** — The principal explicitly ruled this don&#x27;t&#45;care&#46;
