# Demo 1: From precise intent to a guarded handoff

This tutorial follows Falsiq's valid no-review path. Five reviewer responses are
still requested and validated, but every reviewer returns an empty candidate
batch because the example intent is already precise. The selector therefore
has nothing to persist, and the case proceeds directly to derivation and the
implementation guard.

The demo is a deterministic teaching replay. In production, the Falsiq skill
must obtain the five responses from five fresh external reviewers and the
derivation from a fresh external deriver. The inline Python below stands in for
those model responses only so the walkthrough can run offline without checked-in
response fixtures.

## What you'll learn

- how verbatim intent becomes a durable case;
- why an empty selection is a successful result rather than an error;
- when to skip `review add` and `collide`;
- how an external derivation response becomes a guarded implementation brief.

## Prerequisites

Install the matching `falsiq 0.1.0` console tool outside the target project's
dependencies. You also need Git, POSIX `sh`, and Python 3.11 or newer.

## Run the demo

Copy this whole block into a shell. It creates a new temporary Git repository,
so rerunning it opens a separate ledger and cannot alter an existing project.

<!-- demo-test:start -->
```sh
set -eu

DEMO_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/falsiq-no-review.XXXXXX")
TARGET="$DEMO_ROOT/target"
mkdir "$TARGET"
cd "$TARGET"
git init -q

falsiq init >/dev/null
CASE=$(falsiq intent "Add a health command that prints exactly: ok")

for REVIEWER in boundary consequence prototype conflict omission; do
  falsiq review request --case "$CASE" --reviewer "$REVIEWER" \
    > "$REVIEWER-request.json"
  python3 - "$CASE" "$REVIEWER" > "$REVIEWER-raw.json" <<'PY'
import json
import sys

case_id, reviewer = sys.argv[1:]
print(json.dumps({
    "schema_version": 1,
    "case_id": case_id,
    "reviewer": reviewer,
    "candidates": [],
}))
PY
  falsiq review prepare --case "$CASE" --reviewer "$REVIEWER" \
    --file "$REVIEWER-raw.json" > "$REVIEWER.json"
done

falsiq review assemble --case "$CASE" --round 1 \
  boundary.json consequence.json prototype.json conflict.json omission.json \
  > round-1.json
SELECTED=$(python3 -c \
  'import json, sys; print(len(json.load(sys.stdin)["selected"]))' \
  < round-1.json)
test "$SELECTED" -eq 0
printf 'round 1 selected reviews: %s\n' "$SELECTED"

REQUEST=$(falsiq derive --case "$CASE")
python3 - "$REQUEST" > deriver-response.json <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    request = json.load(stream)
print(json.dumps({
    "schema_version": 1,
    "request_id": request["request_id"],
    "case_id": request["case_id"],
    "ledger_head": request["ledger_head"],
    "forbidden_tests": [],
}))
PY

falsiq derive --case "$CASE" --submit deriver-response.json >/dev/null
BRIEF=$(falsiq guard --case "$CASE")
test -f "$BRIEF"
printf 'guard: passed\n'
```
<!-- demo-test:end -->

The stable output is:

```console
round 1 selected reviews: 0
guard: passed
```

The generated case IDs and artifact paths intentionally vary on every run.

## What happened

1. `falsiq intent` preserved the request exactly and returned its case ID.
2. Each reviewer request carried the current state, role prompt, response
   schema, and examples. Each empty response then passed strict preparation.
3. Assembly produced an empty `selected` list. The demo deliberately did not
   call `review add` or `collide`, because there was no human choice to record.
4. `derive` emitted a self-contained request. The inline response copied its
   three identity fields and proposed no forbidden tests because the case had
   no forbidden rulings.
5. Submission published the brief, and `guard` verified that the ledger and
   derived artifact commitments still matched.

Guard success is the end of Falsiq's pre-implementation handoff. A coding agent
would now read the brief, write repository-native tests, implement the change,
and later record an `accepted` or `rework` outcome based on what actually
happened.
