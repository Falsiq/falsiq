# Demo 2: Resolve a collision with an amendment

This tutorial follows Falsiq's contested path. A boundary reviewer exposes two
observable retry policies, the selector persists that collision, and a human
supplies replacement intent. Because an `amend` ruling changes the active
specification, Falsiq permits one fresh second review round before derivation.

The demo is deterministic and runs offline. Inline Python produces strict JSON
responses so there are no checked-in response fixtures. A production Falsiq
skill must instead use five fresh external reviewers per round and one fresh
external deriver. It must also stop for the human; the scripted amendment below
represents the tutorial user's explicit decision and is never a default an
agent may choose.

## What you'll learn

- how a concrete reviewer candidate becomes a selected collision;
- where the mandatory human stop occurs;
- how an amendment supersedes the original active intent;
- why amendment opens round two and why no third round is allowed;
- how the settled case reaches derivation and the implementation guard.

## Prerequisites

Install the matching `falsiq 0.1.0` console tool outside the target project's
dependencies. You also need Git, POSIX `sh`, and Python 3.11 or newer.

## Run the demo

Copy this whole block into a shell. It works only in the new temporary Git
repository it creates, so its tutorial ruling cannot enter a real ledger.

<!-- demo-test:start -->
```sh
set -eu

DEMO_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/falsiq-amendment.XXXXXX")
TARGET="$DEMO_ROOT/target"
mkdir "$TARGET"
cd "$TARGET"
git init -q

falsiq init >/dev/null
CASE=$(falsiq intent "Add bounded retries to the request helper")

for REVIEWER in boundary consequence prototype conflict omission; do
  falsiq review request --case "$CASE" --reviewer "$REVIEWER" \
    > "$REVIEWER-request.json"
  python3 - "$CASE" "$REVIEWER" > "$REVIEWER-raw.json" <<'PY'
import json
import sys

case_id, reviewer = sys.argv[1:]
candidates = []
if reviewer == "boundary":
    candidates.append({
        "schema_version": 1,
        "klass": "boundary",
        "targets": [case_id],
        "artifact": {
            "type": "input",
            "body": "Choose the observable retry policy.",
            "options": [
                {"key": "retry-all", "body": "Retry every failure twice."},
                {"key": "retry-network", "body": "Retry only network failures twice."},
            ],
        },
        "settles": ["which failures are retried"],
        "silent_settles": ["which failures are retried"],
        "risk_scenario": "Invalid requests are repeated even though they cannot succeed.",
        "render_cost": "trivial",
    })
print(json.dumps({
    "schema_version": 1,
    "case_id": case_id,
    "reviewer": reviewer,
    "candidates": candidates,
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
test "$SELECTED" -eq 1
printf 'round 1 selected reviews: %s\n' "$SELECTED"

REVIEW=$(falsiq review add --file round-1.json)
COLLISION=$(falsiq collide --case "$CASE")
test -f "$COLLISION"

# Production stops here. The next command represents the human's explicit ruling.
falsiq rule "$REVIEW" amend \
  --text "Retry network failures at most twice, but never retry invalid requests." \
  >/dev/null
printf 'human ruling: amend\n'

for REVIEWER in boundary consequence prototype conflict omission; do
  falsiq review request --case "$CASE" --reviewer "$REVIEWER" \
    > "round-2-$REVIEWER-request.json"
  python3 - "$CASE" "$REVIEWER" > "round-2-$REVIEWER-raw.json" <<'PY'
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
    --file "round-2-$REVIEWER-raw.json" > "round-2-$REVIEWER.json"
done

falsiq review assemble --case "$CASE" --round 2 \
  round-2-boundary.json round-2-consequence.json round-2-prototype.json \
  round-2-conflict.json round-2-omission.json > round-2.json
SELECTED=$(python3 -c \
  'import json, sys; print(len(json.load(sys.stdin)["selected"]))' \
  < round-2.json)
test "$SELECTED" -eq 0
printf 'round 2 selected reviews: %s\n' "$SELECTED"

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
round 1 selected reviews: 1
human ruling: amend
round 2 selected reviews: 0
guard: passed
```

Case IDs, review IDs, ruling IDs, and artifact paths vary on every run.

## What happened

1. Only the boundary reviewer proposed a candidate. The other four valid empty
   batches still participated in deterministic assembly.
2. `review add` persisted the selector-approved review, and `collide` rendered
   the forced choices and legal ruling commands. This is the mandatory human
   barrier in the real skill workflow.
3. The explicit `amend` ruling recorded both a ruling and linked replacement
   intent. It did not rewrite the original ledger fact.
4. Because round one had a selected review and an active `amend` verdict, the
   second round was legal. Its empty selection settled the case without adding
   another review fact or manufacturing another human stop.
5. Derivation used the amended ledger head, and `guard` verified the resulting
   brief before implementation could begin.

To adapt this tutorial, replace the initial request, candidate artifact, and
human amendment with your own concrete behavior. Never automate the ruling in
an agent workflow: stop, show the complete collision, and wait for the user's
explicit command or instruction.
