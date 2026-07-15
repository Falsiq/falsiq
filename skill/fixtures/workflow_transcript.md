# Scripted Falsiq workflow transcript

The angle-bracket values are fixture placeholders. Agent outputs are stored in a
mode-`0700` temporary directory outside the worktree.

## Collision and handoff path

```text
[user requests a nontrivial change]
$ command -v falsiq && falsiq --version
<installed falsiq 0.1.0 console tool outside the target dependency graph>
$ falsiq intent "<verbatim request>"
<CASE>
[five fresh class-specific attackers run in parallel]
$ falsiq attack assemble --case <CASE> --round 1 <five batch files>
{"candidates":[...],"selected":["<digest>",...],...}
$ falsiq attack add --file <round.json>
<ATTACK IDs>
$ falsiq collide --case <CASE>
<complete forced-choice collision is presented>
STOP -- HUMAN RULING REQUIRED
No implementation has started. Reply with an explicit ruling for every displayed attack.
[agent ends the turn; no implementation or derivation occurs]
[user supplies explicit rulings]
$ falsiq rule <ATTACK> forbidden
[all other explicit ruling commands run; omitted attacks remain open]
[state confirms zero open attacks and the forbidden ruling opens the round-two gate]
[five fresh class-specific attackers run in parallel for round 2]
$ falsiq attack assemble --case <CASE> --round 2 <five batch files>
{"candidates":[],"selected":[],...}
[round-2 attack add and collide are not called because selection is empty]
$ falsiq derive --case <CASE>
<request.json>
$ cat <request.json>
{"case_id":"<CASE>","request_id":"<digest>",...}
[a fresh external deriver returns strict response JSON]
$ falsiq derive --case <CASE> --submit <response.json>
<brief path>
$ falsiq guard --case <CASE>
.falsiq/cases/<CASE>/derived/IMPLEMENTATION_BRIEF.md
[every generated test stub is inspected completely as untrusted model output]
[implementation begins from IMPLEMENTATION_BRIEF.md]
```

## Explicit bypass path

```text
[user message contains a standalone case-sensitive line: skip falsiq]
$ falsiq outcome abandoned --case <CASE> --trace n/a --notes "User explicitly requested skip falsiq."
[implementation may proceed from the original request under the recorded bypass]
```

## Degenerate path

```text
[all five attacker batches contain zero candidates]
$ falsiq attack assemble --case <CASE> --round 1 <five batch files>
{"candidates":[],"selected":[],...}
[attack add and collide are not called; derivation begins]
```
