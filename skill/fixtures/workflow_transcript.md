# Scripted Falsiq workflow transcript

The angle-bracket values are fixture placeholders. Agent outputs are stored in a
mode-`0700` temporary directory outside the worktree.

## Collision and handoff path

```text
[user explicitly requests a nontrivial change with falsiq]
$ command -v falsiq && falsiq --version
<installed falsiq 0.1.0 console tool outside the target dependency graph>
$ falsiq intent "<verbatim request>"
<CASE>
$ falsiq review request --case <CASE> --reviewer <each class>
<five self-contained requests with instructions, JSON Schema, and examples>
[five fresh class-specific reviewers run in parallel]
$ falsiq review prepare --case <CASE> --reviewer <each class> --file <raw response>
<five validated batches; malformed output becomes that class's empty batch>
[any degraded role warning is disclosed with the round result]
$ falsiq review assemble --case <CASE> --round 1 <five batch files>
{"candidates":[...],"selected":["<digest>",...],...}
$ falsiq review add --file <round.json>
<REVIEW IDs>
$ falsiq collide --case <CASE>
<complete forced-choice collision is presented>
STOP -- HUMAN RULING REQUIRED
No implementation has started. Reply with an explicit ruling for every displayed review.
[agent ends the turn; no implementation or derivation occurs]
[user supplies explicit rulings]
$ falsiq rule <REVIEW> forbidden
[all other explicit ruling commands run; omitted reviews remain open]
[state confirms zero open reviews and the forbidden ruling opens the round-two gate]
$ falsiq review request --case <CASE> --reviewer <each class>
[five fresh class-specific reviewers run in parallel for round 2]
$ falsiq review prepare --case <CASE> --reviewer <each class> --file <raw response>
$ falsiq review assemble --case <CASE> --round 2 <five batch files>
{"candidates":[],"selected":[],...}
[round-2 review add and collide are not called because selection is empty]
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
[all five reviewer batches contain zero candidates]
$ falsiq review request --case <CASE> --reviewer <each class>
$ falsiq review prepare --case <CASE> --reviewer <each class> --file <raw response>
$ falsiq review assemble --case <CASE> --round 1 <five batch files>
{"candidates":[],"selected":[],...}
[review add and collide are not called; derivation begins]
```
