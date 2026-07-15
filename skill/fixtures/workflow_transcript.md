# Scripted Falsiq workflow transcript

The angle-bracket values are fixture placeholders. Agent outputs are stored in a
mode-`0700` temporary directory outside the worktree.

## Collision and handoff path

```text
[user requests a nontrivial change]
$ falsiq intent "<verbatim request>"
<CASE>
[five fresh class-specific attackers run in parallel]
$ python <skill>/scripts/assemble_round.py --case <CASE> --round 1 <five batch files>
{"candidates":[...],"selected":["<digest>",...],...}
$ falsiq attack add --file <round.json>
<ATTACK IDs>
$ falsiq collide --case <CASE>
<complete forced-choice collision is presented>
STOP -- HUMAN RULING REQUIRED
[agent ends the turn; no implementation or derivation occurs]
[user supplies explicit rulings]
$ falsiq rule <ATTACK> forbidden
[all other explicit ruling commands run; omitted attacks remain open]
[state confirms zero open attacks and the round-two gate does not pass]
$ falsiq derive --case <CASE>
<request.json>
$ cat <request.json>
{"case_id":"<CASE>","request_id":"<digest>",...}
[a fresh external deriver returns strict response JSON]
$ falsiq derive --case <CASE> --submit <response.json>
<brief path>
$ python <skill>/scripts/guard_open_attacks.py --case <CASE>
.falsiq/cases/<CASE>/derived/IMPLEMENTATION_BRIEF.md
[implementation begins from IMPLEMENTATION_BRIEF.md]
```

## Explicit bypass path

```text
[user says the exact phrase: skip falsiq]
$ falsiq outcome abandoned --case <CASE> --trace n/a --notes "User explicitly requested skip falsiq."
[implementation may proceed from the original request under the recorded bypass]
```

## Degenerate path

```text
[all five attacker batches contain zero candidates]
$ python <skill>/scripts/assemble_round.py --case <CASE> --round 1 <five batch files>
{"candidates":[],"selected":[],...}
[attack add and collide are not called; derivation begins]
```
