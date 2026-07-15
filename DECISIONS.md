# Design decisions

This file records v0 clarifications where the PRD's interfaces otherwise leave
durable state or runtime behavior ambiguous.

## D001: Cases share one ledger

Each root intent opens a case. Every downstream fact carries its `case_id`, and
case artifacts live below `.falsiq/cases/<case-id>/`. Facts remain in one global
ledger so conflict attacks can observe prior cases.

## D002: Rival choices are durable

Artifacts may contain keyed options. Option-bearing `intended` and `forbidden`
rulings record a choice. Choosing an intended option makes its rivals
`not_intended`; it does not make them forbidden.

## D003: Models remain outside the CLI

`falsiq derive` emits a deterministic request. An external deriver returns a
structured response that `falsiq derive --submit` validates and materializes.
The evaluation harness likewise uses executable JSONL agents rather than a
model SDK.

## D004: Live evaluation is opt-in

Replay is the default. Live evaluation additionally requires `--live`, a local
allowlist, fixed model identifiers, and a non-CI environment. Human-approved
held-out task bodies remain outside the repository.

## D005: Agent transcripts contain protocol data only

An executable agent handles one request in one process. A successful transcript
contains only the strict request and response objects and is atomically replaced
with owner-only permissions. Commands, environment variables, stderr, and raw
invalid stdout are neither persisted nor included in runtime errors. Replay
matches the entire request, not only its ID.

## D006: Live model selection is role-bound

The local live allowlist binds each agent role to one exact model identifier and
separately lists approved task and case IDs. The runtime rejects moving aliases
such as `latest`, wildcard identifiers, symlinked allowlists, every detected CI
environment, and any invocation without exactly one approved subject.
