from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from . import __version__
from .attacks import (
    RoundGateError,
    SelectionEnvelope,
    append_attack_round,
    write_collision_file,
)
from .derive import (
    DerivationError,
    DeriverResponse,
    build_derivation_request,
    submit_derivation,
    write_derivation_request,
)
from .facts import (
    AttackFact,
    DerivationFact,
    IntentFact,
    ReviewRoundFact,
    RulingFact,
    SchemaMigrationFact,
    new_ulid,
    utc_timestamp,
)
from .ledger import FalsiqError, Ledger, LedgerValidationError
from .outcomes import build_outcomes_report
from .policy import PolicyError, load_policy, validate_round
from .profiles import ProfileError, load_profile
from .prompt_assets import production_prompt_digests
from .review_language import neutralize_review_state
from .rpc import serve as serve_rpc
from .rulings import RulingCommandError, build_outcome, build_ruling_batch
from .sandbox import SandboxError, create_sandbox, reap_sandboxes, sandbox_json
from .workflow import (
    REVIEW_CLASSES,
    assemble_attack_round,
    build_review_request,
    canonical_review_request_json,
    canonical_selection_json,
    prepare_review_batch,
    ready_brief,
)


def _init_command(_args: argparse.Namespace) -> int:
    ledger = Ledger.initialize()
    print(f"Initialized {ledger.state_dir}")
    return 0


def _intent_command(args: argparse.Namespace) -> int:
    ledger = Ledger.open()
    fact_id = new_ulid()
    schema_version = ledger.write_schema_version()
    profile_name: str | None = None
    profile_digest: str | None = None
    if schema_version == 2:
        profile = load_profile(args.profile, path=args.profile_file)
        profile_name = profile.profile.name
        profile_digest = profile.digest
    fact = IntentFact(
        schema_version=schema_version,
        id=fact_id,
        ts=utc_timestamp(),
        case_id=fact_id,
        text=args.text,
        source="user",
        profile_name=profile_name,
        profile_digest=profile_digest,
    )
    ledger.append(fact)
    print(fact.id)
    return 0


def _log_command(args: argparse.Namespace) -> int:
    ledger = Ledger.open()
    kind = "attack" if args.kind == "review" else args.kind
    for fact in ledger.log(kind=kind, case_id=args.case_id):
        print(
            json.dumps(
                neutralize_review_state(fact.model_dump(mode="json")),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    return 0


def _render_case(case: dict[str, object]) -> list[str]:
    lines = [f"Case {case['case_id']}"]
    intents = case["intents"]
    if isinstance(intents, list):
        for intent in intents:
            if isinstance(intent, dict):
                lines.append(f"Intent: {intent['text']}")
    rulings = case["rulings"]
    open_reviews = case["open_reviews"]
    lines.append(f"Rulings: {len(rulings) if isinstance(rulings, list) else 0}")
    if isinstance(rulings, list):
        for ruling in rulings:
            if not isinstance(ruling, dict):
                continue
            ruling_id = ruling.get("id")
            verdict = ruling.get("verdict")
            age_facts = ruling.get("age_facts")
            if not isinstance(ruling_id, str) or not isinstance(verdict, str):
                continue
            if not isinstance(age_facts, int):
                continue
            noun = "fact" if age_facts == 1 else "facts"
            lines.append(f"Ruling {ruling_id}: {verdict} ({age_facts} later case {noun})")
    lines.append(f"Open reviews: {len(open_reviews) if isinstance(open_reviews, list) else 0}")
    return lines


def _render_state(state: dict[str, object]) -> str:
    if "cases" in state:
        cases = state["cases"]
        if not isinstance(cases, list) or not cases:
            return "No cases."
        blocks = ["\n".join(_render_case(case)) for case in cases if isinstance(case, dict)]
        return "\n\n".join(blocks)
    return "\n".join(_render_case(state))


def _state_command(args: argparse.Namespace) -> int:
    state = neutralize_review_state(Ledger.open().state(args.case_id))
    if args.json:
        print(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(_render_state(state))
    return 0


def _review_add_command(args: argparse.Namespace) -> int:
    envelope = SelectionEnvelope.model_validate_json(args.file.read_bytes())
    ledger = Ledger.open()
    facts = ledger.read()
    case_exists = any(
        isinstance(fact, IntentFact) and fact.source == "user" and fact.id == envelope.case_id
        for fact in facts
    )
    if not case_exists:
        raise LedgerValidationError(f"unknown case: {envelope.case_id}")
    ledger_head = facts[-1].id if facts else None
    existing_attacks = [
        fact for fact in facts if isinstance(fact, AttackFact) and fact.case_id == envelope.case_id
    ]
    active_rulings: dict[str, RulingFact] = {}
    for fact in facts:
        if isinstance(fact, RulingFact) and fact.case_id == envelope.case_id:
            active_rulings[fact.attack_id] = fact
    schema_version = ledger.write_schema_version()
    existing_rounds: tuple[int, ...] = ()
    max_rounds = 2
    prompt_versions: dict[str, str] | None = None
    policy_digest: str | None = None
    profile_name: str | None = None
    profile_digest: str | None = None
    if schema_version == 2:
        policy = load_policy(args.policy)
        validate_round(envelope.round, policy.policy)
        max_rounds = policy.policy.max_rounds
        policy_digest = policy.digest
        prompt_versions = production_prompt_digests()
        existing_rounds = tuple(
            fact.round
            for fact in facts
            if isinstance(fact, ReviewRoundFact) and fact.case_id == envelope.case_id
        )
        intent = next(
            (
                fact
                for fact in facts
                if isinstance(fact, IntentFact)
                and fact.case_id == envelope.case_id
                and fact.source == "user"
            ),
            None,
        )
        if intent is None or intent.profile_name is None or intent.profile_digest is None:
            raise LedgerValidationError(
                f"case {envelope.case_id} has no v2 domain-profile provenance"
            )
        profile_name = intent.profile_name
        profile_digest = intent.profile_digest
    appended = append_attack_round(
        envelope,
        existing_attacks=existing_attacks,
        existing_rounds=existing_rounds,
        active_rulings=active_rulings,
        append_batch=lambda batch: ledger.append_batch(batch, expected_head=ledger_head),
        schema_version=schema_version,
        max_rounds=max_rounds,
        prompt_versions=prompt_versions,
        policy_digest=policy_digest,
        profile_name=profile_name,
        profile_digest=profile_digest,
    )
    for fact in appended:
        print(fact.id)
    return 0


def _review_assemble_command(args: argparse.Namespace) -> int:
    envelope = assemble_attack_round(args.case_id, args.round_number, args.batches)
    print(canonical_selection_json(envelope))
    return 0


def _review_request_command(args: argparse.Namespace) -> int:
    request = build_review_request(Ledger.open(), args.case_id, args.reviewer)
    print(canonical_review_request_json(request))
    return 0


def _review_prepare_command(args: argparse.Namespace) -> int:
    batch, degraded = prepare_review_batch(args.case_id, args.reviewer, args.file)
    if degraded:
        print(
            f"warning: invalid {args.reviewer} reviewer output was replaced by an empty batch",
            file=sys.stderr,
        )
    print(batch.model_dump_json())
    return 0


def _collide_command(args: argparse.Namespace) -> int:
    ledger = Ledger.open()
    state = ledger.state(args.case_id)
    open_values = state.get("open_attacks")
    if not isinstance(open_values, list) or not open_values:
        raise LedgerValidationError(f"case {args.case_id} has no open reviews")
    attacks = [AttackFact.model_validate(value) for value in open_values]
    path = write_collision_file(ledger.root, args.case_id, attacks)
    print(path)
    return 0


def _rule_command(args: argparse.Namespace) -> int:
    ledger = Ledger.open()
    facts = ledger.read()
    batch = build_ruling_batch(
        facts,
        attack_id=args.review_id,
        verdict=args.verdict,
        choice=args.choice,
        amendment_text=args.text,
        intent_id=args.intent_id,
    )
    ledger_head = facts[-1].id if facts else None
    appended = ledger.append_batch(batch, expected_head=ledger_head)
    for fact in appended:
        print(fact.id)
    return 0


def _outcome_command(args: argparse.Namespace) -> int:
    ledger = Ledger.open()
    facts = ledger.read()
    outcome = build_outcome(
        facts,
        case_id=args.case_id,
        otype=args.otype,
        trace=args.trace,
        attack_id=args.review_id,
        notes=args.notes,
        missable_class=args.missable_class,
        prompt_version=args.prompt_version,
    )
    ledger_head = facts[-1].id if facts else None
    appended = ledger.append_batch([outcome], expected_head=ledger_head)
    print(appended[0].id)
    return 0


def _sandbox_new_command(args: argparse.Namespace) -> int:
    sandbox = create_sandbox(Path.cwd(), args.review_id)
    print(sandbox_json(sandbox))
    return 0


def _sandbox_reap_command(args: argparse.Namespace) -> int:
    result = reap_sandboxes(Path.cwd(), force=args.force)
    for attack_id in result.reaped:
        print(f"reaped {attack_id}")
    for attack_id, error in sorted(result.failures.items()):
        print(f"error: {attack_id}: {error}", file=sys.stderr)
    return 2 if result.failures else 0


def _derive_command(args: argparse.Namespace) -> int:
    ledger = Ledger.open()
    facts = ledger.read()
    if args.submit is None:
        request = build_derivation_request(facts, args.case_id)
        print(write_derivation_request(ledger.root, request, state_dir=ledger.state_dir))
        return 0

    response = DeriverResponse.model_validate_json(args.submit.read_bytes())
    if response.case_id != args.case_id:
        raise DerivationError(
            f"response case mismatch: expected {args.case_id}, got {response.case_id}"
        )
    ledger_head = facts[-1].id if facts else None

    def fact_committed(fact_id: str) -> bool | None:
        try:
            return any(fact.id == fact_id for fact in ledger.read())
        except (FalsiqError, OSError):
            return None

    _fact, brief_path = submit_derivation(
        ledger.root,
        facts,
        response,
        state_dir=ledger.state_dir,
        append_batch=lambda batch: ledger.append_batch(batch, expected_head=ledger_head),
        fact_committed=fact_committed,
    )
    print(brief_path)
    return 0


def _brief_command(args: argparse.Namespace) -> int:
    ledger, markdown_path = ready_brief(args.case_id)
    if not args.json:
        print(markdown_path.read_text(encoding="utf-8"), end="")
        return 0
    derivation = next(
        (
            fact
            for fact in reversed(ledger.read())
            if isinstance(fact, DerivationFact) and fact.case_id == args.case_id
        ),
        None,
    )
    if derivation is None or derivation.brief_json_path is None:
        raise LedgerValidationError(
            f"case {args.case_id} has no machine brief; migrate and derive again"
        )
    path = ledger.state_dir / derivation.brief_json_path
    print(path.read_text(encoding="utf-8"), end="")
    return 0


def _migrate_command(args: argparse.Namespace) -> int:
    ledger = Ledger.open()
    if ledger.write_schema_version() == 2:
        print("Ledger already writes durable fact schema version 2.")
        return 0
    if not args.apply:
        print("Dry run: append schema migration 1 -> 2; no ledger bytes changed.")
        return 0
    facts = ledger.read()
    head = facts[-1].id if facts else None
    marker_id = new_ulid()
    marker = SchemaMigrationFact(
        id=marker_id,
        ts=utc_timestamp(),
        case_id=marker_id,
        from_version=1,
        to_version=2,
    )
    ledger.append_batch([marker], expected_head=head)
    print(marker.id)
    return 0


def _outcomes_report_command(args: argparse.Namespace) -> int:
    report = build_outcomes_report(Ledger.open().read(), since=args.since)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    else:
        print("# Falsiq outcome attribution")
        for klass, row in report["by_class"].items():
            print(
                f"- {klass}: attacks={row['attacks_fired']}, "
                f"elicited={row['reworks_elicited']}, missable={row['reworks_missable']}"
            )
    return 0


def _guard_command(args: argparse.Namespace) -> int:
    ledger, brief = ready_brief(args.case_id)
    print(brief.relative_to(ledger.root))
    return 0


def _rpc_command(_args: argparse.Namespace) -> int:
    return serve_rpc(sys.stdin, sys.stdout)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="falsiq")
    parser.add_argument(
        "--version",
        action="version",
        version=f"falsiq {__version__}",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    init_parser = commands.add_parser("init", help="initialize the repository ledger")
    init_parser.set_defaults(handler=_init_command)

    intent_parser = commands.add_parser("intent", help="open a case with verbatim intent")
    intent_parser.add_argument("text")
    intent_parser.add_argument("--profile", default="coding")
    intent_parser.add_argument("--profile-file", type=Path)
    intent_parser.set_defaults(handler=_intent_command)

    log_parser = commands.add_parser("log", help="print canonical ledger facts")
    log_parser.add_argument(
        "--kind",
        choices=("intent", "review", "ruling", "derivation", "outcome"),
    )
    log_parser.add_argument("--case", dest="case_id")
    log_parser.set_defaults(handler=_log_command)

    state_parser = commands.add_parser("state", help="derive current case state")
    state_parser.add_argument("--json", action="store_true")
    state_parser.add_argument("--case", dest="case_id")
    state_parser.set_defaults(handler=_state_command)

    review_parser = commands.add_parser(
        "attack",
        aliases=["review"],
        help="validate and append review rounds",
    )
    review_commands = review_parser.add_subparsers(dest="review_command", required=True)
    review_request_parser = review_commands.add_parser(
        "request",
        help="emit a self-contained request for one reviewer",
    )
    review_request_parser.add_argument("--case", dest="case_id", required=True)
    review_request_parser.add_argument("--reviewer", choices=tuple(REVIEW_CLASSES), required=True)
    review_request_parser.set_defaults(handler=_review_request_command)
    review_prepare_parser = review_commands.add_parser(
        "prepare",
        help="validate reviewer output with an empty-batch fallback",
    )
    review_prepare_parser.add_argument("--case", dest="case_id", required=True)
    review_prepare_parser.add_argument("--reviewer", choices=tuple(REVIEW_CLASSES), required=True)
    review_prepare_parser.add_argument("-f", "--file", type=Path, required=True)
    review_prepare_parser.set_defaults(handler=_review_prepare_command)
    review_assemble_parser = review_commands.add_parser(
        "assemble",
        help="assemble five reviewer batches into a deterministic round",
    )
    review_assemble_parser.add_argument("--case", dest="case_id", required=True)
    review_assemble_parser.add_argument(
        "--round",
        dest="round_number",
        type=int,
        required=True,
    )
    review_assemble_parser.add_argument("batches", nargs="*", type=Path)
    review_assemble_parser.set_defaults(handler=_review_assemble_command)
    review_add_parser = review_commands.add_parser("add", help="append a selector-approved round")
    review_add_parser.add_argument("-f", "--file", type=Path, required=True)
    review_add_parser.add_argument("--policy", type=Path)
    review_add_parser.set_defaults(handler=_review_add_command)

    collide_parser = commands.add_parser("collide", help="render a case's open reviews")
    collide_parser.add_argument("--case", dest="case_id", required=True)
    collide_parser.set_defaults(handler=_collide_command)

    rule_parser = commands.add_parser("rule", help="record or supersede a review ruling")
    rule_parser.add_argument("review_id")
    rule_parser.add_argument(
        "verdict",
        choices=("intended", "forbidden", "dont_care", "amend"),
    )
    rule_parser.add_argument("--choice")
    rule_parser.add_argument("--text")
    rule_parser.add_argument("--intent", dest="intent_id")
    rule_parser.set_defaults(handler=_rule_command)

    outcome_parser = commands.add_parser("outcome", help="record implementation feedback")
    outcome_parser.add_argument("otype", choices=("rework", "accepted", "abandoned"))
    outcome_parser.add_argument("--case", dest="case_id", required=True)
    outcome_parser.add_argument(
        "--trace",
        choices=("elicited", "missable", "novel", "n/a"),
        required=True,
    )
    outcome_parser.add_argument("--review", dest="review_id")
    outcome_parser.add_argument(
        "--missable-class",
        choices=("boundary", "consequence", "prototype", "conflict", "omission"),
    )
    outcome_parser.add_argument("--prompt-version")
    outcome_parser.add_argument("--notes", default="")
    outcome_parser.set_defaults(handler=_outcome_command)

    sandbox_parser = commands.add_parser("sandbox", help="manage disposable prototype worktrees")
    sandbox_commands = sandbox_parser.add_subparsers(dest="sandbox_command", required=True)
    sandbox_new = sandbox_commands.add_parser("new", help="create a prototype worktree")
    sandbox_new.add_argument("review_id", nargs="?", metavar="ID")
    sandbox_new.set_defaults(handler=_sandbox_new_command)
    sandbox_reap = sandbox_commands.add_parser("reap", help="remove managed prototype worktrees")
    sandbox_reap.add_argument(
        "--force",
        action="store_true",
        help="discard changes in dirty managed prototype worktrees",
    )
    sandbox_reap.set_defaults(handler=_sandbox_reap_command)

    derive_parser = commands.add_parser("derive", help="request or submit brief derivation")
    derive_parser.add_argument("--case", dest="case_id", required=True)
    derive_parser.add_argument("--submit", type=Path)
    derive_parser.set_defaults(handler=_derive_command)

    brief_parser = commands.add_parser("brief", help="print the current derived brief")
    brief_parser.add_argument("--case", dest="case_id", required=True)
    brief_parser.add_argument("--json", action="store_true")
    brief_parser.set_defaults(handler=_brief_command)

    outcomes_parser = commands.add_parser(
        "outcomes",
        help="report outcome attribution",
    )
    outcomes_commands = outcomes_parser.add_subparsers(
        dest="outcomes_command",
        required=True,
    )
    outcomes_report = outcomes_commands.add_parser("report")
    outcomes_report.add_argument("--since")
    outcomes_report.add_argument("--json", action="store_true")
    outcomes_report.set_defaults(handler=_outcomes_report_command)

    migrate_parser = commands.add_parser(
        "migrate",
        help="activate a newer durable fact writer without rewriting history",
    )
    migrate_parser.add_argument("--to", type=int, choices=(2,), required=True)
    migrate_parser.add_argument("--apply", action="store_true")
    migrate_parser.set_defaults(handler=_migrate_command)

    guard_parser = commands.add_parser(
        "guard",
        help="verify a case is ready for implementation",
    )
    guard_parser.add_argument("--case", dest="case_id", required=True)
    guard_parser.set_defaults(handler=_guard_command)

    rpc_parser = commands.add_parser("rpc", help="serve newline-delimited JSON requests")
    rpc_parser.set_defaults(handler=_rpc_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    try:
        return int(args.handler(args))
    except ValidationError as exc:
        message = exc.errors(include_url=False)[0]["msg"]
        print(f"error: {message}", file=sys.stderr)
        return 2
    except (
        DerivationError,
        FalsiqError,
        OSError,
        RoundGateError,
        RulingCommandError,
        SandboxError,
        PolicyError,
        ProfileError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
