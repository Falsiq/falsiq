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
from .facts import AttackFact, IntentFact, RulingFact, new_ulid, utc_timestamp
from .ledger import FalsiqError, Ledger, LedgerValidationError, canonical_fact_json
from .rulings import RulingCommandError, build_outcome, build_ruling_batch
from .sandbox import SandboxError, create_sandbox, reap_sandboxes, sandbox_json
from .workflow import (
    ATTACK_CLASSES,
    assemble_attack_round,
    build_attack_request,
    canonical_attack_request_json,
    canonical_selection_json,
    prepare_attack_batch,
    ready_brief,
)


def _init_command(_args: argparse.Namespace) -> int:
    ledger = Ledger.initialize()
    print(f"Initialized {ledger.state_dir}")
    return 0


def _intent_command(args: argparse.Namespace) -> int:
    ledger = Ledger.open()
    fact_id = new_ulid()
    fact = IntentFact(
        id=fact_id,
        ts=utc_timestamp(),
        case_id=fact_id,
        text=args.text,
        source="user",
    )
    ledger.append(fact)
    print(fact.id)
    return 0


def _log_command(args: argparse.Namespace) -> int:
    ledger = Ledger.open()
    for fact in ledger.log(kind=args.kind, case_id=args.case_id):
        print(canonical_fact_json(fact))
    return 0


def _render_case(case: dict[str, object]) -> list[str]:
    lines = [f"Case {case['case_id']}"]
    intents = case["intents"]
    if isinstance(intents, list):
        for intent in intents:
            if isinstance(intent, dict):
                lines.append(f"Intent: {intent['text']}")
    rulings = case["rulings"]
    open_attacks = case["open_attacks"]
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
    lines.append(f"Open attacks: {len(open_attacks) if isinstance(open_attacks, list) else 0}")
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
    state = Ledger.open().state(args.case_id)
    if args.json:
        print(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(_render_state(state))
    return 0


def _attack_add_command(args: argparse.Namespace) -> int:
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
    appended = append_attack_round(
        envelope,
        existing_attacks=existing_attacks,
        active_rulings=active_rulings,
        append_batch=lambda batch: ledger.append_batch(batch, expected_head=ledger_head),
    )
    for fact in appended:
        print(fact.id)
    return 0


def _attack_assemble_command(args: argparse.Namespace) -> int:
    envelope = assemble_attack_round(args.case_id, args.round_number, args.batches)
    print(canonical_selection_json(envelope))
    return 0


def _attack_request_command(args: argparse.Namespace) -> int:
    request = build_attack_request(Ledger.open(), args.case_id, args.attacker)
    print(canonical_attack_request_json(request))
    return 0


def _attack_prepare_command(args: argparse.Namespace) -> int:
    batch, degraded = prepare_attack_batch(args.case_id, args.attacker, args.file)
    if degraded:
        print(
            f"warning: invalid {args.attacker} attacker output was replaced by an empty batch",
            file=sys.stderr,
        )
    print(batch.model_dump_json())
    return 0


def _collide_command(args: argparse.Namespace) -> int:
    ledger = Ledger.open()
    state = ledger.state(args.case_id)
    open_values = state.get("open_attacks")
    if not isinstance(open_values, list) or not open_values:
        raise LedgerValidationError(f"case {args.case_id} has no open attacks")
    attacks = [AttackFact.model_validate(value) for value in open_values]
    path = write_collision_file(ledger.root, args.case_id, attacks)
    print(path)
    return 0


def _rule_command(args: argparse.Namespace) -> int:
    ledger = Ledger.open()
    facts = ledger.read()
    batch = build_ruling_batch(
        facts,
        attack_id=args.attack_id,
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
        attack_id=args.attack_id,
        notes=args.notes,
    )
    ledger_head = facts[-1].id if facts else None
    appended = ledger.append_batch([outcome], expected_head=ledger_head)
    print(appended[0].id)
    return 0


def _sandbox_new_command(args: argparse.Namespace) -> int:
    sandbox = create_sandbox(Path.cwd(), args.attack_id)
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
        print(write_derivation_request(ledger.root, request))
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
        append_batch=lambda batch: ledger.append_batch(batch, expected_head=ledger_head),
        fact_committed=fact_committed,
    )
    print(brief_path)
    return 0


def _guard_command(args: argparse.Namespace) -> int:
    ledger, brief = ready_brief(args.case_id)
    print(brief.relative_to(ledger.root))
    return 0


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
    intent_parser.set_defaults(handler=_intent_command)

    log_parser = commands.add_parser("log", help="print canonical ledger facts")
    log_parser.add_argument(
        "--kind",
        choices=("intent", "attack", "ruling", "derivation", "outcome"),
    )
    log_parser.add_argument("--case", dest="case_id")
    log_parser.set_defaults(handler=_log_command)

    state_parser = commands.add_parser("state", help="derive current case state")
    state_parser.add_argument("--json", action="store_true")
    state_parser.add_argument("--case", dest="case_id")
    state_parser.set_defaults(handler=_state_command)

    attack_parser = commands.add_parser("attack", help="validate and append attack rounds")
    attack_commands = attack_parser.add_subparsers(dest="attack_command", required=True)
    attack_request_parser = attack_commands.add_parser(
        "request",
        help="emit a self-contained request for one attacker",
    )
    attack_request_parser.add_argument("--case", dest="case_id", required=True)
    attack_request_parser.add_argument("--attacker", choices=tuple(ATTACK_CLASSES), required=True)
    attack_request_parser.set_defaults(handler=_attack_request_command)
    attack_prepare_parser = attack_commands.add_parser(
        "prepare",
        help="validate attacker output with an empty-batch fallback",
    )
    attack_prepare_parser.add_argument("--case", dest="case_id", required=True)
    attack_prepare_parser.add_argument("--attacker", choices=tuple(ATTACK_CLASSES), required=True)
    attack_prepare_parser.add_argument("-f", "--file", type=Path, required=True)
    attack_prepare_parser.set_defaults(handler=_attack_prepare_command)
    attack_assemble_parser = attack_commands.add_parser(
        "assemble",
        help="assemble five attacker batches into a deterministic round",
    )
    attack_assemble_parser.add_argument("--case", dest="case_id", required=True)
    attack_assemble_parser.add_argument(
        "--round",
        dest="round_number",
        type=int,
        choices=(1, 2),
        required=True,
    )
    attack_assemble_parser.add_argument("batches", nargs="*", type=Path)
    attack_assemble_parser.set_defaults(handler=_attack_assemble_command)
    attack_add_parser = attack_commands.add_parser("add", help="append a selector-approved round")
    attack_add_parser.add_argument("-f", "--file", type=Path, required=True)
    attack_add_parser.set_defaults(handler=_attack_add_command)

    collide_parser = commands.add_parser("collide", help="render a case's open attacks")
    collide_parser.add_argument("--case", dest="case_id", required=True)
    collide_parser.set_defaults(handler=_collide_command)

    rule_parser = commands.add_parser("rule", help="record or supersede an attack ruling")
    rule_parser.add_argument("attack_id")
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
    outcome_parser.add_argument("--attack", dest="attack_id")
    outcome_parser.add_argument("--notes", default="")
    outcome_parser.set_defaults(handler=_outcome_command)

    sandbox_parser = commands.add_parser("sandbox", help="manage disposable prototype worktrees")
    sandbox_commands = sandbox_parser.add_subparsers(dest="sandbox_command", required=True)
    sandbox_new = sandbox_commands.add_parser("new", help="create a prototype worktree")
    sandbox_new.add_argument("attack_id", nargs="?", metavar="ID")
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

    guard_parser = commands.add_parser(
        "guard",
        help="verify a case is ready for implementation",
    )
    guard_parser.add_argument("--case", dest="case_id", required=True)
    guard_parser.set_defaults(handler=_guard_command)
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
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
