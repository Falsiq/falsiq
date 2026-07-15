from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from pydantic import ValidationError

from . import __version__
from .facts import IntentFact, new_ulid, utc_timestamp
from .ledger import FalsiqError, Ledger, canonical_fact_json


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
    except (FalsiqError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
