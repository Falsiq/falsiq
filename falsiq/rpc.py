"""Strict newline-delimited JSON RPC over the model-free Falsiq core."""

from __future__ import annotations

import hashlib
import json
import stat
from collections.abc import Mapping
from typing import IO, Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from .attacks import ReviewCandidateBatch, SelectionEnvelope, build_selection_envelope
from .derive import (
    DeriverResponse,
    build_derivation_request,
    submit_derivation,
)
from .facts import DerivationFact, IntentFact, new_ulid, utc_timestamp
from .ledger import FalsiqError, Ledger, LedgerValidationError
from .profiles import load_profile
from .review_language import neutralize_review_state
from .rulings import build_outcome, build_ruling_batch
from .workflow import REVIEW_CLASSES, ready_brief

RpcOperation = Literal[
    "state",
    "brief",
    "intent",
    "attack.assemble",
    "rule",
    "derive.request",
    "derive.submit",
    "outcome",
]


class RpcModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class RpcRequest(RpcModel):
    id: Annotated[str, Field(min_length=1, max_length=128)]
    op: RpcOperation
    params: dict[str, object] = Field(default_factory=dict)


class StateParams(RpcModel):
    case_id: str | None = None


class BriefParams(RpcModel):
    case_id: str


class IntentParams(RpcModel):
    text: str
    profile: str = "coding"


class AttackAssembleParams(RpcModel):
    case_id: str
    round: int = Field(ge=1)
    batches: list[dict[str, object]]


class RuleParams(RpcModel):
    review_id: str
    verdict: Literal["intended", "forbidden", "dont_care", "amend"]
    choice: str | None = None
    text: str | None = None
    intent_id: str | None = None


class DeriveRequestParams(RpcModel):
    case_id: str


class DeriveSubmitParams(RpcModel):
    case_id: str
    response: dict[str, object]


class OutcomeParams(RpcModel):
    case_id: str
    otype: Literal["rework", "accepted", "abandoned"]
    trace: Literal["elicited", "missable", "novel", "n/a"]
    review_id: str | None = None
    missable_class: (
        Literal["boundary", "consequence", "prototype", "conflict", "omission"] | None
    ) = None
    prompt_version: str | None = None
    notes: str = ""


_PARAM_ADAPTERS: dict[str, TypeAdapter[BaseModel]] = {
    "state": TypeAdapter(StateParams),
    "brief": TypeAdapter(BriefParams),
    "intent": TypeAdapter(IntentParams),
    "attack.assemble": TypeAdapter(AttackAssembleParams),
    "rule": TypeAdapter(RuleParams),
    "derive.request": TypeAdapter(DeriveRequestParams),
    "derive.submit": TypeAdapter(DeriveSubmitParams),
    "outcome": TypeAdapter(OutcomeParams),
}


def _latest_derivation(ledger: Ledger, case_id: str) -> DerivationFact:
    derivation = next(
        (
            fact
            for fact in reversed(ledger.read())
            if isinstance(fact, DerivationFact) and fact.case_id == case_id
        ),
        None,
    )
    if derivation is None:
        raise LedgerValidationError(f"case {case_id} has no derivation")
    return derivation


def _read_machine_brief(case_id: str) -> dict[str, object]:
    ledger, _markdown = ready_brief(case_id)
    derivation = _latest_derivation(ledger, case_id)
    if derivation.brief_json_path is None or derivation.brief_json_sha256 is None:
        raise LedgerValidationError(
            f"case {case_id} has no machine brief; migrate and derive again"
        )
    path = ledger.state_dir / derivation.brief_json_path
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise LedgerValidationError("machine brief must be a regular non-symlink file")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != derivation.brief_json_sha256:
        raise LedgerValidationError("machine brief digest mismatch")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise LedgerValidationError("machine brief must be a JSON object")
    return value


def _assemble_from_values(params: AttackAssembleParams) -> SelectionEnvelope:
    if len(params.batches) != len(REVIEW_CLASSES):
        raise ValueError("exactly five reviewer batches are required")
    batches = [ReviewCandidateBatch.model_validate(item) for item in params.batches]
    by_role: dict[str, ReviewCandidateBatch] = {}
    for batch in batches:
        if batch.case_id != params.case_id:
            raise ValueError("reviewer batch case does not match request")
        if batch.reviewer in by_role:
            raise ValueError(f"duplicate reviewer batch: {batch.reviewer}")
        by_role[batch.reviewer] = batch
    missing = set(REVIEW_CLASSES).difference(by_role)
    if missing:
        raise ValueError(f"missing reviewer batches: {', '.join(sorted(missing))}")
    candidates = [candidate for role in REVIEW_CLASSES for candidate in by_role[role].candidates]
    return build_selection_envelope(params.case_id, params.round, candidates)


def _dispatch(request: RpcRequest) -> object:
    params = _PARAM_ADAPTERS[request.op].validate_python(request.params, strict=True)
    ledger = Ledger.open()
    if isinstance(params, StateParams):
        return neutralize_review_state(ledger.state(params.case_id))
    if isinstance(params, BriefParams):
        return _read_machine_brief(params.case_id)
    if isinstance(params, IntentParams):
        fact_id = new_ulid()
        schema_version = ledger.write_schema_version()
        profile_name: str | None = None
        profile_digest: str | None = None
        if schema_version == 2:
            loaded = load_profile(params.profile)
            profile_name = loaded.profile.name
            profile_digest = loaded.digest
        fact = IntentFact(
            schema_version=schema_version,
            id=fact_id,
            ts=utc_timestamp(),
            case_id=fact_id,
            text=params.text,
            source="user",
            profile_name=profile_name,
            profile_digest=profile_digest,
        )
        ledger.append(fact)
        return {"case_id": fact.id}
    if isinstance(params, AttackAssembleParams):
        return _assemble_from_values(params).model_dump(mode="json")
    facts = ledger.read()
    head = facts[-1].id if facts else None
    if isinstance(params, RuleParams):
        batch = build_ruling_batch(
            facts,
            attack_id=params.review_id,
            verdict=params.verdict,
            choice=params.choice,
            amendment_text=params.text,
            intent_id=params.intent_id,
        )
        return {"fact_ids": [fact.id for fact in ledger.append_batch(batch, expected_head=head)]}
    if isinstance(params, DeriveRequestParams):
        return build_derivation_request(facts, params.case_id).model_dump(mode="json")
    if isinstance(params, DeriveSubmitParams):
        response = DeriverResponse.model_validate(params.response)
        if response.case_id != params.case_id:
            raise ValueError("derivation response case does not match request")
        fact, _path = submit_derivation(
            ledger.root,
            facts,
            response,
            state_dir=ledger.state_dir,
            append_batch=lambda batch: ledger.append_batch(batch, expected_head=head),
            fact_committed=lambda fact_id: any(item.id == fact_id for item in ledger.read()),
        )
        return {"fact_id": fact.id}
    if isinstance(params, OutcomeParams):
        fact = build_outcome(
            facts,
            case_id=params.case_id,
            otype=params.otype,
            trace=params.trace,
            attack_id=params.review_id,
            notes=params.notes,
            missable_class=params.missable_class,
            prompt_version=params.prompt_version,
        )
        appended = ledger.append_batch([fact], expected_head=head)
        return {"fact_id": appended[0].id}
    raise AssertionError("unreachable RPC operation")


def dispatch_request(value: Mapping[str, object]) -> dict[str, object]:
    """Validate and execute one request, returning a non-throwing response envelope."""

    request_id = value.get("id")
    response_id = request_id if isinstance(request_id, str) else None
    try:
        request = RpcRequest.model_validate(value)
        result = _dispatch(request)
        return {"id": request.id, "ok": True, "result": result}
    except (FalsiqError, OSError, ValidationError, ValueError) as exc:
        return {
            "id": response_id,
            "ok": False,
            "error": {
                "code": type(exc).__name__,
                "message": str(exc),
            },
        }


def _decode_line(line: str) -> Mapping[str, object]:
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("RPC request must be a JSON object")
    return value


def serve(source: IO[str], sink: IO[str]) -> int:
    """Serve newline-delimited requests until EOF."""

    for line in source:
        try:
            value = _decode_line(line)
            response = dispatch_request(value)
        except (json.JSONDecodeError, ValueError) as exc:
            response = {
                "id": None,
                "ok": False,
                "error": {"code": type(exc).__name__, "message": str(exc)},
            }
        sink.write(
            json.dumps(
                response,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        sink.flush()
    return 0


__all__ = ["RpcRequest", "dispatch_request", "serve"]
