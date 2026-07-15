from __future__ import annotations

import hashlib
import json
import stat
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest
from pydantic import ValidationError

from falsiq.cli import main
from falsiq.derive import (
    DERIVER_PROMPT,
    DerivationError,
    DerivationRequest,
    DeriverResponse,
    ForbiddenTest,
    build_derivation_request,
    deriver_prompt_hash,
    render_implementation_brief,
    submit_derivation,
)
from falsiq.facts import (
    Artifact,
    AttackFact,
    DerivationFact,
    IntentFact,
    OutcomeFact,
    RulingFact,
    new_ulid,
)
from falsiq.ledger import Ledger, LedgerValidationError

TS = "2026-07-15T12:00:00.000Z"


def make_id(number: int) -> str:
    return new_ulid(timestamp_ms=number, randomness=number.to_bytes(10, "big"))


def git_repo(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    return path


def root_intent(number: int = 1) -> IntentFact:
    case_id = make_id(number)
    return IntentFact(
        id=case_id,
        ts=TS,
        case_id=case_id,
        text="  Add retries <without> retrying 4xx.",
        source="user",
    )


def attack(
    number: int,
    intent: IntentFact,
    *,
    klass: str = "boundary",
    decision: str = "retryable status behavior",
) -> AttackFact:
    return AttackFact(
        id=make_id(number),
        ts=TS,
        case_id=intent.case_id,
        klass=klass,
        targets=[intent.id],
        artifact=Artifact(type="scenario", body=f"Concrete scenario {number}"),
        settles=[decision],
        silent_settles=[decision],
        hate_scenario=f"Bad outcome {number}",
        render_cost="trivial",
        round=1,
    )


def ruled_ledger(repo: Path) -> tuple[Ledger, IntentFact, RulingFact, RulingFact]:
    ledger = Ledger.initialize(repo)
    intent = root_intent()
    forbidden_attack = attack(2, intent)
    forbidden = RulingFact(
        id=make_id(3),
        ts=TS,
        case_id=intent.case_id,
        attack_id=forbidden_attack.id,
        verdict="forbidden",
    )
    discretion_attack = attack(
        4,
        intent,
        klass="omission",
        decision="retry log wording",
    )
    dont_care = RulingFact(
        id=make_id(5),
        ts=TS,
        case_id=intent.case_id,
        attack_id=discretion_attack.id,
        verdict="dont_care",
    )
    ledger.append_batch([intent, forbidden_attack, forbidden, discretion_attack, dont_care])
    return ledger, intent, forbidden, dont_care


def response_for(
    request,
    forbidden: RulingFact,
    *,
    content: str | None = None,
    reason: str | None = None,
) -> DeriverResponse:
    test = ForbiddenTest(
        ruling_id=forbidden.id,
        filename="test_forbidden_retry_on_4xx.py" if content is not None else None,
        content=content,
        unexpressible_reason=reason,
    )
    return DeriverResponse(
        request_id=request.request_id,
        case_id=request.case_id,
        ledger_head=request.ledger_head,
        forbidden_tests=[test],
    )


def write_response(path: Path, response: DeriverResponse | dict[str, object]) -> Path:
    payload = (
        response.model_dump(mode="json") if isinstance(response, DeriverResponse) else response
    )
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def test_derivation_request_is_strict_deterministic_and_prompt_keyed(tmp_path: Path) -> None:
    ledger, intent, _forbidden, _dont_care = ruled_ledger(git_repo(tmp_path / "repo"))
    facts = ledger.read()

    first = build_derivation_request(facts, intent.case_id)
    second = build_derivation_request(facts, intent.case_id)

    assert first == second
    assert first.ledger_head == facts[-1].id
    assert first.prompt_sha256 == deriver_prompt_hash()
    assert len(first.request_id) == 64
    assert first.response_schema == DeriverResponse.model_json_schema()
    assert first.state["open_attacks"] == []
    strict_payload = first.model_dump(mode="json") | {"unexpected": True}
    with pytest.raises(ValidationError):
        DerivationRequest.model_validate(strict_payload)


def test_derivation_request_refuses_open_attacks(tmp_path: Path) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger = Ledger.initialize(repo)
    intent = root_intent()
    ledger.append_batch([intent, attack(2, intent)])

    with pytest.raises(DerivationError, match="open attacks"):
        build_derivation_request(ledger.read(), intent.case_id)


@pytest.mark.parametrize(
    "payload",
    [
        {
            "ruling_id": make_id(3),
            "filename": "../test_escape.py",
            "content": "def test_x(): pass",
        },
        {
            "ruling_id": make_id(3),
            "filename": "/tmp/test_escape.py",
            "content": "def test_x(): pass",
        },
        {
            "ruling_id": make_id(3),
            "filename": "helper.py",
            "content": "def test_x(): pass",
        },
        {
            "ruling_id": make_id(3),
            "filename": "test_con.py",
            "content": "def test_x(): pass",
        },
        {
            "ruling_id": make_id(3),
            "filename": "test_invalid_syntax.py",
            "content": "def test_broken(: pass",
        },
        {
            "ruling_id": make_id(3),
            "filename": "test_no_test_function.py",
            "content": "VALUE = 1\n",
        },
        {
            "ruling_id": make_id(3),
            "filename": "test_both.py",
            "content": "def test_x(): pass",
            "unexpressible_reason": "also a reason",
        },
        {
            "ruling_id": make_id(3),
            "filename": None,
            "content": None,
            "unexpressible_reason": None,
        },
    ],
)
def test_forbidden_test_contract_rejects_unsafe_or_ambiguous_entries(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        ForbiddenTest.model_validate(payload)


@pytest.mark.parametrize(
    "content",
    [
        "def test_placeholder() -> None:\n    pass\n",
        (
            '"""Inert forbidden-ruling scaffolds."""\n\n'
            "def test_first_forbidden_behavior() -> None:\n"
            '    """Replace this placeholder with a repository-native assertion."""\n'
            '    raise NotImplementedError("implement from the forbidden ruling")\n\n'
            "def test_second_forbidden_behavior():\n"
            "    raise NotImplementedError\n"
        ),
    ],
)
def test_forbidden_test_contract_accepts_inert_top_level_pytest_scaffolds(
    content: str,
) -> None:
    test = ForbiddenTest(
        ruling_id=make_id(3),
        filename="test_inert_scaffold.py",
        content=content,
    )

    assert test.content == content


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        (
            'print("import-time side effect")\ndef test_placeholder() -> None:\n    pass\n',
            "module-level",
        ),
        (
            "import dangerous_plugin\ndef test_placeholder() -> None:\n    pass\n",
            "module-level",
        ),
        (
            "# coding: utf-7\ndef test_placeholder() -> None:\n    pass\n",
            "encoding declaration",
        ),
        (
            'def test_placeholder() -> None:\n    """unpaired surrogate: \ud800"""\n    pass\n',
            "valid string|UTF-8 encodable",
        ),
        (
            "def helper() -> None:\n    def test_nested_only() -> None:\n        pass\n",
            "top-level test_",
        ),
        (
            "def test_executes_model_code() -> None:\n    assert repository_call()\n",
            "inert placeholder",
        ),
        (
            "@pytest.mark.parametrize('value', [side_effect()])\n"
            "def test_decorated(value) -> None:\n"
            "    pass\n",
            "decorators",
        ),
        (
            "async def test_async() -> None:\n    pass\n",
            "module-level",
        ),
        (
            "def test_fixture(fixture) -> None:\n    pass\n",
            "parameters",
        ),
        (
            "def test_annotation() -> annotation_factory():\n    pass\n",
            "return annotation",
        ),
        (
            "def test_type_comment():  # type: () -> None\n    pass\n",
            "type comments",
        ),
        (
            "def test_dynamic_message() -> None:\n"
            "    raise NotImplementedError(message_factory())\n",
            "inert placeholder",
        ),
    ],
    ids=[
        "module-call",
        "import-side-effect",
        "alternate-source-encoding",
        "invalid-utf8-scalar",
        "nested-only",
        "unsafe-body",
        "decorated-parameterized",
        "async",
        "fixture-parameter",
        "evaluated-annotation",
        "function-type-comment",
        "dynamic-raise-message",
    ],
)
def test_forbidden_test_contract_rejects_executable_model_authored_scaffolds(
    content: str,
    reason: str,
) -> None:
    with pytest.raises(ValidationError, match=reason):
        ForbiddenTest(
            ruling_id=make_id(3),
            filename="test_untrusted_scaffold.py",
            content=content,
        )


def test_derive_submit_rejects_executable_stub_without_publishing(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent, forbidden, _dont_care = ruled_ledger(repo)
    request = build_derivation_request(ledger.read(), intent.case_id)
    payload = response_for(request, forbidden, reason="Not expressible").model_dump(mode="json")
    payload["forbidden_tests"] = [
        {
            "ruling_id": forbidden.id,
            "filename": "test_import_time_call.py",
            "content": ("repository_call()\ndef test_forbidden_behavior() -> None:\n    pass\n"),
            "unexpressible_reason": None,
        }
    ]
    response_path = write_response(repo / "response.json", payload)
    before = ledger.path.read_bytes()
    monkeypatch.chdir(repo)

    assert main(["derive", "--case", intent.case_id, "--submit", str(response_path)]) == 2

    output = capsys.readouterr()
    assert output.out == ""
    assert "module-level imports or executable statements are forbidden" in output.err
    assert ledger.path.read_bytes() == before
    derived = repo / ".falsiq" / "cases" / intent.case_id / "derived"
    assert not (derived / "IMPLEMENTATION_BRIEF.md").exists()
    assert not (derived / "tests").exists()


def test_deriver_response_rejects_extra_intent_or_duplicate_outputs() -> None:
    base = {
        "request_id": "a" * 64,
        "case_id": make_id(1),
        "ledger_head": make_id(5),
        "forbidden_tests": [],
    }
    with pytest.raises(ValidationError, match="Extra inputs"):
        DeriverResponse.model_validate(base | {"intent": "agent rewrite"})

    with pytest.raises(ValidationError, match="Extra inputs"):
        DeriverResponse.model_validate(
            base
            | {
                "agent_discretion": [
                    {
                        "decision": "Silently add a new requirement.",
                        "rationale": "The deriver chose it.",
                    }
                ]
            }
        )

    duplicate = ForbiddenTest(
        ruling_id=make_id(3),
        filename="test_duplicate.py",
        content="def test_duplicate() -> None:\n    pass\n",
    )
    with pytest.raises(ValidationError, match="duplicate"):
        DeriverResponse.model_validate(base | {"forbidden_tests": [duplicate, duplicate]})

    case_collision = ForbiddenTest.model_construct(
        ruling_id=make_id(4),
        filename="TEST_DUPLICATE.PY",
        content="def test_other() -> None:\n    pass\n",
        unexpressible_reason=None,
    )
    with pytest.raises(ValidationError, match="case-insensitive"):
        DeriverResponse.model_validate(base | {"forbidden_tests": [duplicate, case_collision]})


def test_brief_rendering_is_order_stable_and_intent_section_is_ledger_only(
    tmp_path: Path,
) -> None:
    ledger, intent, forbidden, _dont_care = ruled_ledger(git_repo(tmp_path / "repo"))
    facts = ledger.read()
    request = build_derivation_request(facts, intent.case_id)
    response = response_for(
        request,
        forbidden,
        content=(
            "def test_never_retry_4xx() -> None:\n"
            '    raise NotImplementedError("implement from forbidden ruling")\n'
        ),
    )

    first = render_implementation_brief(facts, response)
    reordered = response.model_copy(
        update={
            "forbidden_tests": list(reversed(response.forbidden_tests)),
        }
    )
    second = render_implementation_brief(facts, reordered)

    assert first == second
    intent_section = first.split("## Rulings", maxsplit=1)[0]
    assert intent.text in intent_section
    assert "agent rewrite" not in intent_section
    assert first == (Path(__file__).parent / "golden" / "implementation_brief.md").read_text()


def test_brief_derives_dont_care_discretion_from_ledger(tmp_path: Path) -> None:
    ledger, intent, forbidden, dont_care = ruled_ledger(git_repo(tmp_path / "repo"))
    facts = ledger.read()
    request = build_derivation_request(facts, intent.case_id)
    response = response_for(request, forbidden, reason="Not expressible")

    brief = render_implementation_brief(facts, response)
    discretion = brief.split("## Agent discretion", maxsplit=1)[1]

    assert "retry log wording" in discretion
    assert dont_care.id in discretion
    assert dont_care.attack_id in discretion
    assert "None recorded" not in discretion


def test_brief_preserves_the_ledger_meaning_of_each_ruling_choice(tmp_path: Path) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    intent = root_intent()
    probe = AttackFact(
        id=make_id(2),
        ts=TS,
        case_id=intent.case_id,
        klass="boundary",
        targets=[intent.id],
        artifact=Artifact(
            type="input",
            body="Input: an empty file",
            options=[
                {"key": "A", "body": "Exit 0 and emit empty output."},
                {"key": "B", "body": 'Exit 2 with "error: empty input".'},
            ],
        ),
        settles=["empty-input behavior", "empty-input exit code"],
        silent_settles=["empty-input exit code"],
        hate_scenario="Silent output masks an upstream pipeline failure.",
        render_cost="trivial",
        round=1,
    )
    ruling = RulingFact(
        id=make_id(3),
        ts=TS,
        case_id=intent.case_id,
        attack_id=probe.id,
        verdict="intended",
        choice="B",
    )
    ledger.append_batch([intent, probe, ruling])
    request = build_derivation_request(ledger.read(), intent.case_id)
    response = DeriverResponse(
        request_id=request.request_id,
        case_id=request.case_id,
        ledger_head=request.ledger_head,
    )

    brief = render_implementation_brief(ledger.read(), response)

    assert "## Ruling evidence (ledger)" in brief
    assert "Input: an empty file" in brief
    assert "Exit 0 and emit empty output." in brief
    assert 'Exit 2 with "error: empty input".' in brief
    assert "empty-input behavior" in brief
    assert "Silent output masks an upstream pipeline failure." in brief
    assert brief.index("Choice `A`") < brief.index("Choice `B`")


def test_amendment_text_is_rendered_verbatim_only_from_linked_ledger_facts(
    tmp_path: Path,
) -> None:
    ledger = Ledger.initialize(git_repo(tmp_path / "repo"))
    intent = root_intent()
    probe = attack(2, intent)
    amended_text = "  Never retry 4xx; preserve `Retry-After`.  "
    ruling = RulingFact(
        id=make_id(3),
        ts=TS,
        case_id=intent.case_id,
        attack_id=probe.id,
        verdict="amend",
        amendment_text=amended_text,
    )
    amended = IntentFact(
        id=make_id(4),
        ts=TS,
        case_id=intent.case_id,
        text=amended_text,
        source="amendment",
        supersedes=intent.id,
        source_ruling_id=ruling.id,
    )
    ledger.append_batch([intent, probe, ruling, amended])
    request = build_derivation_request(ledger.read(), intent.case_id)
    response = DeriverResponse(
        request_id=request.request_id,
        case_id=request.case_id,
        ledger_head=request.ledger_head,
    )

    brief = render_implementation_brief(ledger.read(), response)

    assert brief.count(amended_text) == 2
    assert "Never retry client errors" not in brief
    assert "### Amendment ruling" in brief
    assert "- No active forbidden rulings." in brief
    assert "- None recorded." in brief


def test_deriver_prompt_file_matches_the_hashed_runtime_contract() -> None:
    prompt_path = Path(__file__).parents[1] / "agents" / "deriver.md"
    skill_prompt_path = Path(__file__).parents[1] / "skill" / "references" / "deriver.md"

    assert prompt_path.read_text(encoding="utf-8") == DERIVER_PROMPT
    assert skill_prompt_path.read_text(encoding="utf-8") == DERIVER_PROMPT
    assert deriver_prompt_hash() == (
        "9297e30e738f4e76904ebeb6cdefe733066419500a27a9e42c1ced93309da6ea"
    )


def test_derive_cli_emits_same_canonical_request_for_same_head(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent, _forbidden, _dont_care = ruled_ledger(repo)
    monkeypatch.chdir(repo)

    assert main(["derive", "--case", intent.case_id]) == 0
    first_output = capsys.readouterr()
    request_path = Path(first_output.out.strip())
    first_bytes = request_path.read_bytes()
    assert first_output.err == ""
    assert request_path == (
        repo
        / ".falsiq"
        / "cases"
        / intent.case_id
        / "derived"
        / ledger.read()[-1].id
        / "request.json"
    )
    assert first_bytes.endswith(b"\n")
    assert first_bytes == (
        json.dumps(
            json.loads(first_bytes),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )

    assert main(["derive", "--case", intent.case_id]) == 0
    second_output = capsys.readouterr()
    assert second_output.err == ""
    assert Path(second_output.out.strip()) == request_path
    assert request_path.read_bytes() == first_bytes


def test_derive_cli_refuses_open_attacks_without_writing_request(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger = Ledger.initialize(repo)
    intent = root_intent()
    ledger.append_batch([intent, attack(2, intent)])
    monkeypatch.chdir(repo)

    assert main(["derive", "--case", intent.case_id]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "open attacks" in output.err
    assert not (repo / ".falsiq" / "cases" / intent.case_id / "derived").exists()


def test_derive_request_refuses_symlinked_case_output_directory(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    _ledger, intent, _forbidden, _dont_care = ruled_ledger(repo)
    outside = tmp_path / "outside"
    outside.mkdir()
    case_directory = repo / ".falsiq" / "cases" / intent.case_id
    case_directory.mkdir(parents=True)
    (case_directory / "derived").symlink_to(outside, target_is_directory=True)
    monkeypatch.chdir(repo)

    assert main(["derive", "--case", intent.case_id]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "symlink" in output.err
    assert list(outside.iterdir()) == []


def test_derive_submit_materializes_brief_stubs_and_derivation_fact(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent, forbidden, _dont_care = ruled_ledger(repo)
    monkeypatch.chdir(repo)
    assert main(["derive", "--case", intent.case_id]) == 0
    request_path = Path(capsys.readouterr().out.strip())
    request = build_derivation_request(ledger.read(), intent.case_id)
    stub_content = (
        "def test_never_retry_4xx() -> None:\n"
        '    raise NotImplementedError("implement from forbidden ruling")\n'
    )
    response = response_for(request, forbidden, content=stub_content)
    response_path = write_response(repo / "response.json", response)

    assert main(["derive", "--case", intent.case_id, "--submit", str(response_path)]) == 0
    output = capsys.readouterr()
    brief_path = repo / ".falsiq" / "cases" / intent.case_id / "derived" / "IMPLEMENTATION_BRIEF.md"
    stub_path = (
        repo
        / ".falsiq"
        / "cases"
        / intent.case_id
        / "derived"
        / "tests"
        / "test_forbidden_retry_on_4xx.py"
    )
    assert output.err == ""
    assert output.out == f"{brief_path}\n"
    assert request_path.is_file()
    assert brief_path.read_text() == render_implementation_brief(ledger.read()[:-1], response)
    assert stub_path.read_text() == stub_content
    derivation = ledger.read()[-1]
    assert isinstance(derivation, DerivationFact)
    assert derivation.ledger_head == request.ledger_head
    assert derivation.brief_path == f"cases/{intent.case_id}/derived/IMPLEMENTATION_BRIEF.md"
    assert derivation.brief_sha256 == hashlib.sha256(brief_path.read_bytes()).hexdigest()
    assert derivation.test_stub_paths == [
        f"cases/{intent.case_id}/derived/tests/test_forbidden_retry_on_4xx.py"
    ]
    assert derivation.test_stub_sha256 == {
        f"cases/{intent.case_id}/derived/tests/test_forbidden_retry_on_4xx.py": hashlib.sha256(
            stub_path.read_bytes()
        ).hexdigest()
    }
    assert stat.S_IMODE((brief_path.parent / ".derive.lock").stat().st_mode) == 0o600


def test_unexpressible_forbidden_ruling_is_rendered_without_a_stub(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent, forbidden, _dont_care = ruled_ledger(repo)
    monkeypatch.chdir(repo)
    request = build_derivation_request(ledger.read(), intent.case_id)
    response = response_for(
        request,
        forbidden,
        reason="The ruling is an operational policy with no repository-level assertion.",
    )
    path = write_response(repo / "response.json", response)

    assert main(["derive", "--case", intent.case_id, "--submit", str(path)]) == 0
    capsys.readouterr()
    derived = repo / ".falsiq" / "cases" / intent.case_id / "derived"
    assert "not expressible" in (derived / "IMPLEMENTATION_BRIEF.md").read_text()
    assert list((derived / "tests").iterdir()) == []
    fact = ledger.read()[-1]
    assert isinstance(fact, DerivationFact)
    assert fact.test_stub_paths == []
    assert fact.test_stub_sha256 == {}


@pytest.mark.parametrize("mismatch", ["request_id", "case_id", "ledger_head"])
def test_submit_rejects_mismatched_response_identity_without_outputs(
    tmp_path: Path, monkeypatch, capsys, mismatch: str
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent, forbidden, _dont_care = ruled_ledger(repo)
    monkeypatch.chdir(repo)
    request = build_derivation_request(ledger.read(), intent.case_id)
    response = response_for(request, forbidden, reason="Not expressible").model_dump(mode="json")
    response[mismatch] = "b" * 64 if mismatch == "request_id" else make_id(99)
    path = write_response(repo / "response.json", response)
    before = ledger.path.read_bytes()

    assert main(["derive", "--case", intent.case_id, "--submit", str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "mismatch" in output.err or "stale" in output.err
    assert ledger.path.read_bytes() == before
    derived = repo / ".falsiq" / "cases" / intent.case_id / "derived"
    assert not (derived / "IMPLEMENTATION_BRIEF.md").exists()


def test_submit_rejects_missing_or_nonforbidden_ruling_entries(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent, forbidden, dont_care = ruled_ledger(repo)
    monkeypatch.chdir(repo)
    request = build_derivation_request(ledger.read(), intent.case_id)
    base = response_for(request, forbidden, reason="Not expressible").model_dump(mode="json")
    before = ledger.path.read_bytes()

    for entries in (
        [],
        [
            ForbiddenTest(
                ruling_id=dont_care.id,
                filename=None,
                content=None,
                unexpressible_reason="Wrong ruling",
            ).model_dump(mode="json")
        ],
    ):
        payload = base | {"forbidden_tests": entries}
        path = write_response(repo / "response.json", payload)
        assert main(["derive", "--case", intent.case_id, "--submit", str(path)]) == 2
        output = capsys.readouterr()
        assert output.out == ""
        assert "forbidden ruling" in output.err
        assert ledger.path.read_bytes() == before


def test_stale_response_is_rejected_before_publication(tmp_path: Path, monkeypatch, capsys) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent, forbidden, _dont_care = ruled_ledger(repo)
    monkeypatch.chdir(repo)
    request = build_derivation_request(ledger.read(), intent.case_id)
    response = response_for(request, forbidden, reason="Not expressible")
    path = write_response(repo / "response.json", response)
    ledger.append(
        OutcomeFact(
            id=make_id(6),
            ts=TS,
            case_id=intent.case_id,
            otype="accepted",
            trace="n/a",
            notes="Head moved",
        )
    )
    before = ledger.path.read_bytes()

    assert main(["derive", "--case", intent.case_id, "--submit", str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "stale" in output.err
    assert ledger.path.read_bytes() == before
    assert not (
        repo / ".falsiq" / "cases" / intent.case_id / "derived" / "IMPLEMENTATION_BRIEF.md"
    ).exists()


def test_submit_refuses_symlinked_derived_paths(tmp_path: Path, monkeypatch, capsys) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent, forbidden, _dont_care = ruled_ledger(repo)
    monkeypatch.chdir(repo)
    request = build_derivation_request(ledger.read(), intent.case_id)
    response = response_for(
        request,
        forbidden,
        content="def test_safe() -> None:\n    pass\n",
    )
    path = write_response(repo / "response.json", response)
    outside = tmp_path / "outside"
    outside.mkdir()
    derived = repo / ".falsiq" / "cases" / intent.case_id / "derived"
    derived.mkdir(parents=True)
    (derived / "tests").symlink_to(outside, target_is_directory=True)
    before = ledger.path.read_bytes()

    assert main(["derive", "--case", intent.case_id, "--submit", str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "symlink" in output.err
    assert ledger.path.read_bytes() == before
    assert list(outside.iterdir()) == []


def test_submit_refuses_a_symlinked_derivation_lock(tmp_path: Path, monkeypatch, capsys) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent, forbidden, _dont_care = ruled_ledger(repo)
    request = build_derivation_request(ledger.read(), intent.case_id)
    response = response_for(request, forbidden, reason="Not expressible")
    path = write_response(repo / "response.json", response)
    derived = repo / ".falsiq" / "cases" / intent.case_id / "derived"
    derived.mkdir(parents=True)
    outside = tmp_path / "outside-lock"
    outside.write_text("do not lock\n", encoding="utf-8")
    (derived / ".derive.lock").symlink_to(outside)
    monkeypatch.chdir(repo)

    assert main(["derive", "--case", intent.case_id, "--submit", str(path)]) == 2
    output = capsys.readouterr()
    assert "derivation lock must not be a symlink" in output.err
    assert outside.read_text(encoding="utf-8") == "do not lock\n"
    assert not (derived / "IMPLEMENTATION_BRIEF.md").exists()


@pytest.mark.parametrize("preexisting", [False, True])
def test_expected_head_race_rolls_back_all_published_outputs(
    tmp_path: Path, monkeypatch, capsys, preexisting: bool
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent, forbidden, _dont_care = ruled_ledger(repo)
    monkeypatch.chdir(repo)
    request = build_derivation_request(ledger.read(), intent.case_id)
    response = response_for(
        request,
        forbidden,
        content="def test_safe() -> None:\n    pass\n",
    )
    path = write_response(repo / "response.json", response)
    derived = repo / ".falsiq" / "cases" / intent.case_id / "derived"
    old_brief = b"old brief bytes\n"
    old_stub = b"def test_existing() -> None:\n    pass\n"
    if preexisting:
        old_tests = derived / "tests"
        old_tests.mkdir(parents=True)
        (derived / "IMPLEMENTATION_BRIEF.md").write_bytes(old_brief)
        (old_tests / "test_existing.py").write_bytes(old_stub)
    original_append_batch = Ledger.append_batch
    raced = False

    def append_after_concurrent_change(self, facts, **kwargs):
        nonlocal raced
        if "expected_head" in kwargs and not raced:
            raced = True
            concurrent_case = make_id(99)
            original_append_batch(
                self,
                [
                    IntentFact(
                        id=concurrent_case,
                        ts=TS,
                        case_id=concurrent_case,
                        text="Concurrent case",
                        source="user",
                    )
                ],
            )
        return original_append_batch(self, facts, **kwargs)

    monkeypatch.setattr(Ledger, "append_batch", append_after_concurrent_change)

    assert main(["derive", "--case", intent.case_id, "--submit", str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "ledger head changed" in output.err
    if preexisting:
        assert (derived / "IMPLEMENTATION_BRIEF.md").read_bytes() == old_brief
        assert [path.name for path in (derived / "tests").iterdir()] == ["test_existing.py"]
        assert (derived / "tests" / "test_existing.py").read_bytes() == old_stub
    else:
        assert not (derived / "IMPLEMENTATION_BRIEF.md").exists()
        assert not (derived / "tests").exists()
    assert not any(isinstance(fact, DerivationFact) for fact in Ledger.open(repo).read())


def test_committed_then_raised_append_keeps_new_outputs_consistent_with_fact(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent, forbidden, _dont_care = ruled_ledger(repo)
    request = build_derivation_request(ledger.read(), intent.case_id)
    new_stub = "def test_new_output() -> None:\n    pass\n"
    response = response_for(request, forbidden, content=new_stub)
    path = write_response(repo / "response.json", response)
    derived = repo / ".falsiq" / "cases" / intent.case_id / "derived"
    old_tests = derived / "tests"
    old_tests.mkdir(parents=True)
    (derived / "IMPLEMENTATION_BRIEF.md").write_bytes(b"old brief\n")
    (old_tests / "test_old.py").write_bytes(b"def test_old() -> None:\n    pass\n")
    monkeypatch.chdir(repo)
    original_append_batch = Ledger.append_batch

    def append_then_raise(self, facts, **kwargs):
        original_append_batch(self, facts, **kwargs)
        raise LedgerValidationError("simulated journal cleanup failure")

    monkeypatch.setattr(Ledger, "append_batch", append_then_raise)

    assert main(["derive", "--case", intent.case_id, "--submit", str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "simulated journal cleanup failure" in output.err
    derivations = [fact for fact in Ledger.open(repo).read() if isinstance(fact, DerivationFact)]
    assert len(derivations) == 1
    assert (derived / "IMPLEMENTATION_BRIEF.md").read_text().startswith("# Implementation brief")
    assert [item.name for item in (derived / "tests").iterdir()] == [
        "test_forbidden_retry_on_4xx.py"
    ]
    assert (derived / "tests" / "test_forbidden_retry_on_4xx.py").read_text() == new_stub


def test_unknown_commit_status_keeps_new_disposable_outputs(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent, forbidden, _dont_care = ruled_ledger(repo)
    request = build_derivation_request(ledger.read(), intent.case_id)
    new_stub = "def test_new_output() -> None:\n    pass\n"
    response = response_for(request, forbidden, content=new_stub)
    path = write_response(repo / "response.json", response)
    derived = repo / ".falsiq" / "cases" / intent.case_id / "derived"
    old_tests = derived / "tests"
    old_tests.mkdir(parents=True)
    (derived / "IMPLEMENTATION_BRIEF.md").write_bytes(b"old brief\n")
    (old_tests / "test_old.py").write_bytes(b"def test_old() -> None:\n    pass\n")
    monkeypatch.chdir(repo)
    original_read = Ledger.read
    read_count = 0

    def first_read_only(self):
        nonlocal read_count
        read_count += 1
        if read_count > 1:
            raise LedgerValidationError("simulated unreadable commit status")
        return original_read(self)

    def raise_before_commit(self, facts, **kwargs):
        raise LedgerValidationError("simulated append failure")

    monkeypatch.setattr(Ledger, "read", first_read_only)
    monkeypatch.setattr(Ledger, "append_batch", raise_before_commit)

    assert main(["derive", "--case", intent.case_id, "--submit", str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "simulated append failure" in output.err
    assert not any(isinstance(fact, DerivationFact) for fact in original_read(Ledger.open(repo)))
    assert (derived / "IMPLEMENTATION_BRIEF.md").read_text().startswith("# Implementation brief")
    assert [item.name for item in (derived / "tests").iterdir()] == [
        "test_forbidden_retry_on_4xx.py"
    ]
    assert (derived / "tests" / "test_forbidden_retry_on_4xx.py").read_text() == new_stub
    assert {item.name for item in derived.iterdir() if item.name.startswith(".")} == {
        ".derive.lock"
    }


def test_concurrent_submissions_cannot_roll_back_a_committed_brief(tmp_path: Path) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent, forbidden, _dont_care = ruled_ledger(repo)
    facts = ledger.read()
    request = build_derivation_request(facts, intent.case_id)
    base = response_for(request, forbidden, reason="Not expressible")
    responses = {
        label: base.model_copy(
            update={
                "forbidden_tests": [
                    base.forbidden_tests[0].model_copy(
                        update={"unexpressible_reason": f"Not expressible response {label}."}
                    )
                ]
            }
        )
        for label in ("A", "B")
    }
    derived = repo / ".falsiq" / "cases" / intent.case_id / "derived"
    (derived / "tests").mkdir(parents=True)
    (derived / "IMPLEMENTATION_BRIEF.md").write_text("old brief\n", encoding="utf-8")
    a_append_started = Event()
    b_append_started = Event()

    def run_submission(label: str) -> tuple[str, bool]:
        def append(batch):
            if label == "A":
                a_append_started.set()
                b_append_started.wait(timeout=0.25)
            else:
                b_append_started.set()
            return ledger.append_batch(batch, expected_head=facts[-1].id)

        try:
            submit_derivation(
                repo,
                facts,
                responses[label],
                append_batch=append,
                fact_committed=lambda fact_id: any(fact.id == fact_id for fact in ledger.read()),
            )
        except LedgerValidationError:
            return label, False
        return label, True

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(run_submission, "A")
        assert a_append_started.wait(timeout=2)
        second = executor.submit(run_submission, "B")
        results = (first.result(timeout=3), second.result(timeout=3))

    committed = [label for label, success in results if success]
    assert len(committed) == 1
    brief = (derived / "IMPLEMENTATION_BRIEF.md").read_text(encoding="utf-8")
    assert f"Not expressible response {committed[0]}" in brief
    assert "old brief" not in brief


def test_submit_rejects_open_attack_even_with_a_preexisting_response(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger, intent, forbidden, _dont_care = ruled_ledger(repo)
    request = build_derivation_request(ledger.read(), intent.case_id)
    response = response_for(request, forbidden, reason="Not expressible")
    path = write_response(repo / "response.json", response)
    ledger.append(attack(6, intent, klass="conflict", decision="new ambiguity"))
    monkeypatch.chdir(repo)

    assert main(["derive", "--case", intent.case_id, "--submit", str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "open attacks" in output.err


def test_cli_rejects_malformed_or_extra_response_without_traceback(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = git_repo(tmp_path / "repo")
    _ledger, intent, _forbidden, _dont_care = ruled_ledger(repo)
    monkeypatch.chdir(repo)
    path = repo / "bad-response.json"
    path.write_text('{"unexpected": true}', encoding="utf-8")

    assert main(["derive", "--case", intent.case_id, "--submit", str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err.startswith("error:")
    assert "Traceback" not in output.err
