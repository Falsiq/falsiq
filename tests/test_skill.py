from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from falsiq.attacks import AttackCandidate, AttackCandidateBatch, build_selection_envelope
from falsiq.derive import (
    DeriverResponse,
    ForbiddenTest,
    build_derivation_request,
    submit_derivation,
)
from falsiq.facts import (
    Artifact,
    AttackFact,
    IntentFact,
    OutcomeFact,
    RulingFact,
    new_ulid,
)
from falsiq.ledger import Ledger
from falsiq.workflow import (
    ATTACK_CLASSES,
    AssemblyError,
    AttackGenerationRequest,
    GuardError,
    assemble_attack_round,
    build_attack_request,
    canonical_attack_request_json,
    canonical_selection_json,
    prepare_attack_batch,
    ready_brief,
)

ROOT = Path(__file__).parents[1]
ASSEMBLE = ROOT / "skill" / "scripts" / "assemble_round.py"
GUARD = ROOT / "skill" / "scripts" / "guard_open_attacks.py"
REQUIRE_CLI = ROOT / "skill" / "scripts" / "require_cli.sh"
ATTACKERS = ATTACK_CLASSES


def git_repo(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    return path


def make_id(number: int) -> str:
    return new_ulid(timestamp_ms=number, randomness=number.to_bytes(10, "big"))


def candidate(case_id: str, klass: str, *, score: int = 1) -> AttackCandidate:
    decisions = [f"{klass} decision {index}" for index in range(score)]
    return AttackCandidate(
        klass=klass,
        targets=[case_id],
        artifact=Artifact(type="scenario", body=f"Observable {klass} behavior"),
        settles=decisions,
        silent_settles=decisions[:1],
        hate_scenario=f"The {klass} behavior loses user data.",
        render_cost="cheap" if klass == "prototype" else "trivial",
    )


def write_batches(directory: Path, case_id: str, *, empty: bool = False) -> list[Path]:
    paths: list[Path] = []
    for index, attacker in enumerate(ATTACKERS):
        batch = AttackCandidateBatch(
            case_id=case_id,
            attacker=attacker,
            candidates=[] if empty else [candidate(case_id, attacker, score=index + 1)],
        )
        path = directory / f"{attacker}.json"
        path.write_text(batch.model_dump_json(indent=2), encoding="utf-8")
        paths.append(path)
    return paths


def run_script(
    script: Path, *args: object, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *(str(arg) for arg in args)],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )


def run_installed_cli(
    *args: object, cwd: Path, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run the environment's console script as a target repo would."""

    executable = Path(sys.executable).with_name("falsiq")
    assert executable.is_file(), "tests require the installed falsiq console script"
    clean_env = os.environ.copy() if env is None else env.copy()
    clean_env.pop("PYTHONPATH", None)
    return subprocess.run(
        [str(executable), *(str(arg) for arg in args)],
        cwd=cwd,
        env=clean_env,
        check=False,
        capture_output=True,
        text=True,
    )


def test_assemble_round_is_input_order_independent_and_machine_verified(tmp_path: Path) -> None:
    case_id = make_id(1)
    paths = write_batches(tmp_path, case_id)

    direct_first = assemble_attack_round(case_id, 1, paths)
    direct_second = assemble_attack_round(case_id, 1, list(reversed(paths)))
    first = run_script(ASSEMBLE, "--case", case_id, "--round", 1, *paths)
    second = run_script(ASSEMBLE, "--case", case_id, "--round", 1, *reversed(paths))

    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == ""
    assert first.stdout == second.stdout
    assert direct_first == direct_second
    assert canonical_selection_json(direct_first) == first.stdout.strip()
    payload = json.loads(first.stdout)
    expected = build_selection_envelope(
        case_id,
        1,
        [candidate(case_id, attacker, score=index + 1) for index, attacker in enumerate(ATTACKERS)],
    )
    assert payload == expected.model_dump(mode="json")
    assert len(payload["selected"]) == 3


def test_assemble_round_preserves_degenerate_empty_pool(tmp_path: Path) -> None:
    case_id = make_id(1)
    paths = write_batches(tmp_path, case_id, empty=True)

    direct = assemble_attack_round(case_id, 1, paths)
    result = run_script(ASSEMBLE, "--case", case_id, "--round", 1, *paths)

    assert result.returncode == 0
    assert direct.candidates == []
    assert direct.selected == []
    assert json.loads(result.stdout)["candidates"] == []
    assert json.loads(result.stdout)["selected"] == []


def test_assemble_round_requires_exactly_one_batch_per_attacker(tmp_path: Path) -> None:
    case_id = make_id(1)
    paths = write_batches(tmp_path, case_id)

    missing = run_script(ASSEMBLE, "--case", case_id, "--round", 1, *paths[:-1])
    duplicate = run_script(
        ASSEMBLE,
        "--case",
        case_id,
        "--round",
        1,
        *paths[:-1],
        paths[0],
    )

    with pytest.raises(AssemblyError, match="exactly five"):
        assemble_attack_round(case_id, 1, paths[:-1])
    with pytest.raises(AssemblyError, match="duplicate attacker"):
        assemble_attack_round(case_id, 1, [*paths[:-1], paths[0]])
    assert missing.returncode == 2
    assert "exactly five" in missing.stderr
    assert duplicate.returncode == 2
    assert "duplicate attacker" in duplicate.stderr


@pytest.mark.parametrize("attacker", ATTACKERS)
def test_attack_request_carries_the_exact_schema_and_valid_examples(
    tmp_path: Path,
    attacker: str,
) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger = Ledger.initialize(repo)
    case_id = make_id(1)
    ledger.append(
        IntentFact(
            id=case_id,
            ts="2026-07-15T12:00:00.000Z",
            case_id=case_id,
            text="Add bounded retries",
            source="user",
        )
    )
    request = build_attack_request(ledger, case_id, attacker)

    assert request.attacker == attacker
    assert request.response_schema == AttackCandidateBatch.model_json_schema()
    if attacker == "conflict":
        assert "cases" in request.state
    else:
        assert request.state["case_id"] == case_id
    assert "Return only one JSON object" in request.instructions
    assert "Do not wrap it in Markdown" in request.instructions
    assert "response_schema" in request.instructions
    assert len(request.examples) == 2
    parsed_examples = [AttackCandidateBatch.model_validate(example) for example in request.examples]
    assert parsed_examples[0].candidates == []
    assert parsed_examples[1].candidates
    assert all(example.case_id == case_id for example in parsed_examples)
    assert all(example.attacker == attacker for example in parsed_examples)
    assert (
        AttackGenerationRequest.model_validate_json(canonical_attack_request_json(request))
        == request
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"{not json",
        b"{}",
        b'{"case_id":"duplicate","case_id":"wins"}',
        b'{"schema_version":1,"case_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV",'
        b'"attacker":"boundary","candidates":[],"commentary":"extra"}',
    ],
)
def test_prepare_attack_batch_replaces_invalid_agent_output_with_an_empty_batch(
    tmp_path: Path,
    payload: bytes,
) -> None:
    path = tmp_path / "attacker-output.json"
    path.write_bytes(payload)
    case_id = make_id(1)

    batch, degraded = prepare_attack_batch(case_id, "boundary", path)

    assert degraded is True
    assert batch == AttackCandidateBatch(
        case_id=case_id,
        attacker="boundary",
        candidates=[],
    )


def test_prepare_attack_batch_keeps_valid_agent_output(tmp_path: Path) -> None:
    case_id = make_id(1)
    expected = AttackCandidateBatch(
        case_id=case_id,
        attacker="boundary",
        candidates=[candidate(case_id, "boundary")],
    )
    path = tmp_path / "attacker-output.json"
    path.write_text(expected.model_dump_json(), encoding="utf-8")

    batch, degraded = prepare_attack_batch(case_id, "boundary", path)

    assert degraded is False
    assert batch == expected


@pytest.mark.parametrize("wrong_field", ["case_id", "attacker"])
def test_prepare_attack_batch_rejects_valid_schema_for_the_wrong_request_identity(
    tmp_path: Path,
    wrong_field: str,
) -> None:
    case_id = make_id(1)
    payload = AttackCandidateBatch(
        case_id=make_id(2) if wrong_field == "case_id" else case_id,
        attacker="omission" if wrong_field == "attacker" else "boundary",
        candidates=[],
    )
    path = tmp_path / "wrong-identity.json"
    path.write_text(payload.model_dump_json(), encoding="utf-8")

    batch, degraded = prepare_attack_batch(case_id, "boundary", path)

    assert degraded is True
    assert batch.case_id == case_id
    assert batch.attacker == "boundary"
    assert batch.candidates == []


def test_prepare_attack_batch_contains_unsafe_response_files(tmp_path: Path) -> None:
    case_id = make_id(1)
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    symlink = tmp_path / "output.json"
    symlink.symlink_to(target.name)

    symlink_batch, symlink_degraded = prepare_attack_batch(case_id, "boundary", symlink)

    assert symlink_degraded is True
    assert symlink_batch.candidates == []


def test_assemble_round_rejects_case_mismatch_and_symlink_input(tmp_path: Path) -> None:
    case_id = make_id(1)
    paths = write_batches(tmp_path, case_id)
    mismatched = AttackCandidateBatch(case_id=make_id(2), attacker="boundary", candidates=[])
    paths[0].write_text(mismatched.model_dump_json(), encoding="utf-8")

    mismatch = run_script(ASSEMBLE, "--case", case_id, "--round", 1, *paths)

    with pytest.raises(AssemblyError, match="case mismatch"):
        assemble_attack_round(case_id, 1, paths)
    assert mismatch.returncode == 2
    assert "case mismatch" in mismatch.stderr

    paths = write_batches(tmp_path, case_id)
    target = tmp_path / "boundary-target.json"
    paths[0].replace(target)
    paths[0].symlink_to(target.name)
    symlink = run_script(ASSEMBLE, "--case", case_id, "--round", 1, *paths)
    with pytest.raises(AssemblyError, match="symlink"):
        assemble_attack_round(case_id, 1, paths)
    assert symlink.returncode == 2
    assert "symlink" in symlink.stderr


def test_guard_blocks_open_attacks_and_missing_derivation(tmp_path: Path) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger = Ledger.initialize(repo)
    case_id = make_id(1)
    intent = IntentFact(
        id=case_id,
        ts="2026-07-15T12:00:00.000Z",
        case_id=case_id,
        text="Add bounded retries",
        source="user",
    )
    ledger.append(intent)

    missing = run_script(GUARD, "--case", case_id, cwd=repo)
    with pytest.raises(GuardError, match="no current derivation"):
        ready_brief(case_id, repo)
    assert missing.returncode == 2
    assert "no current derivation" in missing.stderr

    probe = AttackFact(
        id=make_id(2),
        ts="2026-07-15T12:00:00.000Z",
        case_id=case_id,
        klass="boundary",
        targets=[case_id],
        artifact=Artifact(type="scenario", body="The upstream returns 429."),
        settles=["retry 429"],
        silent_settles=["retry 429"],
        hate_scenario="The client overloads the upstream.",
        render_cost="trivial",
        round=1,
    )
    ledger.append(probe)
    opened = run_script(GUARD, "--case", case_id, cwd=repo)
    with pytest.raises(GuardError, match="1 open attack"):
        ready_brief(case_id, repo)
    assert opened.returncode == 2
    assert "1 open attack" in opened.stderr


def test_guard_allows_only_the_current_safe_derived_brief(tmp_path: Path) -> None:
    repo = git_repo(tmp_path / "repo")
    ledger = Ledger.initialize(repo)
    case_id = make_id(1)
    intent = IntentFact(
        id=case_id,
        ts="2026-07-15T12:00:00.000Z",
        case_id=case_id,
        text="Add bounded retries",
        source="user",
    )
    probe = AttackFact(
        id=make_id(2),
        ts="2026-07-15T12:00:00.000Z",
        case_id=case_id,
        klass="boundary",
        targets=[case_id],
        artifact=Artifact(type="scenario", body="The upstream returns 429."),
        settles=["retry 429"],
        hate_scenario="The client overloads the upstream.",
        render_cost="trivial",
        round=1,
    )
    ruling = RulingFact(
        id=make_id(3),
        ts="2026-07-15T12:00:00.000Z",
        case_id=case_id,
        attack_id=probe.id,
        verdict="forbidden",
    )
    ledger.append_batch([intent, probe, ruling])
    facts = ledger.read()
    request = build_derivation_request(facts, case_id)
    response = DeriverResponse(
        request_id=request.request_id,
        case_id=case_id,
        ledger_head=request.ledger_head,
        forbidden_tests=[
            ForbiddenTest(
                ruling_id=ruling.id,
                filename="test_no_unbounded_retry.py",
                content="def test_no_unbounded_retry() -> None:\n    pass\n",
            )
        ],
    )
    submit_derivation(
        repo,
        facts,
        response,
        append_batch=lambda batch: ledger.append_batch(batch, expected_head=facts[-1].id),
        fact_committed=lambda fact_id: any(fact.id == fact_id for fact in ledger.read()),
    )

    allowed = run_script(GUARD, "--case", case_id, cwd=repo)
    direct_ledger, direct_brief = ready_brief(case_id, repo)
    assert allowed.returncode == 0
    assert allowed.stderr == ""
    assert allowed.stdout.strip() == (f".falsiq/cases/{case_id}/derived/IMPLEMENTATION_BRIEF.md")
    assert direct_ledger.root == repo.resolve()
    assert direct_brief == repo / allowed.stdout.strip()

    brief = repo / allowed.stdout.strip()
    original = brief.read_bytes()
    brief.write_bytes(original + b"tampered\n")
    tampered_brief = run_script(GUARD, "--case", case_id, cwd=repo)
    with pytest.raises(GuardError, match="digest mismatch"):
        ready_brief(case_id, repo)
    assert tampered_brief.returncode == 2
    assert "digest mismatch" in tampered_brief.stderr

    brief.write_bytes(original)
    brief.unlink()
    missing_brief = run_script(GUARD, "--case", case_id, cwd=repo)
    with pytest.raises(GuardError, match="derived brief is unavailable"):
        ready_brief(case_id, repo)
    assert missing_brief.returncode == 2
    assert "derived brief is unavailable" in missing_brief.stderr

    outside = repo / "outside.md"
    outside.write_bytes(original)
    brief.symlink_to(os.path.relpath(outside, brief.parent))
    unsafe = run_script(GUARD, "--case", case_id, cwd=repo)
    with pytest.raises(GuardError, match="symlink"):
        ready_brief(case_id, repo)
    assert unsafe.returncode == 2
    assert "symlink" in unsafe.stderr

    brief.unlink()
    brief.write_bytes(original)
    tests_dir = brief.parent / "tests"
    stub = tests_dir / "test_no_unbounded_retry.py"
    stub_original = stub.read_bytes()
    stub.write_bytes(stub_original + b"# edited\n")
    tampered_stub = run_script(GUARD, "--case", case_id, cwd=repo)
    with pytest.raises(GuardError, match="digest mismatch"):
        ready_brief(case_id, repo)
    assert tampered_stub.returncode == 2
    assert "digest mismatch" in tampered_stub.stderr

    stub.write_bytes(stub_original)
    stub.unlink()
    missing_stub = run_script(GUARD, "--case", case_id, cwd=repo)
    with pytest.raises(GuardError, match="missing derived test stubs"):
        ready_brief(case_id, repo)
    assert missing_stub.returncode == 2
    assert "missing derived test stubs" in missing_stub.stderr

    outside_stub = repo / "outside_stub.py"
    outside_stub.write_bytes(stub_original)
    stub.symlink_to(os.path.relpath(outside_stub, stub.parent))
    symlinked_stub = run_script(GUARD, "--case", case_id, cwd=repo)
    with pytest.raises(GuardError, match="symlink"):
        ready_brief(case_id, repo)
    assert symlinked_stub.returncode == 2
    assert "symlink" in symlinked_stub.stderr

    stub.unlink()
    stub.write_bytes(stub_original)
    extra = tests_dir / "test_uncommitted.py"
    extra.write_text("def test_extra() -> None:\n    pass\n", encoding="utf-8")
    extra_stub = run_script(GUARD, "--case", case_id, cwd=repo)
    with pytest.raises(GuardError, match="unexpected derived test stubs"):
        ready_brief(case_id, repo)
    assert extra_stub.returncode == 2
    assert "unexpected derived test stubs" in extra_stub.stderr
    extra.unlink()

    ledger.append(
        OutcomeFact(
            id=make_id(4),
            ts="2026-07-15T12:00:00.000Z",
            case_id=case_id,
            otype="accepted",
            trace="n/a",
            notes="The implementation passed review.",
        )
    )
    after_outcome = run_script(GUARD, "--case", case_id, cwd=repo)
    _ledger_after_outcome, brief_after_outcome = ready_brief(case_id, repo)
    assert after_outcome.returncode == 0
    assert brief_after_outcome == brief

    ledger.append(
        RulingFact(
            id=make_id(5),
            ts="2026-07-15T12:00:00.000Z",
            case_id=case_id,
            attack_id=probe.id,
            verdict="dont_care",
            supersedes=ruling.id,
        )
    )
    after_reruling = run_script(GUARD, "--case", case_id, cwd=repo)
    with pytest.raises(GuardError, match="rulings changed after derive"):
        ready_brief(case_id, repo)
    assert after_reruling.returncode == 2
    assert "rulings changed after derive" in after_reruling.stderr


def test_skill_contract_and_scripted_transcript_encode_human_barriers() -> None:
    skill = (ROOT / "skill" / "SKILL.md").read_text(encoding="utf-8")
    transcript = (ROOT / "skill" / "fixtures" / "workflow_transcript.md").read_text(
        encoding="utf-8"
    )

    required_skill_phrases = (
        "STOP -- HUMAN RULING REQUIRED",
        "Never infer, suggest, or execute a ruling",
        "skip falsiq",
        "outcome abandoned --case",
        "--trace n/a",
        "exactly five fresh attackers",
        "At most two rounds",
        "IMPLEMENTATION_BRIEF.md",
        "Read the regular request file",
        "full global state",
        "command -v falsiq",
        "STOP -- FALSIQ CLI REQUIRED",
        "falsiq==0.1.0",
        "falsiq attack assemble",
        "falsiq attack request",
        "falsiq attack prepare",
        "disclose the degraded coverage",
        "falsiq guard --case",
        "untrusted model output",
        "Inspect every generated test stub completely",
        "Never run, import, copy, or merge them as-is",
        "translate each forbidden behavior into a new repository-native failing test",
        "${SKILL_DIR}/scripts/require_cli.sh",
        ".agents/skills/falsiq",
        ".claude/skills/falsiq",
    )
    assert all(phrase in skill for phrase in required_skill_phrases)
    assert "uv run" not in skill
    assert "${CLAUDE_PROJECT_DIR}/agents/" not in skill
    assert "${SKILL_DIR}/references/" not in skill

    complete_barrier = (
        "STOP -- HUMAN RULING REQUIRED\n"
        "No implementation has started. Reply with an explicit ruling for every "
        "displayed attack."
    )
    assert complete_barrier in skill
    assert complete_barrier in transcript
    normalized_skill = " ".join(skill.split())
    assert "case-sensitive standalone line" in normalized_skill
    assert "after trimming surrounding whitespace" in normalized_skill
    assert "Surrounding prose, synonyms, and case variants do not bypass" in normalized_skill
    assert "declared compatible CLI version" in normalized_skill
    assert "exactly matches this skill" not in skill
    assert "Resolve `${SKILL_DIR}` once per session" in normalized_skill
    assert "Under Claude Code that is exactly `${CLAUDE_SKILL_DIR}`" in normalized_skill
    assert "Under Cursor, Codex, or another generic agent host" in normalized_skill

    forbidden = transcript.index("$ falsiq rule <ATTACK> forbidden")
    round_two_agents = transcript.index(
        "[five fresh class-specific attackers run in parallel for round 2]"
    )
    round_two_assembly = transcript.index("$ falsiq attack assemble --case <CASE> --round 2")
    derivation = transcript.index("$ falsiq derive --case <CASE>")
    assert forbidden < round_two_agents < round_two_assembly < derivation
    assert "round-two gate does not pass" not in transcript

    ordered_transcript_phrases = (
        "$ falsiq intent",
        "$ falsiq attack assemble",
        "$ falsiq collide --case",
        "STOP -- HUMAN RULING REQUIRED",
        "[user supplies explicit rulings]",
        "$ falsiq rule",
        "$ falsiq derive --case",
        "$ cat <request.json>",
        "$ falsiq derive --case <CASE> --submit",
        "$ falsiq guard --case",
        "[implementation begins from IMPLEMENTATION_BRIEF.md]",
        "$ falsiq outcome abandoned --case <CASE> --trace n/a",
    )
    positions = [transcript.index(phrase) for phrase in ordered_transcript_phrases]
    assert positions == sorted(positions)


def test_production_prompts_have_one_packaged_source_of_truth() -> None:
    skill = (ROOT / "skill" / "SKILL.md").read_text(encoding="utf-8")
    prompt_dir = ROOT / "falsiq" / "prompts"
    prompt_names = tuple(f"attacker_{attacker}.md" for attacker in ATTACKERS) + ("deriver.md",)

    assert {path.name for path in prompt_dir.glob("*.md")} == set(prompt_names)
    assert not (ROOT / "skill" / "references").exists()
    for prompt_name in prompt_names:
        assert not (ROOT / "agents" / prompt_name).exists()
        assert f"${{SKILL_DIR}}/references/{prompt_name}" not in skill


def test_cli_prerequisite_fails_closed_with_actionable_missing_executable(
    tmp_path: Path,
) -> None:
    empty_path = tmp_path / "empty-path"
    empty_path.mkdir()

    result = subprocess.run(
        ["/bin/sh", str(REQUIRE_CLI)],
        env={"PATH": str(empty_path)},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "STOP -- FALSIQ CLI REQUIRED" in result.stderr
    assert "Install falsiq==0.1.0 as an isolated console tool" in result.stderr


def test_cli_prerequisite_rejects_mismatch_and_accepts_installed_version(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    fake_cli = fake_bin / "falsiq"
    fake_cli.write_text("#!/bin/sh\nprintf '%s\\n' 'falsiq 9.9.9'\n", encoding="utf-8")
    fake_cli.chmod(0o700)

    mismatched = subprocess.run(
        ["/bin/sh", str(REQUIRE_CLI)],
        env={"PATH": str(fake_bin)},
        check=False,
        capture_output=True,
        text=True,
    )
    assert mismatched.returncode == 2
    assert "STOP -- FALSIQ CLI VERSION MISMATCH" in mismatched.stderr

    installed = Path(sys.executable).with_name("falsiq")
    accepted = subprocess.run(
        ["/bin/sh", str(REQUIRE_CLI)],
        env={"PATH": str(installed.parent)},
        check=False,
        capture_output=True,
        text=True,
    )
    assert accepted.returncode == 0
    assert accepted.stdout == accepted.stderr == ""


def test_installed_console_workflow_is_portable_to_a_repo_without_project_files(
    tmp_path: Path,
) -> None:
    """Exercise the skill-facing commands without a source checkout in the target."""

    target = git_repo(tmp_path / "target")
    assert not (target / "pyproject.toml").exists()
    assert not (target / "falsiq").exists()
    placed_skill = target / ".claude" / "skills" / "falsiq"
    shutil.copytree(ROOT / "skill", placed_skill)
    assert (placed_skill / "SKILL.md").is_file()
    assert not (placed_skill / "references").exists()

    initialized = run_installed_cli("init", cwd=target)
    assert initialized.returncode == 0, initialized.stderr
    opened = run_installed_cli("intent", "Add bounded retries", cwd=target)
    assert opened.returncode == 0, opened.stderr
    case_id = opened.stdout.strip()

    requested_attacker = run_installed_cli(
        "attack",
        "request",
        "--case",
        case_id,
        "--attacker",
        "boundary",
        cwd=target,
    )
    assert requested_attacker.returncode == 0, requested_attacker.stderr
    attacker_request = json.loads(requested_attacker.stdout)
    assert attacker_request["response_schema"] == AttackCandidateBatch.model_json_schema()

    malformed_path = tmp_path / "malformed-attacker.json"
    malformed_path.write_text("not json", encoding="utf-8")
    prepared_attacker = run_installed_cli(
        "attack",
        "prepare",
        "--case",
        case_id,
        "--attacker",
        "boundary",
        "--file",
        malformed_path,
        cwd=target,
    )
    assert prepared_attacker.returncode == 0
    assert "replaced by an empty batch" in prepared_attacker.stderr
    assert json.loads(prepared_attacker.stdout)["candidates"] == []

    batches_dir = tmp_path / "private-batches"
    batches_dir.mkdir()
    batch_paths = write_batches(batches_dir, case_id)
    assembled = run_installed_cli(
        "attack",
        "assemble",
        "--case",
        case_id,
        "--round",
        1,
        *batch_paths,
        cwd=target,
    )
    assert assembled.returncode == 0, assembled.stderr
    envelope = json.loads(assembled.stdout)
    assert len(envelope["selected"]) == 3
    round_path = batches_dir / "round.json"
    round_path.write_text(assembled.stdout, encoding="utf-8")

    appended = run_installed_cli("attack", "add", "--file", round_path, cwd=target)
    assert appended.returncode == 0, appended.stderr
    attack_ids = appended.stdout.splitlines()
    assert len(attack_ids) == 3
    collision = run_installed_cli("collide", "--case", case_id, cwd=target)
    assert collision.returncode == 0, collision.stderr
    assert Path(collision.stdout.strip()).is_file()

    for attack_id in attack_ids:
        ruled = run_installed_cli("rule", attack_id, "dont_care", cwd=target)
        assert ruled.returncode == 0, ruled.stderr

    requested = run_installed_cli("derive", "--case", case_id, cwd=target)
    assert requested.returncode == 0, requested.stderr
    request_path = Path(requested.stdout.strip())
    request = json.loads(request_path.read_text(encoding="utf-8"))
    response_path = batches_dir / "deriver-response.json"
    response_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "request_id": request["request_id"],
                "case_id": request["case_id"],
                "ledger_head": request["ledger_head"],
                "forbidden_tests": [],
            }
        ),
        encoding="utf-8",
    )
    submitted = run_installed_cli(
        "derive", "--case", case_id, "--submit", response_path, cwd=target
    )
    assert submitted.returncode == 0, submitted.stderr
    guarded = run_installed_cli("guard", "--case", case_id, cwd=target)
    assert guarded.returncode == 0, guarded.stderr
    assert guarded.stdout.strip() == (f".falsiq/cases/{case_id}/derived/IMPLEMENTATION_BRIEF.md")
    assert (target / guarded.stdout.strip()).is_file()


def test_claude_project_discovery_is_a_single_source_directory_symlink() -> None:
    discovery = ROOT / ".claude" / "skills" / "falsiq"

    assert discovery.is_symlink()
    assert os.readlink(discovery) == "../../skill"
    assert discovery.resolve() == (ROOT / "skill").resolve()
    assert (discovery / "SKILL.md").samefile(ROOT / "skill" / "SKILL.md")
    assert (discovery / "scripts" / "assemble_round.py").samefile(ASSEMBLE)


def test_agents_project_discovery_is_a_single_source_directory_symlink() -> None:
    """Cursor, Codex, and generic agents discover the skill via .agents/skills/."""

    discovery = ROOT / ".agents" / "skills" / "falsiq"

    assert discovery.is_symlink()
    assert os.readlink(discovery) == "../../skill"
    assert discovery.resolve() == (ROOT / "skill").resolve()
    assert (discovery / "SKILL.md").samefile(ROOT / "skill" / "SKILL.md")
    assert (discovery / "scripts" / "assemble_round.py").samefile(ASSEMBLE)
