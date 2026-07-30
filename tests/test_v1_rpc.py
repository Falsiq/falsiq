from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from falsiq.facts import IntentFact
from falsiq.ledger import Ledger
from falsiq.rpc import dispatch_request, serve


def initialized_external_ledger(tmp_path: Path, monkeypatch) -> Ledger:
    workspace = tmp_path / "workspace"
    state = tmp_path / "state"
    workspace.mkdir()
    state.mkdir()
    monkeypatch.chdir(workspace)
    monkeypatch.setenv("FALSIQ_STATE_ROOT", str(state))
    return Ledger.initialize()


def test_rpc_intent_and_state_have_cli_equivalent_semantics(tmp_path: Path, monkeypatch) -> None:
    initialized_external_ledger(tmp_path, monkeypatch)

    opened = dispatch_request(
        {
            "id": "open-1",
            "op": "intent",
            "params": {"text": "Draft a welcoming email"},
        }
    )
    assert opened["ok"] is True
    case_id = opened["result"]["case_id"]

    state = dispatch_request(
        {
            "id": "state-1",
            "op": "state",
            "params": {"case_id": case_id},
        }
    )
    assert state["ok"] is True
    assert state["result"]["intents"][0]["text"] == "Draft a welcoming email"


def test_rpc_is_one_request_and_response_per_line_and_recovers_after_error(
    tmp_path: Path, monkeypatch
) -> None:
    initialized_external_ledger(tmp_path, monkeypatch)
    source = io.StringIO(
        '{"id":"bad","op":"unknown","params":{}}\n{"id":"good","op":"state","params":{}}\n'
    )
    sink = io.StringIO()

    assert serve(source, sink) == 0

    responses = [json.loads(line) for line in sink.getvalue().splitlines()]
    assert [item["id"] for item in responses] == ["bad", "good"]
    assert responses[0]["ok"] is False
    assert responses[1]["ok"] is True


def test_rpc_rejects_paths_in_request_parameters(tmp_path: Path, monkeypatch) -> None:
    initialized_external_ledger(tmp_path, monkeypatch)
    response = dispatch_request(
        {
            "id": "path-1",
            "op": "derive.submit",
            "params": {"path": "../../outside.json"},
        }
    )
    assert response["ok"] is False
    assert "extra_forbidden" in response["error"]["message"]


def test_two_rpc_processes_append_safely_to_one_external_ledger(
    tmp_path: Path, monkeypatch
) -> None:
    ledger = initialized_external_ledger(tmp_path, monkeypatch)
    environment = {
        **os.environ,
        "FALSIQ_STATE_ROOT": str(ledger.state_dir),
    }

    def invoke(request_id: str) -> subprocess.CompletedProcess[str]:
        request = {
            "id": request_id,
            "op": "intent",
            "params": {"text": f"Concurrent intent {request_id}"},
        }
        return subprocess.run(
            [sys.executable, "-m", "falsiq", "rpc"],
            cwd=ledger.root,
            env=environment,
            input=json.dumps(request) + "\n",
            capture_output=True,
            text=True,
            check=False,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(invoke, ("one", "two")))

    assert all(result.returncode == 0 for result in results)
    responses = [json.loads(result.stdout) for result in results]
    assert all(response["ok"] is True for response in responses)
    assert len([fact for fact in ledger.read() if isinstance(fact, IntentFact)]) == 2


def test_rpc_module_has_no_model_network_or_process_runtime_surface() -> None:
    source = (Path(__file__).parents[1] / "falsiq" / "rpc.py").read_text()
    assert "subprocess" not in source
    assert "socket" not in source
    assert "openai" not in source.lower()
    assert "anthropic" not in source.lower()
