from __future__ import annotations

import io
import json
from pathlib import Path

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
