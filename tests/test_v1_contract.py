from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from falsiq.brief import BriefContract, canonical_brief_json
from falsiq.rpc import RpcRequest

CONTRACT = Path(__file__).parents[1] / "contract"
FIXTURE_DIGESTS = {
    "brief.json": "8812131063e1d5d7cbab37db378d1b520d64b74a9b598090dcca50249f4bfe59",
    "request.json": "39f4ae74373b53ce890db1be13fb81cdc4b9277add13038f9196bd9bb85ca288",
    "response.json": "5d22d0baae2c83fddeae003f526fe4abe58494bc0204dc906b68607d930ac9ed",
}


def test_contract_version_and_schemas_are_published() -> None:
    version = (CONTRACT / "VERSION").read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"elicitation-contract/\d+\.\d+\.\d+", version)
    for name in ("brief", "request", "response"):
        schema = json.loads((CONTRACT / f"{name}.schema.json").read_text())
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_golden_fixtures_validate_against_runtime_contracts() -> None:
    request = RpcRequest.model_validate_json((CONTRACT / "fixtures" / "request.json").read_bytes())
    brief = BriefContract.model_validate_json((CONTRACT / "fixtures" / "brief.json").read_bytes())
    response = json.loads((CONTRACT / "fixtures" / "response.json").read_text())

    assert request.op == "state"
    assert canonical_brief_json(brief) + "\n" == (CONTRACT / "fixtures" / "brief.json").read_text()
    assert response == {"id": "fixture-1", "ok": True, "result": {"cases": []}}


def test_golden_fixtures_are_byte_stable() -> None:
    actual = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((CONTRACT / "fixtures").iterdir())
    }
    assert actual == FIXTURE_DIGESTS
