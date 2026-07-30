from __future__ import annotations

from pathlib import Path

import pytest

from falsiq.domain_runtime import (
    RenderWorkspace,
    create_tmpdir_workspace,
    render_acceptance_check,
)


def test_tmpdir_backend_is_contained_and_requires_no_git(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "subprocess.run",
        lambda *args, **kwargs: pytest.fail("tmpdir backend must not invoke Git"),
    )
    root = tmp_path / "state"
    root.mkdir()

    workspace = create_tmpdir_workspace(root, "01ARZ3NDEKTSV4RRFFQ69G5FAV")

    assert isinstance(workspace, RenderWorkspace)
    assert workspace.backend == "tmpdir"
    assert workspace.path.parent == root / "render"
    assert workspace.path.is_dir()


@pytest.mark.parametrize(
    ("renderer", "strength"),
    [
        ("pytest", "executable"),
        ("command", "executable"),
        ("assertion", "executable"),
        ("checklist", "attested"),
    ],
)
def test_verification_renderers_label_strength_truthfully(renderer: str, strength: str) -> None:
    check = render_acceptance_check(renderer, "Confirm the greeting is welcoming.")
    assert check.renderer == renderer
    assert check.strength == strength
    assert "Confirm the greeting" in check.content
