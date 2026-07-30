"""Domain-neutral render workspaces and acceptance-check renderers."""

from __future__ import annotations

import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


class DomainRuntimeError(ValueError):
    """A render workspace or acceptance check is unsafe or unsupported."""


@dataclass(frozen=True, slots=True)
class RenderWorkspace:
    backend: Literal["tmpdir"]
    path: Path


@dataclass(frozen=True, slots=True)
class RenderedCheck:
    renderer: Literal["pytest", "command", "assertion", "checklist"]
    strength: Literal["executable", "attested"]
    content: str


def create_tmpdir_workspace(state_root: Path, case_id: str) -> RenderWorkspace:
    """Create a disposable render directory strictly beneath an existing state root."""

    metadata = state_root.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise DomainRuntimeError("state root must be an existing non-symlink directory")
    render_root = state_root / "render"
    if render_root.exists() and render_root.is_symlink():
        raise DomainRuntimeError("render root must not be a symbolic link")
    render_root.mkdir(mode=0o700, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix=f"{case_id}-", dir=render_root))
    return RenderWorkspace(backend="tmpdir", path=path)


def render_acceptance_check(
    renderer: Literal["pytest", "command", "assertion", "checklist"],
    statement: str,
) -> RenderedCheck:
    """Render inert acceptance-check text without executing it."""

    if not statement.strip():
        raise DomainRuntimeError("acceptance-check statement must not be blank")
    if renderer == "pytest":
        content = f"def test_acceptance() -> None:\n    raise NotImplementedError({statement!r})\n"
    elif renderer == "command":
        content = f"# Expected command-level acceptance:\n# {statement}\n"
    elif renderer == "assertion":
        content = f"assert observed_condition, {statement!r}\n"
    else:
        content = f"- [ ] {statement}\n"
    return RenderedCheck(
        renderer=renderer,
        strength="attested" if renderer == "checklist" else "executable",
        content=content,
    )


__all__ = [
    "DomainRuntimeError",
    "RenderWorkspace",
    "RenderedCheck",
    "create_tmpdir_workspace",
    "render_acceptance_check",
]
