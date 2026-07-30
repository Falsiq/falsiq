from __future__ import annotations

from pathlib import Path

import pytest

from falsiq.profiles import ProfileError, load_profile


def test_packaged_profiles_cover_coding_and_non_coding_backends() -> None:
    coding = load_profile("coding")
    writing = load_profile("writing")

    assert coding.profile.backend == "git-worktree"
    assert writing.profile.backend == "tmpdir"
    assert "checklist" in writing.profile.verification_renderers
    assert len(coding.digest) == 64


def test_external_profile_is_digest_pinned_and_name_checked(tmp_path: Path) -> None:
    profile = tmp_path / "profile.toml"
    profile.write_text(
        "\n".join(
            [
                'name = "custom"',
                'artifact_label = "draft"',
                'backend = "tmpdir"',
                'verification_renderers = ["checklist"]',
                'collision_term = "choice"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    loaded = load_profile("custom", path=profile)
    assert loaded.profile.name == "custom"

    with pytest.raises(ProfileError, match="name mismatch"):
        load_profile("other", path=profile)
