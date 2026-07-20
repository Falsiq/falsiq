from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
DEMO_DIR = ROOT / "docs" / "demos"
DEMO_CASES = (
    ("no_review_handoff.md", ("round 1 selected reviews: 0", "guard: passed")),
    (
        "collision_amendment.md",
        (
            "round 1 selected reviews: 1",
            "human ruling: amend",
            "round 2 selected reviews: 0",
            "guard: passed",
        ),
    ),
)

EXECUTABLE_BLOCK = re.compile(
    r"<!-- demo-test:start -->\n```sh\n(?P<script>.*?)\n```\n<!-- demo-test:end -->",
    re.DOTALL,
)


@pytest.mark.parametrize(("filename", "expected_output"), DEMO_CASES)
def test_markdown_demo_runs_end_to_end(
    tmp_path: Path,
    filename: str,
    expected_output: tuple[str, ...],
) -> None:
    tutorial = DEMO_DIR / filename
    text = tutorial.read_text(encoding="utf-8")
    match = EXECUTABLE_BLOCK.search(text)

    assert text.startswith("# ")
    assert "## What you'll learn" in text
    assert "## Run the demo" in text
    assert "## What happened" in text
    assert match is not None, "tutorial must contain one marked, executable shell block"
    assert len(EXECUTABLE_BLOCK.findall(text)) == 1

    env = os.environ.copy()
    env["TMPDIR"] = str(tmp_path)
    result = subprocess.run(
        ["sh"],
        input=match.group("script"),
        cwd=tmp_path,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    for line in expected_output:
        assert line in result.stdout


def test_demo_directory_contains_only_the_two_standalone_tutorials() -> None:
    assert sorted(path.name for path in DEMO_DIR.iterdir()) == sorted(
        filename for filename, _ in DEMO_CASES
    )


def test_readme_links_both_end_to_end_demos() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    for filename, _ in DEMO_CASES:
        assert f"docs/demos/{filename}" in readme
