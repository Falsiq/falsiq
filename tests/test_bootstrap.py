from __future__ import annotations

import subprocess
import sys

import falsiq
from falsiq.cli import main


def test_package_exposes_version() -> None:
    assert falsiq.__version__ == "0.1.0"


def test_cli_prints_version(capsys) -> None:
    assert main(["--version"]) == 0
    assert capsys.readouterr().out == "falsiq 0.1.0\n"


def test_module_entrypoint_prints_version() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "falsiq", "--version"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout == "falsiq 0.1.0\n"
    assert result.stderr == ""
