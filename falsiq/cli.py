from __future__ import annotations

import argparse
from collections.abc import Sequence

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="falsiq")
    parser.add_argument(
        "--version",
        action="version",
        version=f"falsiq {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        build_parser().parse_args(argv)
    except SystemExit as exc:
        if exc.code == 0:
            return 0
        raise
    return 0
