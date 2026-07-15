#!/usr/bin/env python3
"""Compatibility wrapper for the installed ``falsiq attack assemble`` command."""

from __future__ import annotations

import sys

from falsiq.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["attack", "assemble", *sys.argv[1:]]))
