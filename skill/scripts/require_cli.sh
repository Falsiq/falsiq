#!/bin/sh
set -u

required_version='0.1.0'

if ! command -v falsiq >/dev/null 2>&1; then
    printf '%s\n' 'STOP -- FALSIQ CLI REQUIRED' \
        "Install falsiq==$required_version as an isolated console tool, then retry." >&2
    exit 2
fi

actual_version=$(falsiq --version 2>/dev/null) || {
    printf '%s\n' 'STOP -- FALSIQ CLI UNUSABLE' \
        "Reinstall falsiq==$required_version as an isolated console tool, then retry." >&2
    exit 2
}
if [ "$actual_version" != "falsiq $required_version" ]; then
    printf '%s\n' 'STOP -- FALSIQ CLI VERSION MISMATCH' \
        "Install falsiq==$required_version as an isolated console tool, then retry." >&2
    exit 2
fi
