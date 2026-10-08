#!/usr/bin/env bash
# Command & Code Terminal Companion CLI Wrapper (Bash)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
python3 "$DIR/cc_cli.py" "$@"
