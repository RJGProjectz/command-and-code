#!/usr/bin/env python3
"""decode-powershell.py - decode PowerShell -EncodedCommand payloads.

Accepts either a bare base64 string or a full command line; finds the argument
that follows any abbreviation of -EncodedCommand (-e, -ec, -enc, ... /e), decodes
it as UTF-16LE, and prints the script. Also reports nested base64 blobs passed to
FromBase64String so you can decode the next stage.

Read-only: nothing is executed.

Examples:
    python decode-powershell.py "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
    python decode-powershell.py SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=
    Get-Clipboard | python decode-powershell.py -          (read from stdin)

Part of Command & Code.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import re
import sys

ENC_ARG = re.compile(r"(?i)(?:^|\s)[-/]e[a-z]*\s+['\"]?([A-Za-z0-9+/=]{8,})")
NESTED_B64 = re.compile(r"(?i)FromBase64String\(\s*['\"]([A-Za-z0-9+/=]{16,})['\"]")
BARE_B64 = re.compile(r"^[A-Za-z0-9+/=\s]+$")


def b64decode(data: str) -> bytes:
    data = re.sub(r"\s+", "", data)
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data, validate=False)


def decode_utf16(data: str) -> str:
    return b64decode(data).decode("utf-16-le", errors="replace")


def extract_payload(text: str) -> str | None:
    text = text.strip()
    match = ENC_ARG.search(text)
    if match:
        return match.group(1)
    if BARE_B64.match(text) and len(text) >= 8:
        return text
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", help="command line or base64 string; '-' reads stdin")
    args = parser.parse_args(argv)

    text = sys.stdin.read() if args.input == "-" else args.input
    payload = extract_payload(text)
    if not payload:
        print("No -EncodedCommand argument or base64 string found.", file=sys.stderr)
        return 1

    try:
        script = decode_utf16(payload)
    except (binascii.Error, ValueError) as exc:
        print(f"Could not decode: {exc}", file=sys.stderr)
        return 1

    print("=== Decoded script (UTF-16LE) ===")
    print(script)

    nested = NESTED_B64.findall(script)
    for index, blob in enumerate(nested, start=1):
        raw = b64decode(blob)
        print(f"\n=== Nested FromBase64String blob {index} ({len(raw)} bytes) ===")
        if raw[:2] == b"\x1f\x8b":
            print("gzip-compressed data - decompress with: python -c \"import gzip,sys;sys.stdout.buffer.write(gzip.decompress(sys.stdin.buffer.read()))\"")
        elif len(raw) > 1 and raw[1:2] == b"\x00":
            print(raw.decode("utf-16-le", errors="replace"))
        else:
            printable = raw.decode("utf-8", errors="replace")
            print(printable if printable.isprintable() else repr(raw[:200]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
