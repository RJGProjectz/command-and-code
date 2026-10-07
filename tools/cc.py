#!/usr/bin/env python3
"""Command & Code repository tooling.

Usage:
    python tools/cc.py validate        Check front matter against the conventions
    python tools/cc.py index           Regenerate browse tables in place
    python tools/cc.py index --check   Fail if browse tables are out of date
    python tools/cc.py code            Syntax-check fenced code blocks and scripts
    python tools/cc.py check           validate + index --check (what CI runs)
    python tools/cc.py list            Print every entry with its metadata (TSV)

Browse tables
-------------
Any Markdown page can contain a generated table of entries that match a
metadata filter. Write the markers once; `index` fills in the rows:

    <!-- cc:index languages="PowerShell" -->
    <!-- /cc:index -->

Filters are ANDed. Supported keys: platforms, languages, tasks, type, category.
Use `|` for OR within one key: tasks="Hardening|Administration".

The generated rows are committed, so the tables also render on GitHub and in
any Markdown viewer. Only the Python standard library and PyYAML are used.
"""

from __future__ import annotations

import datetime as dt
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SCRIPTS = ROOT / "scripts"
VOCAB = yaml.safe_load((ROOT / "tools" / "vocabulary.yml").read_text(encoding="utf-8"))

LIST_KEYS = ("platforms", "languages", "tasks")
CONTENT_TYPES = {"entry", "workflow", "tool", "reference"}
VERIFY_BANNER = "VERIFY BEFORE PRODUCTION USE"
INDEX_RE = re.compile(r"(<!-- cc:index(?P<attrs>[^>]*?)-->)(?P<body>.*?)(<!-- /cc:index -->)", re.S)
ATTR_RE = re.compile(r'(\w+)="([^"]*)"')
FENCE_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<fence>`{3,})(?P<lang>[\w+-]*)[^\n]*\n(?P<code>.*?)^(?P=indent)(?P=fence)[ \t]*$", re.S | re.M)


@dataclass
class Page:
    path: Path
    meta: dict = field(default_factory=dict)
    body: str = ""
    error: str | None = None

    @property
    def rel(self) -> str:
        return self.path.relative_to(DOCS).as_posix()

    @property
    def type(self) -> str:
        default = "index" if self.path.name == "index.md" else "entry"
        return str(self.meta.get("type", default))

    @property
    def title(self) -> str:
        if self.meta.get("title"):
            return str(self.meta["title"])
        match = re.search(r"^# (.+)$", self.body, re.M)
        return match.group(1).strip() if match else self.path.stem


def load_page(path: Path) -> Page:
    text = path.read_text(encoding="utf-8")
    page = Page(path=path, body=text)
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end == -1:
            page.error = "front matter is not closed with ---"
            return page
        try:
            page.meta = yaml.safe_load(text[4:end]) or {}
        except yaml.YAMLError as exc:
            page.error = f"malformed YAML: {exc}"
            return page
        if not isinstance(page.meta, dict):
            page.error = "front matter must be a mapping"
            page.meta = {}
        page.body = text[end + 5 :]
    return page


def all_pages() -> list[Page]:
    return [load_page(p) for p in sorted(DOCS.rglob("*.md"))]


# --------------------------------------------------------------------------- validate


def validate(pages: list[Page]) -> list[str]:
    problems: list[str] = []
    titles: dict[str, str] = {}
    for page in pages:
        where = page.rel
        if page.error:
            problems.append(f"{where}: {page.error}")
            continue
        meta = page.meta
        if page.type not in VOCAB["types"]:
            problems.append(f"{where}: unknown type '{page.type}'")
        for key in LIST_KEYS:
            if key in meta:
                if not isinstance(meta[key], list):
                    problems.append(f"{where}: '{key}' must be a list")
                    continue
                for value in meta[key]:
                    if value not in VOCAB[key]:
                        problems.append(f"{where}: '{value}' is not a known {key[:-1]} (see tools/vocabulary.yml)")
        for key in ("tags", "aliases"):
            if key in meta and not isinstance(meta[key], list):
                problems.append(f"{where}: '{key}' must be a list")
        if "difficulty" in meta and meta["difficulty"] not in VOCAB["difficulty"]:
            problems.append(f"{where}: difficulty must be one of {VOCAB['difficulty']}")

        if page.type not in CONTENT_TYPES:
            continue
        if not meta.get("title"):
            problems.append(f"{where}: missing required 'title'")
        if not meta.get("tasks"):
            problems.append(f"{where}: missing required 'tasks'")
        if not (meta.get("platforms") or meta.get("languages")):
            problems.append(f"{where}: needs at least one of 'platforms' or 'languages'")
        if not isinstance(meta.get("verified"), bool):
            problems.append(f"{where}: 'verified' must be true or false")
        elif meta["verified"]:
            if not isinstance(meta.get("last_verified"), dt.date):
                problems.append(f"{where}: verified pages need 'last_verified: YYYY-MM-DD'")
        elif VERIFY_BANNER not in page.body:
            problems.append(f"{where}: verified: false pages must state '{VERIFY_BANNER}'")
        if not re.search(r"^# .+", page.body, re.M):
            problems.append(f"{where}: missing a top-level '# Heading'")
        title = str(meta.get("title", "")).lower()
        if title in titles:
            problems.append(f"{where}: duplicate title also used by {titles[title]}")
        titles[title] = where
    return problems


# --------------------------------------------------------------------------- index


def _matches(page: Page, filters: dict[str, str]) -> bool:
    for key, wanted in filters.items():
        options = {w.strip() for w in wanted.split("|")}
        if key in LIST_KEYS:
            if not options & set(page.meta.get(key) or []):
                return False
        elif key == "type":
            if page.type not in options:
                return False
        elif key == "category":
            if str(page.meta.get("category", "")) not in options:
                return False
        else:
            raise ValueError(f"unknown filter key '{key}'")
    return True


def render_table(host: Page, filters: dict[str, str], pages: list[Page]) -> str:
    hits = [p for p in pages if p.type in CONTENT_TYPES and p.path != host.path and _matches(p, filters)]
    order = {"workflow": 0, "entry": 1, "tool": 2, "reference": 3}
    hits.sort(key=lambda p: (order.get(p.type, 9), p.title.lower()))
    if not hits:
        return "\n_No entries yet._\n"
    base = posixpath.dirname(host.rel) or "."
    rows = ["", "| Entry | Type | Platforms | Languages | Tasks |", "| --- | --- | --- | --- | --- |"]
    for p in hits:
        link = posixpath.relpath(p.rel, base)
        cells = [
            f"[{p.title}]({link})",
            p.type.capitalize(),
            ", ".join(p.meta.get("platforms") or []) or "—",
            ", ".join(p.meta.get("languages") or []) or "—",
            ", ".join(p.meta.get("tasks") or []),
        ]
        rows.append("| " + " | ".join(cells) + " |")
    return "\n".join(rows) + "\n\n"


def build_indexes(pages: list[Page], check: bool) -> list[str]:
    stale: list[str] = []
    for host in pages:
        text = host.path.read_text(encoding="utf-8")
        if "<!-- cc:index" not in text:
            continue

        def replace(match: re.Match) -> str:
            filters = dict(ATTR_RE.findall(match.group("attrs")))
            return match.group(1) + render_table(host, filters, pages) + match.group(4)

        fenced = [(m.start(), m.end()) for m in FENCE_RE.finditer(text)]

        def replace_outside_code(match: re.Match) -> str:
            if any(start <= match.start() < end for start, end in fenced):
                return match.group(0)  # example markers inside code blocks are left alone
            return replace(match)

        new_text = INDEX_RE.sub(replace_outside_code, text)
        if new_text != text:
            stale.append(host.rel)
            if not check:
                host.path.write_text(new_text, encoding="utf-8")
    return stale


# --------------------------------------------------------------------------- code


def _code_blocks(text: str):
    for match in FENCE_RE.finditer(text):
        lang = match.group("lang").lower()
        indent = match.group("indent")
        code = "\n".join(line[len(indent):] if line.startswith(indent) else line for line in match.group("code").splitlines())
        yield lang, code, text[: match.start()].count("\n") + 1


def check_code() -> list[str]:
    """Parse every PowerShell/Bash/Python/YAML block and every script.

    PowerShell blocks are parsed (not executed) with the PowerShell language
    parser when `pwsh` is on PATH; otherwise they are skipped with a notice.
    """
    problems: list[str] = []
    pwsh = shutil.which("pwsh")
    shellcheck = shutil.which("shellcheck")
    ps_items: list[tuple[str, str]] = []

    def add_bash(label: str, code: str) -> None:
        code_bytes = code.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
        result = subprocess.run(["bash", "-n"], input=code_bytes, capture_output=True)
        if result.returncode:
            problems.append(f"{label}: bash: {result.stderr.decode('utf-8', errors='replace').strip()}")

    for page in all_pages():
        for lang, code, line in _code_blocks(page.path.read_text(encoding="utf-8")):
            label = f"docs/{page.rel}:{line}"
            if "--8<--" in code:
                continue  # snippet include; the included script is checked directly below
            if lang in ("powershell", "ps1", "pwsh"):
                ps_items.append((label, code))
            elif lang in ("bash", "sh"):
                add_bash(label, code)
            elif lang == "python":
                try:
                    compile(code, label, "exec")
                except SyntaxError as exc:
                    problems.append(f"{label}: python: {exc}")
            elif lang == "yaml":
                try:
                    list(yaml.safe_load_all(code))
                except yaml.YAMLError as exc:
                    problems.append(f"{label}: yaml: {exc}")

    for script in sorted(SCRIPTS.rglob("*")):
        rel = script.relative_to(ROOT).as_posix()
        if script.suffix == ".ps1":
            ps_items.append((rel, script.read_text(encoding="utf-8")))
        elif script.suffix == ".sh":
            add_bash(rel, script.read_text(encoding="utf-8"))
            if shellcheck:
                result = subprocess.run([shellcheck, "-S", "error", str(script)], text=True, encoding="utf-8", capture_output=True)
                if result.returncode:
                    problems.append(f"{rel}: shellcheck:\n{result.stdout.strip()}")
        elif script.suffix == ".py":
            try:
                compile(script.read_text(encoding="utf-8"), rel, "exec")
            except SyntaxError as exc:
                problems.append(f"{rel}: python: {exc}")

    if ps_items and not pwsh:
        print(f"note: pwsh not found; skipped {len(ps_items)} PowerShell blocks")
    elif ps_items:
        (ROOT / "scratch").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "scratch") as tmp:
            paths = []
            for n, (label, code) in enumerate(ps_items):
                path = Path(tmp) / f"block{n}.ps1"
                path.write_text(code, encoding="utf-8")
                paths.append((label, path))
            listing = Path(tmp) / "files.txt"
            listing.write_text("\n".join(f"{p}\t{label}" for label, p in paths), encoding="utf-8")
            script_file = Path(tmp) / "parse.ps1"
            script_file.write_text(
                "param($listPath)\n"
                "$ErrorActionPreference = 'SilentlyContinue'\n"
                "foreach($row in Get-Content -LiteralPath $listPath){\n"
                "  $parts = $row -split \"`t\",2\n"
                "  if ($parts.Count -lt 2) { continue }\n"
                "  $f = $parts[0]; $l = $parts[1]; $t = $null; $e = $null\n"
                "  [void][System.Management.Automation.Language.Parser]::ParseFile($f,[ref]$t,[ref]$e)\n"
                "  foreach($x in $e){ Write-Output \"$l (line $($x.Extent.StartLineNumber)): $($x.Message)\" }\n"
                "}\n",
                encoding="utf-8"
            )
            result = subprocess.run([pwsh, "-NoProfile", "-NonInteractive", "-File", str(script_file), str(listing)], text=True, encoding="utf-8", capture_output=True)
            for line in result.stdout.splitlines():
                if line.strip():
                    problems.append(f"powershell: {line.strip()}")
            if result.returncode:
                problems.append(f"powershell parser failed: {result.stderr.strip()}")
    return problems


# --------------------------------------------------------------------------- main


def main(argv: list[str]) -> int:
    command = argv[1] if len(argv) > 1 else "check"
    pages = all_pages()

    if command == "validate":
        problems = validate(pages)
    elif command == "index":
        check = "--check" in argv
        stale = build_indexes(pages, check=check)
        if check and stale:
            problems = [f"{s}: browse table out of date (run: python tools/cc.py index)" for s in stale]
        else:
            for s in stale:
                print(f"updated {s}")
            problems = []
    elif command == "code":
        problems = check_code()
    elif command == "check":
        problems = validate(pages)
        problems += [f"{s}: browse table out of date (run: python tools/cc.py index)" for s in build_indexes(pages, check=True)]
    elif command == "list":
        for p in pages:
            if p.type in CONTENT_TYPES:
                print("\t".join([p.rel, p.type, p.title, ",".join(p.meta.get("platforms") or []),
                                 ",".join(p.meta.get("languages") or []), ",".join(p.meta.get("tasks") or []),
                                 str(p.meta.get("verified"))]))
        return 0
    else:
        print(__doc__)
        return 2

    for problem in problems:
        print(f"ERROR {problem}")
    if problems:
        print(f"\n{len(problems)} problem(s) found.")
        return 1
    print(f"OK: {command} passed ({len(pages)} pages).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
