#!/usr/bin/env python3
"""Command & Code — topic depth check (WP-82, from the WP-79 review).

The WP-22 comparison claimed 397 topic names from the source wiki, almost all as a
front matter alias on the page that covers them. An alias makes the page findable by
that name; when the body never mentions the topic, the page does not deliver it.
This tool measures, for every claimed topic, how often its page body mentions it:

    0     alias only — the body never mentions the topic
    1-2   passing mention
    3+    discussed

Usage:
    python tools/topic_depth.py                  Bands, then alias-only topics per page (worst first)
    python tools/topic_depth.py --check          Fail on alias-only topics not in the baseline (CI)
    python tools/topic_depth.py --update         Rewrite the baseline to today's alias-only list
    python tools/topic_depth.py --import PATH    Rebuild tools/topic_index.tsv from a WP-22 index
                                                 (| Topic | page | path (alias) | rows)
    python tools/topic_depth.py --annotate PATH  Add or refresh a Depth column in that index

Files:
    tools/topic_index.tsv           topic<TAB>page (path under docs/) — topic names only, no source text
    tools/topic_depth_baseline.txt  known alias-only topics; may only shrink (write the body text,
                                    then run --update)

Matching is a heuristic (topic name and bracketed acronyms, punctuation-insensitive),
so a topic phrased very differently in the body still reads as 0.
"""

from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cc import DOCS, ROOT, load_page  # noqa: E402

INDEX = ROOT / "tools" / "topic_index.tsv"
BASELINE = ROOT / "tools" / "topic_depth_baseline.txt"
MIN_COMPACT = 8  # punctuation-free match only for long names, so "ECC" never matches "eccentric"


# Spellings that mean the same standard: "ISO/IEC 27001" = "ISOIEC 27001" = "ISO 27001",
# "NIST Special Publication 800-53" = "NIST SP 800-53".
_SAME = [(re.compile(r"\biso\s*/?\s*iec\b"), "iso"), (re.compile(r"\bspecial publication\b"), "sp")]


def _norm(text: str) -> str:
    text = text.lower()
    for pattern, repl in _SAME:
        text = pattern.sub(repl, text)
    return re.sub(r"[^a-z0-9]+", " ", text).strip()


def _compact(text: str) -> str:
    return _norm(text).replace(" ", "")


def mentions(topic: str, body: str) -> int:
    """How often the body mentions the topic (name without brackets, plus bracketed acronyms > 2 chars)."""
    core = re.sub(r"\s*\(.*?\)", "", topic)
    terms = [core] + [a for a in re.findall(r"\(([^)]+)\)", topic) if len(a) > 2]
    body_norm, body_compact = f" {_norm(body)} ", _compact(body)
    total = 0
    for term in terms:
        norm = _norm(term)
        if not norm:
            continue
        hits = body_norm.count(f" {norm} ")
        compact = _compact(term)
        if hits == 0 and len(compact) >= MIN_COMPACT:
            hits = body_compact.count(compact)
        total += hits
    return total


def band(n: int) -> str:
    return "0" if n == 0 else "1-2" if n <= 2 else "3+"


def load_index() -> list[tuple[str, str]]:
    rows = []
    for line in INDEX.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            topic, _, rel = line.partition("\t")
            rows.append((topic, rel))
    return rows


def measure() -> dict[tuple[str, str], int]:
    """(page path under docs, topic) -> mentions in that page's body (front matter excluded)."""
    bodies: dict[str, str] = {}
    result = {}
    for topic, rel in load_index():
        if rel not in bodies:
            path = DOCS / rel
            bodies[rel] = load_page(path).body if path.exists() else ""
        result[(rel, topic)] = mentions(topic, bodies[rel])
    return result


def load_baseline() -> set[tuple[str, str]]:
    if not BASELINE.exists():
        return set()
    rows = set()
    for line in BASELINE.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            rel, _, topic = line.partition("\t")
            rows.add((rel, topic))
    return rows


def write_baseline(zero: set[tuple[str, str]]) -> None:
    header = (
        "# Alias-only WP-22 topics (WP-82). page<TAB>topic. May only shrink:\n"
        "# mention the topic in the page body, then run: python tools/topic_depth.py --update\n"
    )
    BASELINE.write_text(header + "".join(f"{r}\t{t}\n" for r, t in sorted(zero)), encoding="utf-8", newline="\n")


def report(depth: dict[tuple[str, str], int]) -> None:
    bands = Counter(band(n) for n in depth.values())
    print(f"topics: {len(depth)}  |  0 (alias only): {bands['0']}  |  1-2: {bands['1-2']}  |  3+: {bands['3+']}")
    per_page: dict[str, list[str]] = defaultdict(list)
    for (rel, topic), n in depth.items():
        if n == 0:
            per_page[rel].append(topic)
    for rel, topics in sorted(per_page.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"{len(topics):3} {rel} | {', '.join(topics)}")


def check(depth: dict[tuple[str, str], int]) -> int:
    missing = sorted({rel for rel, _ in depth if not (DOCS / rel).exists()})
    if missing:
        print("FAIL: topic index points at missing pages: " + ", ".join(missing))
        return 1
    zero = {k for k, n in depth.items() if n == 0}
    baseline = load_baseline()
    new, fixed = sorted(zero - baseline), sorted(baseline - zero)
    if new:
        print(f"FAIL: {len(new)} new alias-only topic(s) - mention the topic in the page body:")
        for rel, topic in new:
            print(f"  {rel}: {topic}")
        return 1
    note = f"; {len(fixed)} baseline row(s) now covered - run --update to shrink it" if fixed else ""
    print(f"OK: no new alias-only topics ({len(zero)} of {len(depth)} known in the baseline{note}).")
    return 0


def _index_rows(path: Path):
    """Yield (line, cells) for each line of a Markdown topic index."""
    for line in path.read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")] if line.startswith("|") else []
        yield line, cells


def import_index(path: Path) -> None:
    rows = [(c[0], c[2].replace(" (alias)", "")) for _, c in _index_rows(path) if len(c) >= 3 and c[1] == "page"]
    header = "# WP-22 topic names (names only) and the page under docs/ that covers each. Rebuild: --import\n"
    INDEX.write_text(header + "".join(f"{t}\t{r}\n" for t, r in rows), encoding="utf-8", newline="\n")
    print(f"{INDEX.relative_to(ROOT)}: {len(rows)} topics")


def annotate(path: Path, depth: dict[tuple[str, str], int]) -> None:
    out, after_header = [], False
    for line, cells in _index_rows(path):
        if after_header:  # the separator row under | Topic | ... |
            line, after_header = "| :--- | :--- | :--- | :--- |", False
        elif len(cells) in (3, 4) and cells[0] == "Topic":
            line, after_header = "| Topic | Status | Our page | Depth |", True
        elif len(cells) in (3, 4) and cells[1] == "page":
            n = depth.get((cells[2].replace(" (alias)", ""), cells[0]), 0)
            line = f"| {cells[0]} | {cells[1]} | {cells[2]} | {band(n)} |"
        out.append(line)
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"annotated {path}")


def main(argv: list[str]) -> int:
    if "--import" in argv:
        import_index(Path(argv[argv.index("--import") + 1]))
        return 0
    depth = measure()
    if "--check" in argv:
        return check(depth)
    if "--update" in argv:
        write_baseline({k for k, n in depth.items() if n == 0})
        print(f"baseline written: {BASELINE.relative_to(ROOT)}")
        return 0
    if "--annotate" in argv:
        annotate(Path(argv[argv.index("--annotate") + 1]), depth)
        return 0
    report(depth)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
