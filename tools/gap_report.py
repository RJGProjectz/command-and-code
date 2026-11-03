#!/usr/bin/env python3
"""PDF-to-site coverage gap report.

Compares topic headings extracted from the PDF library against pages already
published on the Command & Code knowledge-base site, then writes a prioritised
gap report for use by WP-104 authoring sessions.

Usage:
    python tools/gap_report.py [--pdf-dir "PDF's"] [--out-dir Audit] [--top N]

security_domain: Knowledge Management
Author: RJGProjectz
Created: 2026-11-03T00:00:00Z
Last Modified: 2026-11-03T00:00:00Z
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from difflib import SequenceMatcher
from pathlib import Path

try:
    import pymupdf as fitz  # newer API (pymupdf >= 1.24)
except ImportError:
    import fitz  # type: ignore[no-redef]  # older pymupdf / PyMuPDF

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import cc  # noqa: E402  # relies on sys.path above

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

FILLER_WORDS = frozenset(
    {
        # English function words
        "a", "an", "the", "and", "or", "but", "of", "in", "on", "at", "to",
        "for", "by", "with", "from", "into", "onto", "upon", "about",
        "over", "under", "between", "through", "during", "before", "after",
        "is", "are", "was", "were", "be", "been", "being", "have", "has",
        "had", "do", "does", "did", "will", "would", "could", "should",
        "may", "might", "must", "can", "shall", "not", "if", "as", "so",
        "its", "it", "this", "that", "these", "those", "which", "who",
        "what", "when", "where", "why", "how", "all", "any", "both", "each",
        "some", "such", "no", "more", "most", "other", "others", "our",
        "your", "their", "we", "you", "they", "he", "she", "i", "my", "our",
        "vs", "via", "per",
        # Book structure
        "introduction", "intro", "overview", "chapter", "part", "appendix",
        "section", "preface", "contents", "index", "foreword", "summary",
        "conclusion", "conclusions", "exercise", "exercises", "lab", "labs",
        "review", "questions", "answers", "further", "reading", "resources",
        "about", "author", "authors", "acknowledgements", "acknowledgments",
        "copyright", "disclaimer", "edition", "book", "books",
        "navigating", "understanding", "getting", "started", "using",
        "read", "table", "page", "title", "contact", "us", "online",
        "learning", "enjoy", "conventions", "used", "written",
        # Generic technical terms without specificity
        "technical", "requirements", "prerequisite", "prerequisites",
        "implementation", "considerations", "discussion", "solution",
        "solutions", "problem", "problems", "scenario", "scenarios",
        "example", "examples", "case", "study", "studies",
        "reporting", "documentation", "monitoring", "mitigations",
        "countermeasures", "defenses", "artifacts", "bottom", "line",
        "reviewing", "typical", "real", "world",
        # Publisher / marketing boilerplate
        "packt", "wiley", "oreilly", "syngress", "apress", "springer",
        "make", "career", "pursue", "wrote",
        # Common filler at end of headings
        "best", "practices", "next", "steps", "wrap", "up",
        "much", "can", "also",
    }
)

# After stripping fillers, a slug MUST have at least this many parts to be kept
_MIN_MEANINGFUL_PARTS = 2

# Topics appearing in more than this many PDFs are likely publisher boilerplate
_MAX_BOOK_COUNT = 20

P1_DOMAINS = frozenset(
    {
        "incident-response", "forensics", "threat-hunting", "hardening",
        "detection", "active-directory", "identity", "cloud",
        "lateral-movement", "privilege-escalation", "credential",
        "persistence", "evasion", "exfiltration",
    }
)

FUZZY_THRESHOLD = 0.82
FONT_SIZE_HEADING = 13.0
FALLBACK_PAGES = 30


# ---------------------------------------------------------------------------
# slug helpers
# ---------------------------------------------------------------------------

_PUNCT = re.compile(r"[^\w\s-]")
_WHITESPACE = re.compile(r"[\s_]+")


def to_slug(text: str, min_parts: int = 1) -> str:
    """Normalise a heading or title to a comparable slug.

    Returns an empty string when fewer than ``min_parts`` non-filler parts
    remain after normalisation.
    """
    text = text.lower().strip()
    text = _PUNCT.sub("", text)
    parts = _WHITESPACE.split(text)
    parts = [p for p in parts if p and p not in FILLER_WORDS]
    if len(parts) < min_parts:
        return ""
    return "-".join(parts)


def is_p1_topic(slug: str) -> bool:
    return any(domain in slug for domain in P1_DOMAINS)


# ---------------------------------------------------------------------------
# step 1 — extract topics from PDFs
# ---------------------------------------------------------------------------

def _book_title(filename: str) -> str:
    """Human-readable title from a PDF filename."""
    stem = Path(filename).stem
    stem = re.sub(r"^copy of ", "", stem, flags=re.IGNORECASE)
    stem = re.sub(r"[-_]+", " ", stem)
    return stem.title()


def _extract_toc_topics(doc: "fitz.Document", filename: str) -> list[dict]:
    toc = doc.get_toc()
    if not toc:
        return []
    title = _book_title(filename)
    entries = []
    for level, heading, page in toc:
        slug = to_slug(heading, min_parts=_MIN_MEANINGFUL_PARTS)
        if len(slug) < 4 or slug.replace("-", "").isdigit():
            continue
        entries.append({"slug": slug, "book_title": title, "filename": filename, "page": page})
    return entries


def _extract_font_topics(doc: "fitz.Document", filename: str) -> list[dict]:
    """Fallback: scan first FALLBACK_PAGES pages for large/bold text."""
    title = _book_title(filename)
    seen: set[str] = set()
    entries = []
    for page_num in range(min(FALLBACK_PAGES, len(doc))):
        page = doc.load_page(page_num)
        blocks = page.get_text("dict")["blocks"]
        for block in blocks:
            if block.get("type") != 0:
                continue
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    if span.get("size", 0) > FONT_SIZE_HEADING:
                        text = span.get("text", "").strip()
                        slug = to_slug(text, min_parts=_MIN_MEANINGFUL_PARTS)
                        if len(slug) >= 4 and slug not in seen and not slug.replace("-", "").isdigit():
                            seen.add(slug)
                            entries.append(
                                {
                                    "slug": slug,
                                    "book_title": title,
                                    "filename": filename,
                                    "page": page_num + 1,
                                }
                            )
    return entries


def extract_book_topics(pdf_dir: Path) -> dict[str, list[dict]]:
    """Return {topic_slug: [{"book_title", "filename", "page"}, ...]}."""
    topics: dict[str, list[dict]] = defaultdict(list)
    for pdf_path in sorted(pdf_dir.glob("*.pdf")):
        doc = fitz.open(str(pdf_path))
        entries = _extract_toc_topics(doc, pdf_path.name)
        if not entries:
            entries = _extract_font_topics(doc, pdf_path.name)
        doc.close()
        for entry in entries:
            slug = entry.pop("slug")
            topics[slug].append(entry)
    return dict(topics)


# ---------------------------------------------------------------------------
# step 2 — load site coverage
# ---------------------------------------------------------------------------

def load_site_slugs() -> set[str]:
    """Return the set of normalised slugs covered by the site."""
    pages = cc.all_pages()
    slugs: set[str] = set()
    for page in pages:
        # page path slug
        slugs.add(to_slug(page.path.stem))
        # title
        if page.meta.get("title"):
            slugs.add(to_slug(str(page.meta["title"])))
        # aliases
        for alias in page.meta.get("aliases") or []:
            slugs.add(to_slug(str(alias)))
        # tags
        for tag in page.meta.get("tags") or []:
            slugs.add(to_slug(str(tag)))
    slugs.discard("")
    return slugs


# ---------------------------------------------------------------------------
# step 3 — fuzzy match
# ---------------------------------------------------------------------------

def build_word_index(covered: set[str]) -> dict[str, set[str]]:
    """Build an inverted index from word tokens (len >= 4) to covered slugs."""
    from collections import defaultdict as _dd
    idx: dict[str, set[str]] = _dd(set)
    for slug in covered:
        for word in slug.split("-"):
            if len(word) >= 4:
                idx[word].add(slug)
    return dict(idx)


def fuzzy_best_match(
    slug: str,
    covered: set[str],
    word_index: dict[str, set[str]] | None = None,
) -> str | None:
    """Return the best matching covered slug at or above FUZZY_THRESHOLD, or None.

    Uses a word-overlap index to prefilter candidates; falls back to
    length-ratio prefiltering when no index is supplied or when the word
    set returns no candidates.
    """
    if slug in covered:
        return slug
    slug_len = len(slug)
    if slug_len == 0:
        return None

    # Candidate prefilter via shared word tokens
    candidates: set[str] | None = None
    if word_index is not None:
        shared: set[str] = set()
        for word in slug.split("-"):
            if len(word) >= 4 and word in word_index:
                shared |= word_index[word]
        if shared:
            candidates = shared

    if candidates is None:
        # Length-ratio fallback: ratio = min/max; must be >= 0.43 for seq ratio >= 0.82
        candidates = {
            c for c in covered
            if c and (min(slug_len, len(c)) / max(slug_len, len(c))) >= 0.43
        }

    best_score = 0.0
    best_match = None
    for candidate in candidates:
        score = SequenceMatcher(None, slug, candidate).ratio()
        if score >= FUZZY_THRESHOLD and score > best_score:
            best_score = score
            best_match = candidate
    return best_match


def score_topic(slug: str, book_count: int, has_site_match: bool) -> int:
    base = (book_count * 2) + (3 if not has_site_match else 0)
    if is_p1_topic(slug):
        base += 2
    return base


# ---------------------------------------------------------------------------
# step 4 — build gap list
# ---------------------------------------------------------------------------

def build_gap_list(
    book_topics: dict[str, list[dict]],
    site_slugs: set[str],
) -> list[dict]:
    """Return gap records sorted by priority DESC."""
    word_index = build_word_index(site_slugs)
    records = []
    for slug, refs in book_topics.items():
        book_count = len(refs)
        if book_count > _MAX_BOOK_COUNT:
            continue  # appears in too many PDFs → publisher boilerplate
        match = fuzzy_best_match(slug, site_slugs, word_index)
        has_match = match is not None
        priority = score_topic(slug, book_count, has_match)

        book_titles = sorted({r["book_title"] for r in refs})
        display = slug.replace("-", " ").title()

        records.append(
            {
                "topic": slug,
                "topic_display": display,
                "books": book_titles,
                "book_count": book_count,
                "site_match": match,
                "priority_score": priority,
                "status": "pending",
                "page_path": None,
                "authored_date": None,
            }
        )

    records.sort(key=lambda r: (-r["priority_score"], -r["book_count"], r["topic"]))
    return records


# ---------------------------------------------------------------------------
# step 5 — write outputs
# ---------------------------------------------------------------------------

def _md_report(records: list[dict], top: int) -> str:
    total = len(records)
    matched = sum(1 for r in records if r["site_match"])
    gap_count = total - matched

    lines = [
        "# PDF Coverage Gap Report",
        "> **Created**: 2026-11-03T00:00:00Z",
        "> **Last Modified**: 2026-11-03T00:00:00Z",
        "> **Author**: RJGProjectz",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total book topics extracted | {total} |",
        f"| Already covered by site | {matched} ({matched * 100 // total if total else 0}%) |",
        f"| Gap topics (need pages) | {gap_count} |",
        "",
    ]

    # Top N gaps table
    gaps = [r for r in records if r["site_match"] is None]
    lines += [
        f"## Top {min(top, len(gaps))} Priority Gaps",
        "",
        "| Priority | Topic | Books Covering It | Count | Site Match |",
        "|----------|-------|-------------------|-------|------------|",
    ]
    for r in gaps[:top]:
        books_short = ", ".join(r["books"][:3])
        if len(r["books"]) > 3:
            books_short += f" +{len(r['books']) - 3} more"
        lines.append(
            f"| {r['priority_score']} | {r['topic_display']} | {books_short} | {r['book_count']} | — |"
        )

    lines += ["", "## Full Gap List", ""]
    for i, r in enumerate(gaps, 1):
        lines.append(f"{i}. **{r['topic_display']}** (score {r['priority_score']}) — {', '.join(r['books'][:2])}")

    lines += [
        "",
        "## Already Covered",
        "",
        "| Topic | Site Match |",
        "|-------|------------|",
    ]
    covered = [r for r in records if r["site_match"] is not None]
    for r in covered[:100]:
        lines.append(f"| {r['topic_display']} | `{r['site_match']}` |")
    if len(covered) > 100:
        lines.append(f"| … and {len(covered) - 100} more | — |")

    return "\n".join(lines) + "\n"


def write_outputs(records: list[dict], out_dir: Path, top: int) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / "PDF_GAP_REPORT.md"
    json_path = out_dir / "PDF_GAP_REPORT.json"

    md_path.write_text(_md_report(records, top), encoding="utf-8")
    json_path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    return md_path, json_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PDF coverage gap report for Command & Code.")
    parser.add_argument("--pdf-dir", default="PDF's", help="Directory containing PDF files")
    parser.add_argument("--out-dir", default="Audit", help="Output directory")
    parser.add_argument("--top", type=int, default=50, help="Number of top gaps in summary table")
    args = parser.parse_args(argv)

    pdf_dir = ROOT / args.pdf_dir
    out_dir = ROOT / args.out_dir

    if not pdf_dir.is_dir():
        print(f"[error] PDF directory not found: {pdf_dir}", file=sys.stderr)
        return 1

    print(f"[1/4] Extracting topics from PDFs in {pdf_dir} …", flush=True)
    book_topics = extract_book_topics(pdf_dir)
    print(f"      {len(book_topics)} unique topic slugs from {sum(len(v) for v in book_topics.values())} heading refs", flush=True)

    print("[2/4] Loading site coverage …", flush=True)
    site_slugs = load_site_slugs()
    print(f"      {len(site_slugs)} covered slugs", flush=True)

    print("[3/4] Matching and scoring …", flush=True)
    records = build_gap_list(book_topics, site_slugs)
    gaps = [r for r in records if r["site_match"] is None]
    print(f"      {len(gaps)} gap topics, {len(records) - len(gaps)} already covered", flush=True)

    print(f"[4/4] Writing outputs to {out_dir} …", flush=True)
    md_path, json_path = write_outputs(records, out_dir, args.top)
    print(f"      {md_path}")
    print(f"      {json_path}")

    print(f"\nDone. {len(gaps)} pending topics ready for WP-104.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
