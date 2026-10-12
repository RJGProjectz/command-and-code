#!/usr/bin/env python3
"""Command & Code — Evaluation of grounded answers (`cc ask`), WP-12.

Scores the question set in tests/eval/ask_questions.yml offline:
1. Retrieval: does ai_grounding.search put an expected page in the top k?
   Reports hit@1, hit@k and MRR (mean reciprocal rank of the first expected page).
2. Citations (only with --answers or --live): does each answer cite a source, cite only
   sources that exist, and cite an expected page?

Retrieval needs no model and runs in CI. --live asks a local Ollama model (never a
"-cloud" one, same rule as `cc ask`) and --save-answers keeps its answers so the
citation check can be re-run offline with --answers.

security_domain: AI Systems
Author: RJGProjectz
Created: 2026-10-12T18:20:00Z
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
QUESTIONS = ROOT / "tests" / "eval" / "ask_questions.yml"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import ai_grounding  # noqa: E402
from tools.cc_cli import CITATION_RE  # noqa: E402


def normalize(path: str) -> str:
    """Index records carry 'docs/...'; the question set is relative to docs/."""
    path = path.replace("\\", "/")
    return path[5:] if path.startswith("docs/") else path


def load_questions(path: Path = QUESTIONS) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return data.get("questions", [])


def check_questions(questions: list[dict], docs: Path = ROOT / "docs") -> list[str]:
    """Problems with the question set itself: duplicate ids, missing fields, missing pages."""
    problems, seen = [], set()
    for q in questions:
        qid = q.get("id")
        if not qid or not q.get("question") or not q.get("expected"):
            problems.append(f"{qid or '?'}: needs id, question and expected")
            continue
        if qid in seen:
            problems.append(f"{qid}: duplicate id")
        seen.add(qid)
        for page in q["expected"]:
            if not (docs / page).is_file():
                problems.append(f"{qid}: expected page does not exist: {page}")
    return problems


def first_hit_rank(retrieved: list[str], expected: list[str]) -> int | None:
    """1-based rank of the first expected page in the retrieved list, or None."""
    wanted = {normalize(p) for p in expected}
    for rank, path in enumerate(retrieved, 1):
        if normalize(path) in wanted:
            return rank
    return None


def check_citations(answer: str, retrieved: list[str], expected: list[str]) -> dict:
    """Which sources an answer cites, and whether those citations are valid and on target."""
    cited = sorted({int(n) for n in CITATION_RE.findall(answer or "")})
    invalid = [n for n in cited if not 1 <= n <= len(retrieved)]
    wanted = {normalize(p) for p in expected}
    on_target = any(normalize(retrieved[n - 1]) in wanted for n in cited if n not in invalid)
    return {"cited": cited, "uncited": not cited, "invalid": invalid, "cites_expected": on_target}


def evaluate(questions: list[dict], k: int, search=ai_grounding.search, answers: dict | None = None) -> dict:
    """Score every question. `search` is injectable so tests run without the real index."""
    rows = []
    for q in questions:
        retrieved = [normalize(rec["path"]) for rec, _score in search(q["question"], top_k=k)]
        row = {"id": q["id"], "question": q["question"], "rank": first_hit_rank(retrieved, q["expected"]),
               "retrieved": retrieved}
        if answers is not None and q["id"] in answers:
            # Citations number the first `sources` pages given to the model (cc ask default: 3).
            row["citations"] = check_citations(answers[q["id"]]["answer"], answers[q["id"]]["sources"], q["expected"])
        rows.append(row)

    n = len(rows) or 1
    summary = {
        "questions": len(rows),
        "k": k,
        "hit_at_1": round(sum(1 for r in rows if r["rank"] == 1) / n, 3),
        "hit_at_k": round(sum(1 for r in rows if r["rank"]) / n, 3),
        "mrr": round(sum(1 / r["rank"] for r in rows if r["rank"]) / n, 3),
    }
    scored = [r["citations"] for r in rows if "citations" in r]
    if scored:
        m = len(scored)
        summary.update({
            "answers": m,
            "cited_rate": round(sum(1 for c in scored if not c["uncited"]) / m, 3),
            "invalid_citation_answers": sum(1 for c in scored if c["invalid"]),
            "cites_expected_rate": round(sum(1 for c in scored if c["cites_expected"]) / m, 3),
        })
    return {"summary": summary, "results": rows}


def live_answers(questions: list[dict], sources: int, model: str | None, host: str, timeout: int) -> dict:
    """Ask a local model each question exactly the way `cc ask` does."""
    from tools.cc_cli import build_cited_prompt, pick_ask_model

    model = model or pick_ask_model(host)
    if not model:
        raise SystemExit(f"No local model found at {host}; start Ollama or pass --model.")
    out = {}
    for q in questions:
        results = ai_grounding.search(q["question"], top_k=sources)
        answer = ai_grounding.query_ollama(build_cited_prompt(q["question"], results), model=model,
                                           host=host, timeout=timeout) or ""
        out[q["id"]] = {"answer": answer, "sources": [normalize(r["path"]) for r, _s in results], "model": model}
        print(f"  {q['id']}: {'answered' if answer else 'no answer'}", file=sys.stderr)
    return out


def load_answers(path: Path) -> dict:
    answers = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                record = json.loads(line)
                answers[record["id"]] = record
    return answers


def print_report(report: dict, show_all: bool) -> None:
    s = report["summary"]
    print(f"Retrieval over {s['questions']} questions (top {s['k']}): "
          f"hit@1 {s['hit_at_1']:.0%}  hit@{s['k']} {s['hit_at_k']:.0%}  MRR {s['mrr']:.2f}")
    if "answers" in s:
        print(f"Citations over {s['answers']} answers: cited {s['cited_rate']:.0%}  "
              f"cites an expected page {s['cites_expected_rate']:.0%}  "
              f"answers with invalid citations {s['invalid_citation_answers']}")
    for r in report["results"]:
        c = r.get("citations")
        bad = not r["rank"] or (c and (c["uncited"] or c["invalid"] or not c["cites_expected"]))
        if not (bad or show_all):
            continue
        rank = f"rank {r['rank']}" if r["rank"] else "MISS"
        line = f"  {r['id']} {rank:7} {r['question']}"
        if c:
            line += f"  cited {c['cited'] or 'nothing'}" + (f" invalid {c['invalid']}" if c["invalid"] else "")
        print(line)
        if not r["rank"]:
            print(f"         got: {', '.join(r['retrieved'][:3])}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score cc ask retrieval and citations against tests/eval/ask_questions.yml")
    parser.add_argument("-k", type=int, default=5, help="Retrieval depth scored as hit@k (default: 5)")
    parser.add_argument("--sources", type=int, default=3, help="Pages given to the model in --live (cc ask default: 3)")
    parser.add_argument("--questions", type=Path, default=QUESTIONS)
    parser.add_argument("--answers", type=Path, help="JSONL of saved answers ({id, answer, sources}) to score offline")
    parser.add_argument("--live", action="store_true", help="Ask a local Ollama model now (slow)")
    parser.add_argument("--save-answers", type=Path, help="With --live: write the answers as JSONL")
    parser.add_argument("--model", help="Ollama model for --live (default: best installed local model)")
    parser.add_argument("--host", default="http://localhost:11434")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--min-hit", type=float, default=0.0, help="Fail (exit 1) if hit@k is below this, e.g. 0.8")
    parser.add_argument("--json", action="store_true", help="Print the full report as JSON")
    parser.add_argument("--all", action="store_true", help="List every question, not only misses")
    args = parser.parse_args(argv)

    questions = load_questions(args.questions)
    problems = check_questions(questions)
    if problems:
        print("Question set problems:\n  " + "\n  ".join(problems), file=sys.stderr)
        return 2

    answers = None
    if args.live:
        answers = live_answers(questions, args.sources, args.model, args.host, args.timeout)
        if args.save_answers:
            with args.save_answers.open("w", encoding="utf-8") as handle:
                for qid, record in answers.items():
                    handle.write(json.dumps({"id": qid, **record}, ensure_ascii=False) + "\n")
    elif args.answers:
        answers = load_answers(args.answers)

    report = evaluate(questions, args.k, answers=answers)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report, args.all)
    return 1 if report["summary"]["hit_at_k"] < args.min_hit else 0


if __name__ == "__main__":
    sys.exit(main())
