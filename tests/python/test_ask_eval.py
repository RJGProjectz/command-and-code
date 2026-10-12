"""Tests for tools/ask_eval.py: the cc ask evaluation scorer (WP-12).

security_domain: AI Systems
Author: RJGProjectz
Created: 2026-10-12T18:40:00Z
"""
from tools import ask_eval

QUESTIONS = [
    {"id": "a", "question": "kerberoasting", "expected": ["tasks/kerberoasting-hunt.md"]},
    {"id": "b", "question": "public buckets", "expected": ["platforms/aws/storage.md"]},
]


def fake_search(query, top_k=5):
    pages = {
        "kerberoasting": ["docs/tasks/kerberoasting-hunt.md", "docs/platforms/windows.md"],
        "public buckets": ["docs/platforms/gcp/storage.md", "docs/platforms/aws/storage.md"],
    }[query]
    return [({"path": p}, 1.0) for p in pages[:top_k]]


def test_first_hit_rank_normalizes_docs_prefix():
    assert ask_eval.first_hit_rank(["docs/a.md", "docs/b.md"], ["b.md"]) == 2
    assert ask_eval.first_hit_rank(["docs/a.md"], ["c.md"]) is None


def test_evaluate_retrieval_metrics():
    summary = ask_eval.evaluate(QUESTIONS, k=5, search=fake_search)["summary"]
    assert summary["hit_at_1"] == 0.5
    assert summary["hit_at_k"] == 1.0
    assert summary["mrr"] == 0.75


def test_check_citations_flags_uncited_invalid_and_off_target():
    sources = ["tasks/kerberoasting-hunt.md", "platforms/windows.md"]
    good = ask_eval.check_citations("Run it [1].", sources, ["tasks/kerberoasting-hunt.md"])
    assert good == {"cited": [1], "uncited": False, "invalid": [], "cites_expected": True}
    bad = ask_eval.check_citations("See [2] and [7].", sources, ["tasks/kerberoasting-hunt.md"])
    assert bad["invalid"] == [7] and bad["cites_expected"] is False
    assert ask_eval.check_citations("No idea.", sources, ["x.md"])["uncited"] is True


def test_evaluate_scores_saved_answers():
    answers = {"a": {"answer": "Use Rubeus [1].", "sources": ["tasks/kerberoasting-hunt.md"]}}
    report = ask_eval.evaluate(QUESTIONS, k=5, search=fake_search, answers=answers)
    assert report["summary"]["answers"] == 1
    assert report["summary"]["cites_expected_rate"] == 1.0


def test_shipped_question_set_is_valid():
    questions = ask_eval.load_questions()
    assert len(questions) >= 30
    assert ask_eval.check_questions(questions) == []
