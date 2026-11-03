"""Tests for tools/gap_report.py: slug normalisation and fuzzy matcher.

security_domain: Code Quality
Author: RJGProjectz
Created: 2026-11-03T00:00:00Z
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.gap_report import (
    build_gap_list,
    fuzzy_best_match,
    is_p1_topic,
    score_topic,
    to_slug,
)


# ---------------------------------------------------------------------------
# to_slug
# ---------------------------------------------------------------------------

def test_slug_lowercases_and_hyphenates():
    assert to_slug("Active Directory Attacks") == "active-directory-attacks"


def test_slug_strips_punctuation():
    assert to_slug("Pass-the-Hash: Overview") == "pass-the-hash"


def test_slug_removes_filler_words():
    assert "introduction" not in to_slug("Introduction to Kerberos")
    assert "chapter" not in to_slug("Chapter 3: Lateral Movement")


def test_slug_collapses_whitespace():
    assert to_slug("  DCOM   Lateral   Movement  ") == "dcom-lateral-movement"


def test_slug_all_filler_returns_empty():
    # "Introduction Overview" → both stripped → empty string
    result = to_slug("Introduction Overview", min_parts=1)
    assert result == ""


def test_slug_preserves_numbers_within_words():
    # Numbers embedded in a meaningful term should stay
    result = to_slug("T1078 Valid Accounts")
    assert "t1078" in result


# ---------------------------------------------------------------------------
# fuzzy_best_match
# ---------------------------------------------------------------------------

def test_fuzzy_exact_match():
    covered = {"pass-the-hash", "kerberoasting", "dcom-lateral-movement"}
    assert fuzzy_best_match("pass-the-hash", covered) == "pass-the-hash"


def test_fuzzy_near_match():
    covered = {"pass-the-hashes"}
    # "pass-the-hash" (13) vs "pass-the-hashes" (15): ratio = 26/28 = 0.929 → match
    result = fuzzy_best_match("pass-the-hash", covered)
    assert result == "pass-the-hashes"


def test_fuzzy_no_match_returns_none():
    covered = {"windows-firewall", "bitlocker-encryption"}
    assert fuzzy_best_match("sql-injection-union", covered) is None


def test_fuzzy_prefers_higher_score():
    covered = {"pass-the-hash", "pass-the-hash-attack"}
    result = fuzzy_best_match("pass-the-hash", covered)
    assert result == "pass-the-hash"


# ---------------------------------------------------------------------------
# is_p1_topic
# ---------------------------------------------------------------------------

def test_p1_topic_positive():
    assert is_p1_topic("lateral-movement-via-smb") is True
    assert is_p1_topic("privilege-escalation-linux") is True
    assert is_p1_topic("active-directory-recon") is True


def test_p1_topic_negative():
    assert is_p1_topic("python-scripting") is False


# ---------------------------------------------------------------------------
# score_topic
# ---------------------------------------------------------------------------

def test_score_gap_no_match_boosted():
    # book_count=2, no match, no P1: 4 + 3 = 7
    assert score_topic("python-scripting", 2, has_site_match=False) == 7


def test_score_p1_domain_adds_two():
    # book_count=1, no match, P1: 2 + 3 + 2 = 7
    assert score_topic("lateral-movement-via-smb", 1, has_site_match=False) == 7


def test_score_site_match_no_bonus():
    # book_count=3, matched, no P1: 6 + 0 = 6
    assert score_topic("python-scripting", 3, has_site_match=True) == 6


# ---------------------------------------------------------------------------
# build_gap_list integration
# ---------------------------------------------------------------------------

def test_build_gap_list_sorts_by_priority():
    book_topics = {
        "lateral-movement-via-dcom": [
            {"book_title": "Book A", "filename": "a.pdf", "page": 1},
            {"book_title": "Book B", "filename": "b.pdf", "page": 5},
        ],
        "python-scripting": [
            {"book_title": "Book C", "filename": "c.pdf", "page": 10},
        ],
    }
    site_slugs: set[str] = set()
    records = build_gap_list(book_topics, site_slugs)
    # lateral-movement-via-dcom: (2*2)+3+2=9; python-scripting: (1*2)+3=5
    assert records[0]["topic"] == "lateral-movement-via-dcom"
    assert records[1]["topic"] == "python-scripting"


def test_build_gap_list_all_pending():
    book_topics = {
        "credential-dumping": [{"book_title": "Hacking", "filename": "h.pdf", "page": 1}],
    }
    records = build_gap_list(book_topics, set())
    assert all(r["status"] == "pending" for r in records)
    assert all(r["page_path"] is None for r in records)
    assert all(r["authored_date"] is None for r in records)


def test_build_gap_list_matched_topic_has_site_match():
    book_topics = {
        "kerberoasting": [{"book_title": "AD Hacking", "filename": "ad.pdf", "page": 3}],
    }
    site_slugs = {"kerberoasting"}
    records = build_gap_list(book_topics, site_slugs)
    assert records[0]["site_match"] == "kerberoasting"
