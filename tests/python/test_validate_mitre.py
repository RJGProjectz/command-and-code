"""Tests for tools/validate_mitre.py: ATT&CK v20 catalog and revoked-ID detection.

security_domain: Intelligence
Author: RJGProjectz
Created: 2026-10-13T00:00:00Z
"""
from tools import validate_mitre


def _scan(tmp_path, monkeypatch, text):
    (tmp_path / "page.md").write_text(text, encoding="utf-8")
    monkeypatch.setattr(validate_mitre, "DOCS", tmp_path)
    return validate_mitre.scan_repository()


def test_revoked_id_without_formerly_is_stale(tmp_path, monkeypatch):
    coverage, stale = _scan(tmp_path, monkeypatch, "Attackers add exclusions (T1562.001).\n")
    assert stale == [("page.md", 1, "T1562.001")]
    assert coverage == {}


def test_revoked_id_named_as_formerly_is_allowed(tmp_path, monkeypatch):
    coverage, stale = _scan(tmp_path, monkeypatch, "Disable or Modify Tools (T1685, formerly T1562.001).\n")
    assert stale == []
    assert coverage == {"T1685": ["page.md"]}


def test_mobile_ids_stay_out_of_enterprise_coverage(tmp_path, monkeypatch):
    coverage, stale = _scan(tmp_path, monkeypatch, "Mobile phishing T1660.\n")
    assert coverage == {} and stale == []


def test_catalog_uses_v20_tactics():
    tactic_names = {name for _, name in validate_mitre.TACTICS}
    assert "Defense Evasion" not in tactic_names
    assert {"Stealth", "Defense Impairment"} <= tactic_names
    for tech_id, (_, tactics) in validate_mitre.TECHNIQUE_CATALOG.items():
        assert set(tactics) <= tactic_names, tech_id
    assert not set(validate_mitre.REVOKED) & set(validate_mitre.TECHNIQUE_CATALOG)
