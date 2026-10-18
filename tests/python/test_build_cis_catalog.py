"""Tests for tools/build_cis_catalog.py on a small synthetic .audit file (no Tenable content).

The synthetic audit file and the catalog built from it are shared with the Pester suite
(tests/powershell/CisAudit.Tests.ps1), so CI never needs a licensed catalog.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

import build_cis_catalog as bcc  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[1] / "powershell" / "fixtures" / "cis"
SYNTHETIC = (FIXTURES / "Synthetic_v1.0.0_L1.audit").read_text(encoding="utf-8")
SYNTHETIC_CATALOG = FIXTURES / "catalog-synthetic.json"


def build(tmp_path: Path, name: str = "Synthetic_v1.0.0_L1.audit") -> dict:
    audit = tmp_path / name
    audit.write_text(SYNTHETIC, encoding="utf-8")
    catalog, problems = bcc.build([audit], "Synthetic Benchmark", "1.0.0")
    assert problems == []
    return catalog


def by_id(catalog: dict) -> dict:
    return {c["id"]: c for c in catalog["checks"]}


def test_catalog_header_and_ordering(tmp_path):
    catalog = build(tmp_path)
    assert catalog["schema"] == "cc.cis.catalog/1"
    assert catalog["sources"][0]["level"] == "L1"
    assert len(catalog["sources"][0]["sha256"]) == 64
    ids = [c["id"] for c in catalog["checks"]]
    assert ids == ["1.1.4", "2.2.2", "2.2.15", "2.2.22", "2.3.10.11", "17.3.2", "18.5.1", "18.9.1"]
    assert catalog["applicability"][0]["name"] == "CurrentBuild"


def test_no_rationale_text_is_copied(tmp_path):
    text = json.dumps(build(tmp_path))
    assert "Rationale" not in text
    assert "synthetic.audit from" not in text


def test_variables_ranges_and_policies(tmp_path):
    c = by_id(build(tmp_path))["1.1.4"]
    assert c["title"] == "Ensure 'Minimum password length' is set to '14 or more character(s)'"
    assert c["tests"] == [{"source": "SecurityPolicy", "key": "MinimumPasswordLength",
                           "expect": {"op": "range", "min": 14, "max": None}}]


def test_user_rights_exact_and_superset(tmp_path):
    checks = by_id(build(tmp_path))
    assert checks["2.2.2"]["tests"][0]["expect"] == {
        "op": "set", "mode": "exact", "anyOf": [["Administrators", "Remote Desktop Users"]]}
    assert checks["2.2.15"]["tests"][0]["expect"]["mode"] == "superset"


def test_audit_set_and_or_values(tmp_path):
    checks = by_id(build(tmp_path))
    assert checks["17.3.2"]["tests"][0]["expect"] == {"op": "in", "values": ["Success", "Success, Failure"]}
    assert checks["18.9.1"]["tests"][0]["expect"] == {
        "op": "any", "of": [{"op": "eq", "value": "1"}, {"op": "eq", "value": "2"}]}


def test_empty_multi_text_allows_missing(tmp_path):
    t = by_id(build(tmp_path))["2.3.10.11"]["tests"][0]
    assert t["allowMissing"] is True
    assert t["expect"] == {"op": "set", "mode": "exact", "anyOf": [[]]}


def test_composite_report_becomes_one_check_with_all_tests(tmp_path):
    c = by_id(build(tmp_path))["18.5.1"]
    assert [t["name"] for t in c["tests"]] == ["AutoAdminLogon", "DefaultPassword"]
    assert c["tests"][1]["mustNotExist"] is True


def test_spooler_condition_becomes_variants(tmp_path):
    c = by_id(build(tmp_path))["2.2.22"]
    assert "tests" not in c
    assert c["variants"][0]["when"][0]["source"] == "Service"
    assert c["variants"][0]["tests"][0]["expect"]["anyOf"] == [
        ["Local Service", "Network Service", "PrintSpoolerService"],
        ["Local Service", "Network Service", "Spooler"]]
    assert c["variants"][1]["when"] is None


def test_level_comes_from_file_name(tmp_path):
    catalog = build(tmp_path, "Synthetic_v1.0.0_L2.audit")
    assert {c["level"] for c in catalog["checks"]} == {"L2"}


def test_cli_writes_ascii_json(tmp_path):
    audit = tmp_path / "Synthetic_v1.0.0_L1.audit"
    audit.write_text(SYNTHETIC, encoding="utf-8")
    out = tmp_path / "out" / "catalog.json"
    assert bcc.main(["--benchmark", "Synthetic", "--version", "1.0.0", "--out", str(out), str(audit)]) == 0
    raw = out.read_bytes()
    assert max(raw) < 128
    assert len(json.loads(raw)["checks"]) == 8


def test_committed_synthetic_catalog_matches_generator(tmp_path):
    """Regenerate with:
    python tools/build_cis_catalog.py --benchmark "Synthetic Benchmark" --version 1.0.0         --out tests/powershell/fixtures/cis/catalog-synthetic.json tests/powershell/fixtures/cis/Synthetic_v1.0.0_L1.audit
    """
    committed = json.loads(SYNTHETIC_CATALOG.read_text(encoding="utf-8"))
    fresh = build(tmp_path)
    for key in ("schema", "benchmark", "version", "applicability", "checks"):
        assert committed[key] == fresh[key], key
