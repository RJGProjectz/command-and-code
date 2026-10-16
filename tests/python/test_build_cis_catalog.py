"""Tests for tools/build_cis_catalog.py on a small synthetic .audit file (no Tenable content)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

import build_cis_catalog as bcc  # noqa: E402

SYNTHETIC = r'''#
# <variables>
#   <variable>
#     <name>MINIMUM_PASSWORD_LENGTH</name>
#     <default>[14..MAX]</default>
#   </variable>
# </variables>
<check_type:"Windows" version:"2">
<group_policy:"Synthetic">
<if>
  <condition type:"AND">
    <custom_item>
      type        : REGISTRY_SETTING
      description : "Windows 11 is installed"
      value_type  : POLICY_TEXT
      value_data  : "2[26][0-9]{3}"
      reg_key     : "HKLM\Software\Microsoft\Windows Nt\Currentversion"
      reg_item    : "CurrentBuild"
      check_type  : CHECK_REGEX
    </custom_item>
  </condition>
  <then>
    <report type:"PASSED">
      description : "synthetic.audit from Synthetic Benchmark"
    </report>
    <custom_item>
      type            : PASSWORD_POLICY
      description     : "1.1.4 Ensure 'Minimum password length' is set to '14 or more character(s)'"
      info            : "Rationale text that must not be copied.
Second line."
      value_type      : POLICY_DWORD
      value_data      : @MINIMUM_PASSWORD_LENGTH@
      password_policy : MINIMUM_PASSWORD_LENGTH
    </custom_item>
    <custom_item>
      type        : USER_RIGHTS_POLICY
      description : "2.2.2 Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users'"
      value_type  : USER_RIGHT
      value_data  : "Administrators" && "Remote Desktop Users"
      right_type  : SeNetworkLogonRight
    </custom_item>
    <custom_item>
      type        : USER_RIGHTS_POLICY
      description : "2.2.15 Ensure 'Deny access to this computer from the network' to include 'Guests, Local account'"
      value_type  : USER_RIGHT
      value_data  : "Guests" && "Local account"
      right_type  : SeDenyNetworkLogonRight
      check_type  : CHECK_SUPERSET
    </custom_item>
    <custom_item>
      type                     : AUDIT_POLICY_SUBCATEGORY
      description              : "17.3.2 Ensure 'Audit Process Creation' is set to include 'Success'"
      value_type               : AUDIT_SET
      value_data               : "Success" || "Success, Failure"
      audit_policy_subcategory : "Process Creation"
    </custom_item>
    <custom_item>
      type        : REGISTRY_SETTING
      description : "2.3.10.11 Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"
      value_type  : POLICY_MULTI_TEXT
      value_data  : ""
      reg_key     : "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters"
      reg_item    : "NullSessionShares"
      reg_option  : CAN_BE_NULL
    </custom_item>
    <custom_item>
      type        : REGISTRY_SETTING
      description : "18.9.1 Ensure 'Something' is set to 'Enabled: 1 or 2'"
      value_type  : POLICY_DWORD
      value_data  : "1" || "2"
      reg_key     : "HKLM\Software\Policies\Synthetic"
      reg_item    : "Value"
      reg_option  : CAN_NOT_BE_NULL
    </custom_item>
    <if>
      <condition auto:"FAILED" type:"AND">
        <custom_item>
          type        : REGISTRY_SETTING
          description : "AutoAdminLogon is 0"
          value_type  : POLICY_TEXT
          value_data  : "0"
          reg_key     : "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
          reg_item    : "AutoAdminLogon"
          reg_option  : CAN_BE_NULL
        </custom_item>
        <custom_item>
          type        : REG_CHECK
          description : "DefaultPassword does not exist"
          value_type  : POLICY_TEXT
          value_data  : "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
          reg_option  : MUST_NOT_EXIST
          key_item    : "DefaultPassword"
        </custom_item>
      </condition>
      <then>
        <report type:"PASSED">
          description : "18.5.1 Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled'"
        </report>
      </then>
    </if>
    <if>
      <condition type:"AND">
        <custom_item>
          type            : AUDIT_POWERSHELL
          description     : "Check if Print Spooler service is running"
          value_type      : POLICY_TEXT
          value_data      : "Running"
          powershell_args : "(Get-Service -Name Spooler -ErrorAction SilentlyContinue).Status"
          check_type      : CHECK_REGEX
        </custom_item>
      </condition>
      <then>
        <custom_item>
          type        : USER_RIGHTS_POLICY
          description : "2.2.22 Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
          value_type  : USER_RIGHT
          value_data  : "Local Service" && "Network Service" && ("PrintSpoolerService" || "Spooler")
          right_type  : SeAuditPrivilege
        </custom_item>
      </then>
      <else>
        <custom_item>
          type        : USER_RIGHTS_POLICY
          description : "2.2.22 Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
          value_type  : USER_RIGHT
          value_data  : "Local Service" && "Network Service"
          right_type  : SeAuditPrivilege
        </custom_item>
      </else>
    </if>
  </then>
</if>
</group_policy>
</check_type>
'''


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
