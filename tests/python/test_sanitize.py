"""Tests for tools/sanitize.py: what the leak scanner reports and what it deliberately ignores.

security_domain: Data Protection
Author: RJGProjectz
Created: 2026-10-11T19:30:00Z
"""
import pytest

from tools import sanitize


@pytest.mark.parametrize("ip", ["8.8.4.5", "52.10.20.30", "206.1.2.3"])
def test_routable_ips_are_reportable(ip):
    assert sanitize.is_reportable_ip(ip)


@pytest.mark.parametrize(
    "ip, why",
    [
        ("192.0.2.10", "RFC 5737 documentation range"),
        ("198.51.100.23", "RFC 5737 documentation range"),
        ("203.0.113.5", "RFC 5737 documentation range"),
        ("24.04.47.09", "version string with leading zeros"),
        ("1.3.6.1", "OID prefix"),
        ("255.255.255.0", "netmask"),
        ("169.254.10.10", "link-local"),
        ("127.0.0.1", "loopback"),
        ("224.0.0.251", "multicast"),
        ("300.1.1.1", "octet out of range"),
    ],
)
def test_non_identifying_ips_are_ignored(ip, why):
    assert not sanitize.is_reportable_ip(ip), why


def test_placeholder_and_vendor_domains_are_allowed():
    assert sanitize.is_allowed_domain("example.com")
    assert sanitize.is_allowed_domain("login.microsoftonline.com")


def test_unknown_domain_is_not_allowed():
    assert not sanitize.is_allowed_domain("acme-internal-corp.com")


def test_sanitize_text_redacts_206_addresses():
    assert sanitize.sanitize_text("ping 206.12.34.56 now") == "ping <REDACTED_IP> now"


def test_sanitize_text_leaves_clean_text_unchanged():
    text = "Get-Process | Sort-Object CPU -Descending"
    assert sanitize.sanitize_text(text) == text


def test_scan_file_reports_ip_and_user_path_with_line_numbers(tmp_path):
    f = tmp_path / "note.md"
    f.write_text("clean line\nhost 52.10.20.30 seen\nC:\\Users\\alice\\Desktop\\x.txt\n", encoding="utf-8")

    findings = sanitize.scan_file(f, tmp_path)
    by_category = {(x.category, x.identifier, x.line_number) for x in findings}

    assert ("IP Address", "52.10.20.30", 2) in by_category
    assert ("Username / User Path", "alice", 3) in by_category


def test_scan_file_ignores_documentation_ips_and_placeholder_users(tmp_path):
    f = tmp_path / "doc.md"
    f.write_text("block 198.51.100.23\nC:\\Users\\<user>\\AppData\nC:\\Users\\Public\n", encoding="utf-8")

    assert sanitize.scan_file(f, tmp_path) == []
