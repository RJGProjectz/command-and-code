"""Fixture tests for scripts/bash/audit_cis_linux.sh (WP-58).

The audit runs with --root against synthetic file trees built per test (Ubuntu 24.04 and RHEL 9), so no
live host is read. File modes are set with os.chmod; ownership checks can only pass when the tests run as
root, so mode assertions look at the Actual text and ownership-dependent statuses are not asserted.

security_domain: Compliance / Hardening
Author: RJGProjectz
Created: 2026-10-19T15:00:00Z
Last Modified: 2026-10-19T15:00:00Z
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools import cc

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "bash" / "audit_cis_linux.sh"
BASH = cc.find_bash()

pytestmark = pytest.mark.skipif(BASH is None, reason="bash not available")
MANDATORY = ("timestamp", "host", "tool", "version", "execution_id", "level", "action", "result")
POSIX_MODES = sys.platform != "win32"

SYSCTL_GOOD = {
    "kernel/randomize_va_space": "2",
    "kernel/yama/ptrace_scope": "1",
    "fs/suid_dumpable": "0",
    "net/ipv4/ip_forward": "0",
    "net/ipv4/conf/all/send_redirects": "0",
    "net/ipv4/conf/default/send_redirects": "0",
    "net/ipv4/icmp_ignore_bogus_error_responses": "1",
    "net/ipv4/icmp_echo_ignore_broadcasts": "1",
    "net/ipv4/conf/all/accept_redirects": "0",
    "net/ipv4/conf/default/accept_redirects": "0",
    "net/ipv4/conf/all/secure_redirects": "0",
    "net/ipv4/conf/default/secure_redirects": "0",
    "net/ipv4/conf/all/rp_filter": "1",
    "net/ipv4/conf/default/rp_filter": "1",
    "net/ipv4/conf/all/accept_source_route": "0",
    "net/ipv4/conf/default/accept_source_route": "0",
    "net/ipv4/conf/all/log_martians": "1",
    "net/ipv4/conf/default/log_martians": "1",
    "net/ipv4/tcp_syncookies": "1",
}


def write(tree: Path, rel: str, text: str, mode: int | None = None) -> Path:
    path = tree / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    if mode is not None:
        os.chmod(path, mode)
    return path


def build_tree(tree: Path, distro: str) -> Path:
    if distro == "ubuntu":
        write(tree, "etc/os-release", 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\n')
        write(tree, "boot/grub/grub.cfg", "menuentry 'Ubuntu' {\n\tlinux /vmlinuz root=/dev/sda1 ro apparmor=1 security=apparmor\n}\n", 0o600)
        write(tree, "etc/security/limits.d/60-cis.conf", "*  hard  core  0\n")
    else:
        write(tree, "etc/os-release", 'NAME="Rocky Linux"\nID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.4"\nPRETTY_NAME="Rocky Linux 9.4"\n')
        write(tree, "boot/grub2/grub.cfg", "blscfg\n", 0o600)
        write(tree, "boot/loader/entries/abc-5.14.0.conf", "title Rocky\noptions root=/dev/mapper/rl-root ro selinux=0\n")
        write(tree, "etc/selinux/config", "SELINUX=permissive\nSELINUXTYPE=targeted\n")
        write(tree, "sys/fs/selinux/enforce", "0\n")
        write(tree, "etc/systemd/coredump.conf.d/60-cis.conf", "[Coredump]\nStorage=none\nProcessSizeMax=0\n")
    write(tree, "etc/hostname", f"fixture-{distro}\n")
    # cramfs: on disk, install + blacklist -> Pass. hfs: on disk, only blacklisted -> Fail. jffs2: loaded -> Fail.
    write(tree, "lib/modules/6.8.0/kernel/fs/cramfs/cramfs.ko.zst", "")
    write(tree, "lib/modules/6.8.0/kernel/fs/hfs/hfs.ko.zst", "")
    write(tree, "lib/modules/6.8.0/kernel/drivers/usb/storage/usb-storage.ko.zst", "")
    write(tree, "etc/modprobe.d/cis.conf",
          "install cramfs /bin/false\nblacklist cramfs\nblacklist hfs\ninstall usb-storage /bin/false\nblacklist usb-storage\n")
    write(tree, "proc/modules", "jffs2 237568 0 - Live 0x0000000000000000\next4 1003520 1 - Live 0x0\n")
    write(tree, "proc/mounts",
          "/dev/sda1 / ext4 rw,relatime 0 0\n"
          "tmpfs /tmp tmpfs rw,nosuid,nodev,relatime 0 0\n"
          "tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0\n")
    for key, value in SYSCTL_GOOD.items():
        write(tree, f"proc/sys/{key}", value + "\n")
    write(tree, "proc/sys/net/ipv4/ip_forward", "1\n")  # runtime drift: forwarding on
    persisted = "".join(f"{k.replace('/', '.')} = {v}\n" for k, v in SYSCTL_GOOD.items())
    write(tree, "usr/lib/sysctl.d/50-default.conf", "net.ipv4.conf.all.rp_filter = 2\nkernel.yama.ptrace_scope = 0\n")
    write(tree, "etc/sysctl.d/60-cis.conf", persisted)
    write(tree, "etc/ssh/sshd_config",
          "Include /etc/ssh/sshd_config.d/*.conf\n"
          "PermitRootLogin yes\n"  # ignored: the drop-in sets it first
          "UsePAM yes\n"
          "Match User backup\n    PermitRootLogin yes\n    MaxAuthTries 10\n", 0o600)
    write(tree, "etc/ssh/sshd_config.d/10-cis.conf",
          "PermitRootLogin no\nMaxAuthTries 4\nLoginGraceTime 1m\nClientAliveInterval 15\nClientAliveCountMax 3\n"
          "MaxStartups 10:30:60\nBanner /etc/issue.net\nMaxSessions 12\nLogLevel VERBOSE\n")
    write(tree, "etc/passwd",
          "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nlegacy:abc:1001:1001::/home/legacy:/bin/bash\n", 0o644)
    write(tree, "etc/group", "root:x:0:\n", 0o644)
    write(tree, "etc/shadow", "root:$6$fixture:19000:0:99999:7:::\nnopass::19000:0:99999:7:::\n", 0o640)
    write(tree, "etc/gshadow", "root:*::\n", 0o640)
    write(tree, "etc/crontab", "SHELL=/bin/sh\n", 0o644)
    wants = tree / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True, exist_ok=True)
    (wants / "auditd.service").write_text("", encoding="utf-8")
    return tree


def run_audit(tree: Path, *extra: str, expect_rc: int = 0):
    out_dir = tree.parent / "out"
    completed = subprocess.run(
        [BASH, SCRIPT.as_posix(), "--root", tree.as_posix(), "--log-dir", (tree.parent / "logs").as_posix(),
         "--output-dir", out_dir.as_posix(), *extra],
        capture_output=True, text=True, check=False, timeout=300,
    )
    assert completed.returncode == expect_rc, completed.stderr
    results = {r["cis_id"]: r for r in (json.loads(x) for x in completed.stdout.splitlines() if x.strip())}
    return results, out_dir, completed


@pytest.fixture(scope="module")
def ubuntu(tmp_path_factory):
    tree = build_tree(tmp_path_factory.mktemp("ubuntu") / "root", "ubuntu")
    return run_audit(tree, "--level", "L2")


@pytest.fixture(scope="module")
def rhel(tmp_path_factory):
    tree = build_tree(tmp_path_factory.mktemp("rhel") / "root", "rhel")
    return run_audit(tree, "--level", "L2")


def test_every_line_has_the_shared_schema(ubuntu):
    results, _, _ = ubuntu
    assert len(results) > 60
    for r in results.values():
        for field in MANDATORY + ("cis_id", "title", "expected", "actual", "source", "benchmark", "profile"):
            assert field in r, field
        assert r["action"] == "cis.check"
        assert r["result"] in ("Pass", "Fail", "NotApplicable", "Error")
        assert r["host"] == "fixture-ubuntu"


def test_profile_detection_and_benchmark(ubuntu, rhel):
    assert {r["benchmark"] for r in ubuntu[0].values()} == {"CIS Ubuntu Linux 24.04 LTS"}
    assert {r["benchmark"] for r in rhel[0].values()} == {"CIS Red Hat Enterprise Linux 9"}
    assert "1.3.1.2" in ubuntu[0] and "AppArmor" in ubuntu[0]["1.3.1.2"]["title"]
    assert "SELinux" in rhel[0]["1.3.1.2"]["title"]
    assert "6.2.1.2" in ubuntu[0] and "6.3.1.4" in rhel[0]


def test_kernel_modules(ubuntu):
    r = ubuntu[0]
    assert r["1.1.1.1"]["result"] == "Pass"      # cramfs: install /bin/false + blacklist
    assert r["1.1.1.3"]["result"] == "Fail"      # hfs: only blacklisted
    assert r["1.1.1.5"]["result"] == "Fail"      # jffs2: loaded
    assert r["1.1.1.2"]["result"] == "Pass"      # freevxfs: not on disk
    assert r["1.1.1.9"]["result"] == "Pass"      # usb-storage with a dash


def test_mounts(ubuntu):
    r = ubuntu[0]
    assert r["1.1.2.1.1"]["result"] == "Pass"
    assert r["1.1.2.1.2"]["result"] == "Pass"
    assert r["1.1.2.1.4"]["result"] == "Fail"    # /tmp without noexec
    assert r["1.1.2.2.4"]["result"] == "Pass"
    assert r["1.1.2.5.2"]["result"] == "NotApplicable"  # no separate /var/tmp


def test_sysctl_runtime_and_persisted(ubuntu):
    r = ubuntu[0]
    assert r["3.3.1"]["result"] == "Fail"        # runtime ip_forward=1
    assert "net.ipv6.conf.all.forwarding=n/a" in r["3.3.1"]["actual"]
    assert r["3.3.7"]["result"] == "Pass"        # /etc/sysctl.d/60 overrides /usr/lib 50 (rp_filter=2)
    assert r["1.5.2"]["result"] == "Pass"        # ptrace_scope >= 1, later file wins
    assert r["3.3.11"]["result"] == "Pass"       # IPv6 absent at runtime
    assert r["1.5.1"]["result"] == "Pass"


def test_sshd_first_value_wins_and_match_is_ignored(ubuntu):
    r = ubuntu[0]
    assert r["5.1.20"]["result"] == "Pass", r["5.1.20"]  # drop-in PermitRootLogin no is read first
    assert r["5.1.16"]["result"] == "Pass"       # Match block MaxAuthTries 10 ignored
    assert r["5.1.13"]["result"] == "Pass"       # LoginGraceTime 1m = 60 s
    assert r["5.1.13"]["actual"] == "60"
    assert r["5.1.17"]["result"] == "Fail"       # MaxSessions 12
    assert r["5.1.8"]["result"] == "Fail"        # DisableForwarding default no (L2)
    assert r["5.1.18"]["result"] == "Pass"
    assert r["5.1.7"]["result"] == "Pass"
    assert r["5.1.22"]["result"] == "Pass"
    assert r["5.1.5"]["result"] == "Pass"


def test_accounts(ubuntu):
    r = ubuntu[0]
    assert r["5.4.2.1"]["result"] == "Fail" and "toor" in r["5.4.2.1"]["actual"]
    assert r["7.2.1"]["result"] == "Fail" and "legacy" in r["7.2.1"]["actual"]
    assert r["7.2.2"]["result"] == "Fail" and "nopass" in r["7.2.2"]["actual"]


@pytest.mark.skipif(not POSIX_MODES, reason="POSIX file modes need a Linux filesystem")
def test_file_modes_are_reported(ubuntu, rhel):
    assert "mode 0644" in ubuntu[0]["2.4.1.2"]["actual"]
    assert ubuntu[0]["2.4.1.2"]["result"] == "Fail"   # crontab 0644 > 0600
    assert "mode 0640" in ubuntu[0]["7.1.5"]["actual"]
    assert rhel[0]["7.1.5"]["result"] == "Fail"       # RHEL wants 0000
    assert ubuntu[0]["7.1.2"]["result"] == "NotApplicable"  # no /etc/passwd- backup


def test_mac_and_core_dumps(ubuntu, rhel):
    assert ubuntu[0]["1.3.1.2"]["result"] == "Pass"
    assert ubuntu[0]["1.5.3"]["result"] == "Pass"
    assert rhel[0]["1.3.1.2"]["result"] == "Fail"     # selinux=0 in a BLS entry
    assert rhel[0]["1.3.1.4"]["result"] == "Pass"     # permissive
    assert rhel[0]["1.3.1.5"]["result"] == "Fail"     # L2 wants enforcing
    assert rhel[0]["1.5.3"]["result"] == "Pass"
    assert rhel[0]["1.5.4"]["result"] == "Pass"
    assert ubuntu[0]["6.2.1.2"]["result"] == "Pass"   # enabled via wants symlink (offline)


def test_level_filter_and_id_filter(tmp_path):
    tree = build_tree(tmp_path / "root", "ubuntu")
    l1, _, _ = run_audit(tree)
    assert "5.1.8" not in l1 and "6.2.1.2" not in l1
    only, _, _ = run_audit(tree, "--id", "5.1.*")
    assert only and all(k.startswith("5.1.") for k in only)


def test_reports_and_exit_codes(tmp_path):
    tree = build_tree(tmp_path / "root", "ubuntu")
    results, out_dir, _ = run_audit(tree, "--fail-on", "Fail", expect_rc=1)
    report = json.loads(next(out_dir.glob("*.json")).read_text(encoding="utf-8"))
    assert report["schema"] == "cc.cis.report/1"
    assert report["summary"]["total"] == len(results) == len(report["results"])
    assert report["summary"]["fail"] == sum(1 for r in results.values() if r["result"] == "Fail")
    first = report["results"][0]
    assert list(first) == ["Id", "Title", "Level", "Section", "Status", "Expected", "Actual", "Source", "Detail"]
    csv_lines = next(out_dir.glob("*.csv")).read_text(encoding="utf-8").splitlines()
    assert csv_lines[0] == "Id,Title,Level,Section,Status,Expected,Actual,Source,Detail"
    assert len(csv_lines) == len(results) + 1
    assert len(next(out_dir.glob("*.ndjson")).read_text(encoding="utf-8").splitlines()) == len(results)


def test_wrong_profile_is_refused_unless_skipped(tmp_path):
    tree = build_tree(tmp_path / "root", "ubuntu")
    run_audit(tree, "--profile", "rhel9", expect_rc=2)
    results, _, _ = run_audit(tree, "--profile", "rhel9", "--skip-applicability")
    assert "1.3.1.5" not in results  # L1 by default
    assert {r["benchmark"] for r in results.values()} == {"CIS Red Hat Enterprise Linux 9"}


def test_whatif_reads_nothing(tmp_path):
    tree = build_tree(tmp_path / "root", "rhel")
    results, out_dir, completed = run_audit(tree, "--whatif")
    assert results == {}
    assert "[WHATIF]" in completed.stderr
    assert not out_dir.exists()
