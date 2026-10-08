#!/usr/bin/env bash
# ==============================================================================
# scripts/bash/audit_cis_linux.sh
# CIS Distribution-Independent Linux Benchmark Automated Compliance Auditor
# ==============================================================================

set -o pipefail

TOTAL=0
PASSED=0
FAILED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}===============================================================${NC}"
echo -e "${CYAN}   COMMAND & CODE - CIS LINUX BENCHMARK AUDIT ENGINE           ${NC}"
echo -e "${CYAN}===============================================================${NC}"
echo -e "Target Host : $(hostname)"
echo -e "Kernel      : $(uname -r)"
echo -e "Timestamp   : $(date -u '+%Y-%m-%d %H:%M:%SZ')"
echo ""

record_result() {
    local cis_id="$1"
    local desc="$2"
    local passed="$3"
    local observed="$4"
    local required="$5"

    TOTAL=$((TOTAL + 1))
    if [ "$passed" -eq 1 ]; then
        PASSED=$((PASSED + 1))
        echo -e "[${GREEN}PASS${NC}] ${cis_id} - ${desc}"
        echo -e "       Observed: ${observed} | Required: ${required}"
    else
        FAILED=$((FAILED + 1))
        echo -e "[${RED}FAIL${NC}] ${cis_id} - ${desc}"
        echo -e "       Observed: ${observed} | Required: ${required}"
    fi
}

# --- CIS Section 1: Initial Setup ---
# 1. ASLR Enabled
aslr_val=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "0")
if [ "$aslr_val" -eq 2 ]; then
    record_result "CIS 1.5.3" "Address Space Layout Randomization (ASLR)" 1 "$aslr_val" "2"
else
    record_result "CIS 1.5.3" "Address Space Layout Randomization (ASLR)" 0 "$aslr_val" "2"
fi

# 2. SUID Core Dumps Disabled
suid_dump=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "1")
if [ "$suid_dump" -eq 0 ]; then
    record_result "CIS 1.5.2" "Restrict SUID Core Dumps" 1 "$suid_dump" "0"
else
    record_result "CIS 1.5.2" "Restrict SUID Core Dumps" 0 "$suid_dump" "0"
fi

# --- CIS Section 2: Services ---
# Legacy Services check (telnet, rsh, xinetd)
legacy_active=0
for s in telnet rsh xinetd nis; do
    if systemctl is-active --quiet "$s" 2>/dev/null; then
        legacy_active=1
    fi
done
if [ "$legacy_active" -eq 0 ]; then
    record_result "CIS 2.1.1" "Legacy Insecure Services Inactive (telnet, rsh, xinetd)" 1 "None Active" "Inactive"
else
    record_result "CIS 2.1.1" "Legacy Insecure Services Inactive" 0 "Found Active Daemons" "Inactive"
fi

# --- CIS Section 3: Network Configuration ---
# IP Forwarding Disabled
ip_fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "1")
if [ "$ip_fwd" -eq 0 ]; then
    record_result "CIS 3.1.1" "IPv4 Forwarding Disabled" 1 "$ip_fwd" "0"
else
    record_result "CIS 3.1.1" "IPv4 Forwarding Disabled" 0 "$ip_fwd" "0"
fi

# Send Redirects Disabled
send_redir=$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null || echo "1")
if [ "$send_redir" -eq 0 ]; then
    record_result "CIS 3.2.1" "Packet Redirect Sending Disabled" 1 "$send_redir" "0"
else
    record_result "CIS 3.2.1" "Packet Redirect Sending Disabled" 0 "$send_redir" "0"
fi

# Accept ICMP Redirects Disabled
accept_redir=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo "1")
if [ "$accept_redir" -eq 0 ]; then
    record_result "CIS 3.2.2" "ICMP Redirects Rejected" 1 "$accept_redir" "0"
else
    record_result "CIS 3.2.2" "ICMP Redirects Rejected" 0 "$accept_redir" "0"
fi

# TCP SYN Cookies Enabled
syn_cookies=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "0")
if [ "$syn_cookies" -eq 1 ]; then
    record_result "CIS 3.2.8" "TCP SYN Cookies Enabled" 1 "$syn_cookies" "1"
else
    record_result "CIS 3.2.8" "TCP SYN Cookies Enabled" 0 "$syn_cookies" "1"
fi

# --- CIS Section 4: Logging & Auditing ---
# Auditd Daemon Active
if systemctl is-active --quiet auditd 2>/dev/null; then
    record_result "CIS 4.1.1" "Auditd Subsystem Service Running" 1 "Active" "Active"
else
    record_result "CIS 4.1.1" "Auditd Subsystem Service Running" 0 "Inactive / Not Installed" "Active"
fi

# Auditd Rules Inspect Shadow Access
if command -v auditctl >/dev/null 2>&1 && auditctl -l 2>/dev/null | grep -q "shadow"; then
    record_result "CIS 4.1.5" "Kernel Audit Rules Monitor /etc/shadow" 1 "Monitored" "Monitored"
else
    record_result "CIS 4.1.5" "Kernel Audit Rules Monitor /etc/shadow" 0 "Not Monitored" "Monitored"
fi

# --- CIS Section 5: Access Control & SSH ---
# SSH PermitRootLogin Disabled
sshd_conf="/etc/ssh/sshd_config"
root_login="yes"
if [ -f "$sshd_conf" ]; then
    root_login=$(sshd -T 2>/dev/null | grep -i "^permitrootlogin" | awk '{print $2}' || echo "unknown")
fi
if [ "$root_login" = "no" ]; then
    record_result "CIS 5.2.4" "SSH Root Login Disabled" 1 "$root_login" "no"
else
    record_result "CIS 5.2.4" "SSH Root Login Disabled" 0 "$root_login" "no"
fi

# SSH MaxAuthTries <= 4
auth_tries=$(sshd -T 2>/dev/null | grep -i "^maxauthtries" | awk '{print $2}' || echo "6")
if [ "$auth_tries" -le 4 ]; then
    record_result "CIS 5.2.5" "SSH MaxAuthTries <= 4" 1 "$auth_tries" "<= 4"
else
    record_result "CIS 5.2.5" "SSH MaxAuthTries <= 4" 0 "$auth_tries" "<= 4"
fi

# Crontab File Permissions <= 0600
if [ -f "/etc/crontab" ]; then
    cron_perm=$(stat -c "%a" /etc/crontab 2>/dev/null || echo "000")
    if [ "$cron_perm" -le 600 ]; then
        record_result "CIS 5.1.1" "/etc/crontab Permissions <= 0600" 1 "$cron_perm" "<= 0600"
    else
        record_result "CIS 5.1.1" "/etc/crontab Permissions <= 0600" 0 "$cron_perm" "<= 0600"
    fi
else
    record_result "CIS 5.1.1" "/etc/crontab Permissions <= 0600" 1 "File absent" "<= 0600"
fi

# --- CIS Section 6: File Permissions ---
# /etc/passwd Permissions <= 0644
passwd_perm=$(stat -c "%a" /etc/passwd 2>/dev/null || echo "777")
if [ "$passwd_perm" -le 644 ]; then
    record_result "CIS 6.1.1" "/etc/passwd Permissions <= 0644" 1 "$passwd_perm" "<= 0644"
else
    record_result "CIS 6.1.1" "/etc/passwd Permissions <= 0644" 0 "$passwd_perm" "<= 0644"
fi

# /etc/shadow Permissions <= 0000
shadow_perm=$(stat -c "%a" /etc/shadow 2>/dev/null || echo "777")
if [ "$shadow_perm" -eq 0 ] || [ "$shadow_perm" -eq 640 ]; then
    record_result "CIS 6.1.2" "/etc/shadow Permissions Restrictive (0000 or 0640)" 1 "$shadow_perm" "0000 or 0640"
else
    record_result "CIS 6.1.2" "/etc/shadow Permissions Restrictive" 0 "$shadow_perm" "0000 or 0640"
fi

# --- Summary Statistics ---
pct=0
if [ "$TOTAL" -gt 0 ]; then
    pct=$(( (PASSED * 100) / TOTAL ))
fi

echo ""
echo -e "${CYAN}---------------------------------------------------------------${NC}"
echo -e "CIS LINUX AUDIT SUMMARY: ${PASSED} / ${TOTAL} Passed (${pct}% Compliant)"
echo -e "${CYAN}---------------------------------------------------------------${NC}"
