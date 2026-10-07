#!/bin/bash
# -----------------------------------------------------------------------------
# .SYNOPSIS
#     Performs a security posture assessment and generates a report file.
#
# .DESCRIPTION
#     Audits network connections, categorized services, SSH config, 
#     kernel hardening, and privileged users. This script follows the 
#     standardized Linux Scripting Standards for the Antigravity repository.
#
# .PARAMETER TARGET_ENVIRONMENT
#     Explicitly requires 'Test' or 'Prod'. Defaults to 'Test'.
#
# .PARAMETER WHAT_IF
#     If set to 'true', simulates actions without making changes.
#
# .EXAMPLE
#     ./Get-LinuxPosture.sh --env Test
#
# .NOTES
#     Author: Antigravity
#     Created: 2026-01-23T15:20:00
#     Last Modified: 2026-01-26T08:50:00
#     KB Article: KB-Sec-019-LinuxPosture
# -----------------------------------------------------------------------------

# --- Configuration & Defaults ---
TARGET_ENVIRONMENT="Test"
WHAT_IF=false
LOG_DIR="/tmp/AntiG-Logs"
LOG_FILE="${LOG_DIR}/ScriptLog.log"
REPORT_DATE=$(date +%Y-%m-%d)
REPORT_FILE="SecurityPostureViewed-${REPORT_DATE}.txt"
RUN_BY=$(whoami)

# --- Logging Helper ---
Write-Log() {
    local MESSAGE=$1
    local LEVEL=${2:-INFO}
    local TIMESTAMP=$(date -Iseconds)
    local LOG_ENTRY="[$TIMESTAMP] [$LEVEL] $MESSAGE"
    
    local CYAN='\033[0;36m'
    local RED='\033[0;31m'
    local YELLOW='\033[1;33m'
    local NC='\033[0m'

    case $LEVEL in
        "ERROR") log_color=$RED ;;
        "WARN")  log_color=$YELLOW ;;
        *)       log_color=$CYAN ;;
    esac

    echo -e "${log_color}${LOG_ENTRY}${NC}"
    mkdir -p "$LOG_DIR"
    echo "$LOG_ENTRY" >> "$LOG_FILE"
}

log_report() { echo -e "$1" >> "$REPORT_FILE"; }

# --- Argument Parsing ---
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --env) TARGET_ENVIRONMENT="$2"; shift ;;
        --whatif) WHAT_IF=true ;;
    esac
    shift
done

# --- Begin Block ---
Write-Log "Initializing Posture Assessment in [$TARGET_ENVIRONMENT] mode..."

# Initialize Report File
echo "====================================================" > "$REPORT_FILE"
echo " SECURITY POSTURE ASSESSMENT REPORT" >> "$REPORT_FILE"
echo "====================================================" >> "$REPORT_FILE"
echo "Date Ran: $(date -Iseconds)" >> "$REPORT_FILE"
echo "Ran By:   $RUN_BY" >> "$REPORT_FILE"
echo "Host:     $(hostname)" >> "$REPORT_FILE"
echo "====================================================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# --- Process Block ---
main() {
    # 1. Network Connection Audit
    log_report "[1] Network Connection Audit"
    log_report "----------------------------------------------------"
    if command -v ss &> /dev/null; then
        log_report "--- Standard Listeners (TCP/UDP) ---"
        ss -tunlp | grep LISTEN >> "$REPORT_FILE"
        
        log_report "\n--- Strange/Non-Standard Listeners ---"
        ss -tunlp | grep LISTEN | grep -vE ":(22|80|443|53|123|631|25|587|993|995|3306|5432) " >> "$REPORT_FILE"
    elif command -v netstat &> /dev/null; then
        netstat -tunlp | grep LISTEN >> "$REPORT_FILE"
    else
        Write-Log "Neither 'ss' nor 'netstat' found. Skipping connection audit." "WARN"
    fi
    log_report ""

    # 2. Categorized Service Audit
    log_report "[2] Categorized Service Audit"
    log_report "----------------------------------------------------"
    if command -v systemctl &> /dev/null; then
        SERVICES=$(systemctl list-units --type=service --state=running --no-legend --no-pager | awk '{print $1}')
        
        log_report "--- Database Servers ---"
        echo "$SERVICES" | grep -Ei "mysql|postgres|mongod|redis|oracle|sqlserver" >> "$REPORT_FILE" || echo "None found" >> "$REPORT_FILE"
        
        log_report "\n--- App/Web Servers ---"
        echo "$SERVICES" | grep -Ei "apache|nginx|httpd|tomcat|node|docker|containerd|python|php-fpm" >> "$REPORT_FILE" || echo "None found" >> "$REPORT_FILE"
        
        log_report "\n--- Printer Servers ---"
        echo "$SERVICES" | grep -Ei "cups|lp|hp" >> "$REPORT_FILE" || echo "None found" >> "$REPORT_FILE"
        
        log_report "\n--- File Servers ---"
        echo "$SERVICES" | grep -Ei "smb|nmb|nfs|rpcbind" >> "$REPORT_FILE" || echo "None found" >> "$REPORT_FILE"
        
        log_report "\n--- Remote Access ---"
        echo "$SERVICES" | grep -Ei "ssh|vnc|rdp|telnet" >> "$REPORT_FILE" || echo "None found" >> "$REPORT_FILE"
        
        log_report "\n--- Other Running Services ---"
        systemctl list-units --type=service --state=running --no-pager >> "$REPORT_FILE"
    else
        Write-Log "systemctl not found. Manual categorization skipped." "WARN"
    fi
    log_report ""

    # 3. SSH Configuration Audit
    log_report "[3] SSH Configuration Audit (/etc/ssh/sshd_config)"
    log_report "----------------------------------------------------"
    if [ -f /etc/ssh/sshd_config ]; then
        grep -E "PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|X11Forwarding" /etc/ssh/sshd_config | grep -v "#" >> "$REPORT_FILE"
    else
        Write-Log "SSH configuration file not found." "ERROR"
    fi
    log_report ""

    # 4. Kernel Hardening Enumeration
    log_report "[4] Kernel Hardening Audit (sysctl)"
    log_report "----------------------------------------------------"
    if command -v sysctl &> /dev/null; then
        sysctl -a 2>/dev/null | grep -E "net.ipv4.conf.all.forwarding|net.ipv4.conf.all.accept_redirects|net.ipv4.icmp_echo_ignore_broadcasts|kernel.dmesg_restrict|kernel.kptr_restrict" >> "$REPORT_FILE"
    else
        Write-Log "sysctl command not found." "WARN"
    fi
    log_report ""

    # 5. Identity & Privileged Users
    log_report "[5] Identity & Privileged User Audit"
    log_report "----------------------------------------------------"
    log_report "--- Root Users in /etc/passwd ---"
    grep "x:0:" /etc/passwd >> "$REPORT_FILE"
    log_report "\n--- Sudoer Capabilities ---"
    if [ -f /etc/sudoers ]; then
        grep -Po '^[^#].*[\(]ALL[\)]' /etc/sudoers >> "$REPORT_FILE" 2>/dev/null || Write-Log "Cannot read /etc/sudoers directly." "WARN"
    fi
    log_report ""
}

# --- Execution ---
main

# --- End Block ---
Write-Log "Assessment finished. Report: $REPORT_FILE"