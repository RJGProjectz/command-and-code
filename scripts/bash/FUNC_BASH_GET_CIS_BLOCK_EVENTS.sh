#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# .SYNOPSIS
#     Read-only CIS block monitor for Linux: executions and file access blocked (or audit-flagged) by hardening controls.
#
# .DESCRIPTION
#     Script Name: FUNC_BASH_GET_CIS_BLOCK_EVENTS
#     Reads the audit log and syslog/journal text and prints one NDJSON event (GOLDEN_STANDARDS 4.7) per
#     block, with the control that blocked it and the CIS recommendation that put the control in place
#     (IDs from scripts/bash/audit_cis_linux.sh profiles: CIS Ubuntu 24.04 v1.0.0, CIS RHEL 9 v2.0.0).
#
#       selinux     AVC "denied" record. permissive=0 -> Blocked (CIS RHEL 9 1.3.1.5, SELinux enforcing),
#                   permissive=1 -> Audited (1.3.1.4, SELinux not disabled).
#       apparmor    apparmor="DENIED" -> Blocked, apparmor="ALLOWED" (complain mode) -> Audited.
#                   CIS Ubuntu 24.04 1.3.1.3 (profiles in enforce or complain mode; not checked by
#                   audit_cis_linux.sh).
#       noexec      execve SYSCALL with exit=-13 (EACCES) under /tmp, /dev/shm or /var/tmp, recorded by an
#                   audit rule such as the one in the KB page (key cis_exec_denied). EACCES can also mean
#                   plain file permissions, so the event says "noexec or permission".
#                   CIS 1.1.2.1.4 / 1.1.2.2.4 / 1.1.2.5.4 (noexec on /tmp, /dev/shm, /var/tmp).
#       fapolicyd   audit FANOTIFY record with resp=2 (rule decision deny_audit, used by the shipped rules)
#                   paired with its SYSCALL and PATH records, and syslog decision lines
#                   "rule=N dec=deny_* perm=..." (deny_syslog, or deny_log with syslog_format).
#                   Not part of the CIS server profiles: cis_id is empty.
#
#     Nothing is changed. Default sources: /var/log/audit/audit.log and, for fapolicyd syslog lines,
#     journalctl when available, else /var/log/messages and /var/log/syslog. Files given with --syslog are
#     also searched for kernel AppArmor/AVC lines (hosts without auditd log them to kern.log).
#
# .PARAMETER --env
#     'Test' or 'Prod'. Defaults to 'Test'. Read-only in both; recorded in each event.
#
# .PARAMETER --whatif
#     Dry run: lists the sources that would be read and reads none of them.
#
# .PARAMETER --audit-log FILE
#     auditd log to read (repeatable). Default /var/log/audit/audit.log.
#
# .PARAMETER --syslog FILE
#     syslog-format text to read for fapolicyd, AppArmor and AVC lines (repeatable). Default: journalctl -t fapolicyd when
#     available, else /var/log/messages and /var/log/syslog.
#
# .PARAMETER --profile NAME
#     ubuntu2404 or rhel9: which CIS IDs to cite. Default: from /etc/os-release, else both are omitted.
#
# .PARAMETER --include-audit
#     Also report audit-mode (would-block) events. Default: blocks only.
#
# .PARAMETER --log-dir DIR
#     Directory for ScriptLog.log and the run-log NDJSON. Default Logs/ beside the script.
#
# .EXAMPLE
#     sudo ./FUNC_BASH_GET_CIS_BLOCK_EVENTS.sh --include-audit | jq -c '{control, result, path, cis_id}'
#
# .EXAMPLE
#     ./FUNC_BASH_GET_CIS_BLOCK_EVENTS.sh --audit-log ./audit.log --syslog ./messages --profile rhel9 > blocks.ndjson
#
# .OUTPUTS
#     NDJSON events on stdout; logs to stderr, <log-dir>/ScriptLog.log and <log-dir>/<ScriptName>.ndjson.
#
# .NOTES
#     Purpose: Show what the CIS hardening actually stopped, so a block can be traced to the recommendation
#         and tuned (allow-list) or escalated (attack).
#     Security Context: blocked execution from /tmp or /dev/shm and MAC denials are common signs of payload
#         staging (T1059.004, T1204.002) and defense-evasion attempts.
#     Security Domain: Compliance / Detection
#     Author: RJGProjectz
#     Version: 1.0.0
#     Created: 2026-10-19T16:00:00Z
#     Last Modified: 2026-10-19T16:00:00Z
#     KB Article: [CIS block monitor](../../docs/tasks/hardening/cis-block-monitor.md)
#     Source Repo: auditd ausearch(8), audit.rules(7), fapolicyd.rules(5), fapolicyd.conf(5), apparmor(7)
# -----------------------------------------------------------------------------
set -euo pipefail

# --- Configuration & Defaults ---
readonly SCRIPT_NAME="FUNC_BASH_GET_CIS_BLOCK_EVENTS"
readonly SCRIPT_VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
TARGET_ENVIRONMENT="Test"
WHAT_IF=false
AUDIT_LOGS=()
SYSLOGS=()
PROFILE=""
INCLUDE_AUDIT=false
LOG_DIR="${SCRIPT_DIR}/Logs"
EXECUTION_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || date +%s%N)"
readonly EXECUTION_ID
EVENT_COUNT=0

usage() {
    printf 'Usage: %s [--env Test|Prod] [--whatif] [--audit-log FILE]... [--syslog FILE]... [--profile ubuntu2404|rhel9] [--include-audit] [--log-dir DIR] [-h|--help]\n' "$(basename "$0")"
}

json_escape() {
    local raw="$1"
    raw="${raw//\\/\\\\}"
    raw="${raw//\"/\\\"}"
    raw="${raw//$'\n'/\\n}"
    raw="${raw//$'\r'/\\r}"
    raw="${raw//$'\t'/\\t}"
    printf '%s' "$raw"
}

# --- Logging Helper (console to stderr + text log + NDJSON) ---
Write-Log() {
    local message="$1"
    local level="${2:-INFO}"
    local timestamp
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local log_color
    case "$level" in
        ERROR) log_color='\033[0;31m' ;;
        WARN)  log_color='\033[1;33m' ;;
        *)     log_color='\033[0;36m' ;;
    esac
    printf '%b[%s] [%s] %s\033[0m\n' "$log_color" "$timestamp" "$level" "$message" >&2
    mkdir -p "$LOG_DIR"
    printf '[%s] [%s] %s\n' "$timestamp" "$level" "$message" >> "${LOG_DIR}/ScriptLog.log"
    printf '{"timestamp":"%s","host":"%s","tool":"%s","version":"%s","execution_id":"%s","environment":"%s","level":"%s","action":"log","message":"%s"}\n' \
        "$timestamp" "$(json_escape "$HOST_NAME")" "$SCRIPT_NAME" "$SCRIPT_VERSION" "$EXECUTION_ID" \
        "$TARGET_ENVIRONMENT" "$level" "$(json_escape "$message")" >> "${LOG_DIR}/${SCRIPT_NAME}.ndjson"
}

# Value of key=value or key="value" in an audit/syslog record.
field() {
    local record="$1" key="$2"
    if [[ "$record" =~ (^|[[:space:]])${key}=\"([^\"]*)\" ]]; then
        printf '%s' "${BASH_REMATCH[2]}"
    elif [[ "$record" =~ (^|[[:space:]])${key}=([^[:space:]]*) ]]; then
        printf '%s' "${BASH_REMATCH[2]}"
    fi
    return 0
}

# audit(1712345678.123:456) -> ISO 8601 UTC and the serial that ties records of one event together.
audit_time() {
    local record="$1" epoch
    if [[ "$record" =~ audit\(([0-9]+)\.[0-9]+:([0-9]+)\) ]]; then
        epoch="${BASH_REMATCH[1]}"
        date -u -d "@${epoch}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf '%s' "$epoch"
    fi
    return 0
}

audit_serial() {
    [[ "$1" =~ audit\([0-9]+\.[0-9]+:([0-9]+)\) ]] && printf '%s' "${BASH_REMATCH[1]}"
    return 0
}

# Arguments: control result event_time path process user cis_id cis_title detail source
Write-BlockEvent() {
    local control="$1" result="$2" event_time="$3" path="$4" process="$5" user="$6" cis_id="$7" cis_title="$8" detail="$9" source="${10}"
    [[ "$result" == "Audited" && "$INCLUDE_AUDIT" == "false" ]] && return 0
    local level="WARN"
    [[ "$result" == "Audited" ]] && level="INFO"
    printf '{"timestamp":"%s","host":"%s","tool":"%s","version":"%s","execution_id":"%s","level":"%s","message":"%s %s %s","environment":"%s","action":"cis.block","target":"%s","result":"%s","control":"%s","event_time":"%s","path":"%s","process":"%s","user":"%s","cis_id":"%s","cis_title":"%s","benchmark":"%s","detail":"%s","source":"%s"}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(json_escape "$HOST_NAME")" "$SCRIPT_NAME" "$SCRIPT_VERSION" "$EXECUTION_ID" "$level" \
        "$control" "$result" "$(json_escape "$path")" "$TARGET_ENVIRONMENT" "$(json_escape "$path")" "$result" "$control" "$event_time" \
        "$(json_escape "$path")" "$(json_escape "$process")" "$(json_escape "$user")" "$cis_id" "$(json_escape "$cis_title")" \
        "$(json_escape "$BENCHMARK")" "$(json_escape "$detail")" "$(json_escape "$source")"
    EVENT_COUNT=$((EVENT_COUNT + 1))
}

# --- CIS mapping (titles as in audit_cis_linux.sh) ---
cis_for() {
    local control="$1" path="${2:-}" verdict="${3:-Blocked}"
    case "$PROFILE:$control" in
        rhel9:selinux)
            if [[ "$verdict" == "Audited" ]]; then printf '1.3.1.4|Ensure the SELinux mode is not disabled'
            else printf '1.3.1.5|Ensure the SELinux mode is enforcing'; fi ;;
        ubuntu2404:apparmor) printf '1.3.1.3|Ensure all AppArmor Profiles are in enforce or complain mode' ;;
        *:noexec)
            [[ -z "$PROFILE" ]] && { printf '|'; return 0; }
            case "$path" in
                /tmp/*) printf '1.1.2.1.4|Ensure noexec option set on /tmp partition' ;;
                /dev/shm/*) printf '1.1.2.2.4|Ensure noexec option set on /dev/shm partition' ;;
                /var/tmp/*) printf '1.1.2.5.4|Ensure noexec option set on /var/tmp partition' ;;
                *) printf '|' ;;
            esac ;;
        *) printf '|' ;;
    esac
}

# --- Audit log parsing ---
# Records of one audit event share a serial. execve SYSCALL records with exit=-13 and fapolicyd FANOTIFY
# records with resp=2 (FAN_DENY) are paired with the PATH record (item=0) of the same serial. FANOTIFY can
# be written before its SYSCALL record; PATH records always come after it.
declare -A EXEC_DENIED=()
declare -A FAN_DENIED=()
declare -A SYS_INFO=()
declare -A EVENT_PATH=()
LAST_SYSCALL=""

# One audit or kernel syslog record. Arguments: record source
Read-AuditRecord() {
    local record="$1" source="$2" serial mapping verdict perms target
    case "$record" in
        *"apparmor=\"DENIED\""*|*"apparmor=\"ALLOWED\""*)
            verdict="Blocked"
            [[ "$record" == *'apparmor="ALLOWED"'* ]] && verdict="Audited"
            mapping="$(cis_for apparmor)"
            Write-BlockEvent apparmor "$verdict" "$(audit_time "$record")" "$(field "$record" name)" "$(field "$record" comm)" \
                "$(field "$record" auid)" "${mapping%%|*}" "${mapping#*|}" \
                "profile=$(field "$record" profile) operation=$(field "$record" operation) denied_mask=$(field "$record" denied_mask)" "$source"
            ;;
        *"avc:"*"denied"*)
            verdict="Blocked"; perms=""
            [[ "$(field "$record" permissive)" == "1" ]] && verdict="Audited"
            target="$(field "$record" path)"
            [[ -z "$target" ]] && target="$(field "$record" name)"
            [[ "$record" =~ denied[[:space:]]+\{([^}]*)\} ]] && perms="$(printf '%s' "${BASH_REMATCH[1]}" | xargs)"
            mapping="$(cis_for selinux "" "$verdict")"
            Write-BlockEvent selinux "$verdict" "$(audit_time "$record")" "$target" \
                "$(field "$record" comm)" "" "${mapping%%|*}" "${mapping#*|}" \
                "perm={ $perms } scontext=$(field "$record" scontext) tcontext=$(field "$record" tcontext) tclass=$(field "$record" tclass)" "$source"
            ;;
        type=FANOTIFY*)
            if [[ "$(field "$record" resp)" == "2" ]]; then
                serial="$(audit_serial "$record")"
                FAN_DENIED[$serial]="$(audit_time "$record")"
                [[ "${LAST_SYSCALL%%|*}" == "$serial" ]] && SYS_INFO[$serial]="${LAST_SYSCALL#*|}"
            fi
            ;;
        type=SYSCALL*)
            serial="$(audit_serial "$record")"
            LAST_SYSCALL="$serial|$(field "$record" comm)|$(field "$record" auid)|$(field "$record" exe)"
            if [[ -n "${FAN_DENIED[$serial]:-}" ]]; then
                SYS_INFO[$serial]="$(field "$record" comm)|$(field "$record" auid)|$(field "$record" exe)"
            elif [[ "$(field "$record" exit)" == "-13" && ( "$(field "$record" syscall)" == "59" || "$(field "$record" syscall)" == "execve" || "$(field "$record" key)" == "cis_exec_denied" ) ]]; then
                EXEC_DENIED[$serial]="$(audit_time "$record")"
                SYS_INFO[$serial]="$(field "$record" comm)|$(field "$record" auid)|$(field "$record" exe)"
            fi
            ;;
        type=PATH*)
            serial="$(audit_serial "$record")"
            if [[ ( -n "${EXEC_DENIED[$serial]:-}" || -n "${FAN_DENIED[$serial]:-}" ) && -z "${EVENT_PATH[$serial]:-}" && "$(field "$record" item)" == "0" ]]; then
                EVENT_PATH[$serial]="$(field "$record" name)"
            fi
            ;;
    esac
    return 0
}

# Emits the execve and fanotify events paired by Read-AuditRecord, then resets the tables. Argument: source
Write-PairedEvent() {
    local source="$1" key process user exe path mapping
    for key in "${!EXEC_DENIED[@]}"; do
        IFS='|' read -r process user exe <<< "${SYS_INFO[$key]:-}"
        path="${EVENT_PATH[$key]:-}"
        case "$path" in
            /tmp/*|/dev/shm/*|/var/tmp/*)
                mapping="$(cis_for noexec "$path")"
                Write-BlockEvent noexec Blocked "${EXEC_DENIED[$key]}" "$path" "$process" "$user" "${mapping%%|*}" "${mapping#*|}" \
                    "execve returned EACCES (noexec mount or permission)" "$source" ;;
        esac
    done
    for key in "${!FAN_DENIED[@]}"; do
        IFS='|' read -r process user exe <<< "${SYS_INFO[$key]:-}"
        Write-BlockEvent fapolicyd Blocked "${FAN_DENIED[$key]}" "${EVENT_PATH[$key]:-}" "${exe:-$process}" "$user" "" "" \
            "fanotify resp=2 (deny_audit)" "$source"
    done
    EXEC_DENIED=(); FAN_DENIED=(); SYS_INFO=(); EVENT_PATH=(); LAST_SYSCALL=""
}

Read-AuditLog() {
    local file="$1" record
    [[ -r "$file" ]] || { Write-Log "Cannot read $file (run as root?)." "WARN"; return 0; }
    while IFS= read -r record || [[ -n "$record" ]]; do
        Read-AuditRecord "$record" "$file"
    done < "$file"
    Write-PairedEvent "$file"
}

# --- syslog lines: fapolicyd decisions (fapolicyd.conf(5) syslog_format, default
# rule,dec,perm,auid,pid,exe,:,path,ftype,trust) and kernel AppArmor/AVC lines from hosts without auditd ---
Read-FapolicydLine() {
    local record="$1" source="$2" decision
    [[ "$record" == *fapolicyd* && "$record" == *"dec=deny"* ]] || return 0
    decision="$(field "$record" dec)"
    Write-BlockEvent fapolicyd Blocked "" "$(field "$record" path)" "$(field "$record" exe)" "$(field "$record" auid)" "" "" \
        "rule=$(field "$record" rule) dec=$decision perm=$(field "$record" perm) trust=$(field "$record" trust)" "$source"
}

Read-Syslog() {
    local file="$1" record
    [[ -r "$file" ]] || return 0
    while IFS= read -r record || [[ -n "$record" ]]; do
        case "$record" in
            *"apparmor=\""*|*"avc:"*) Read-AuditRecord "$record" "$file" ;;
            *) Read-FapolicydLine "$record" "$file" ;;
        esac
    done < "$file"
}

# --- Argument Parsing ---
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --env)        TARGET_ENVIRONMENT="${2:-}"; shift ;;
        --whatif|--dry-run) WHAT_IF=true ;;
        --audit-log)  AUDIT_LOGS+=("${2:-}"); shift ;;
        --syslog)     SYSLOGS+=("${2:-}"); shift ;;
        --profile)    PROFILE="${2:-}"; shift ;;
        --include-audit) INCLUDE_AUDIT=true ;;
        --log-dir)    LOG_DIR="${2:-}"; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            printf 'Unknown parameter: %s (use -h for usage)\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

HOST_NAME="$(hostname 2>/dev/null || uname -n)"
if [[ "$TARGET_ENVIRONMENT" != "Test" && "$TARGET_ENVIRONMENT" != "Prod" ]]; then Write-Log "--env must be Test or Prod." "ERROR"; exit 2; fi
if [[ -z "$PROFILE" && -r /etc/os-release ]]; then
    # shellcheck disable=SC1091  # os-release is a key=value file
    os_id="$(. /etc/os-release && printf '%s %s %s' "${ID:-}" "${ID_LIKE:-}" "${VERSION_ID:-}")"
    case "$os_id" in
        "ubuntu "*24.04) PROFILE="ubuntu2404" ;;
        *rhel*" 9"*|rocky*" 9"*|almalinux*" 9"*) PROFILE="rhel9" ;;
    esac
fi
case "$PROFILE" in
    ubuntu2404) BENCHMARK="CIS Ubuntu Linux 24.04 LTS v1.0.0" ;;
    rhel9) BENCHMARK="CIS Red Hat Enterprise Linux 9 v2.0.0" ;;
    "") BENCHMARK="" ;;
    *) Write-Log "--profile must be ubuntu2404 or rhel9." "ERROR"; exit 2 ;;
esac
[[ "${#AUDIT_LOGS[@]}" -eq 0 ]] && AUDIT_LOGS=(/var/log/audit/audit.log)

# --- Begin ---
if [[ "$WHAT_IF" == "true" ]]; then
    Write-Log "[WHATIF] Would read audit logs: ${AUDIT_LOGS[*]}; fapolicyd lines from: ${SYSLOGS[*]:-journalctl -t fapolicyd or /var/log/messages, /var/log/syslog}. Nothing is changed."
    exit 0
fi
Write-Log "Starting ${SCRIPT_NAME} ${SCRIPT_VERSION} [${TARGET_ENVIRONMENT}] profile ${PROFILE:-none} (read-only)."

for audit_log in "${AUDIT_LOGS[@]}"; do Read-AuditLog "$audit_log"; done
if [[ "${#SYSLOGS[@]}" -gt 0 ]]; then
    for syslog_file in "${SYSLOGS[@]}"; do Read-Syslog "$syslog_file"; done
elif command -v journalctl >/dev/null 2>&1; then
    while IFS= read -r record; do Read-FapolicydLine "fapolicyd $record" "journalctl -t fapolicyd"; done \
        < <(journalctl -t fapolicyd -o cat --no-pager 2>/dev/null || true)
else
    for syslog_file in /var/log/messages /var/log/syslog; do Read-Syslog "$syslog_file"; done
fi

# --- End ---
Write-Log "Script completed: ${EVENT_COUNT} block event(s)."
