#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# .SYNOPSIS
#     Read-only CIS Benchmark audit for Linux with distribution profiles (Ubuntu 24.04, RHEL 9 family), L1 / L2.
#
# .DESCRIPTION
#     Script Name: audit_cis_linux.sh
#     Audits a Linux host (or an offline file tree with --root) against the automatable recommendations
#     of a CIS distribution benchmark and writes one result per recommendation with the same schema as
#     scripts/powershell/Invoke-CisWindowsAudit.ps1: Id, Title, Level, Section, Status
#     (Pass | Fail | NotApplicable | Error), Expected, Actual, Source, Detail.
#
#     Profiles (server profile of each benchmark; IDs and titles only, CIS text is licensed):
#       ubuntu2404   CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0
#       rhel9        CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0 (also Rocky, AlmaLinux, Oracle Linux 9)
#     IDs, titles and levels were checked against the ComplianceAsCode control files for those versions.
#
#     Covered areas: unused filesystem / USB storage kernel modules, /tmp, /dev/shm and /var/tmp mounts,
#     AppArmor / SELinux, bootloader config access, ASLR, ptrace, core dumps, network sysctls (runtime and
#     persisted), sshd settings, crontab and account file permissions, UID 0, shadowed and empty passwords,
#     auditd enabled. Manual recommendations and package checks are not covered.
#
#     Nothing is changed. --root reads another file tree (a mounted image or a test fixture); sshd, sysctl
#     and service state are then taken from files only.
#
# .PARAMETER --env
#     'Test' or 'Prod'. Defaults to 'Test'. Read-only in both; recorded in the report.
#
# .PARAMETER --whatif
#     Dry run: prints the profile and the sources that would be read; reads none of them.
#
# .PARAMETER --profile NAME
#     auto (default, from <root>/etc/os-release), ubuntu2404 or rhel9.
#
# .PARAMETER --level L1|L2
#     CIS level. L2 includes every L1 recommendation. Default L1.
#
# .PARAMETER --id PATTERN
#     Only recommendations whose ID matches the shell pattern (e.g. '5.1.*'). Repeatable.
#
# .PARAMETER --root DIR
#     File tree to audit instead of /. Default /.
#
# .PARAMETER --output-dir DIR
#     Write cis-<host>-<level>-<UTC>.json, .ndjson and .csv there. Nothing is written when omitted.
#
# .PARAMETER --fail-on None|Fail|FailOrError
#     Exit code policy: None (default, exit 0), Fail (exit 1 on any Fail), FailOrError (also exit 2 when a
#     check could not be evaluated, e.g. not root). Same policy as the Windows runner.
#
# .PARAMETER --skip-applicability
#     Audit even when the OS does not match the profile (results indicative only).
#
# .PARAMETER --log-dir DIR
#     Directory for ScriptLog.log and the run-log NDJSON. Default Logs/ beside the script.
#
# .EXAMPLE
#     sudo ./audit_cis_linux.sh --level L1 --output-dir /var/tmp/cis
#
# .EXAMPLE
#     sudo ./audit_cis_linux.sh --id '5.1.*' | jq -c 'select(.result != "Pass") | {cis_id, expected, actual}'
#
# .EXAMPLE
#     ./audit_cis_linux.sh --root /mnt/image --profile rhel9 --level L2 > results.ndjson
#
# .OUTPUTS
#     NDJSON, one line per recommendation, on stdout (GOLDEN_STANDARDS 4.7); logs and summary on stderr.
#
# .NOTES
#     Purpose: Hardening baseline, before/after comparison and compliance evidence for Linux servers.
#     Security Context: verifies controls that block common footholds (T1543, T1548, T1021.004) and log tampering.
#     Security Domain: Compliance / Hardening
#     Author: RJGProjectz
#     Version: 2.0.0
#     Created: 2026-10-05T00:00:00Z
#     Last Modified: 2026-10-19T15:00:00Z
#     KB Article: [Linux CIS audit tool](../../docs/tasks/hardening/linux-cis-audit-tool.md)
#     Source Repo: https://www.cisecurity.org/cis-benchmarks ; https://github.com/ComplianceAsCode/content
#         sysctl.d(5), sshd_config(5), modprobe.d(5), proc(5), coredump.conf(5), selinux_config(5)
# -----------------------------------------------------------------------------
set -euo pipefail

# --- Configuration & Defaults ---
readonly SCRIPT_NAME="audit_cis_linux"
readonly SCRIPT_VERSION="2.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
TARGET_ENVIRONMENT="Test"
WHAT_IF=false
PROFILE="auto"
LEVEL="L1"
ID_FILTERS=()
AUDIT_ROOT="/"
OUTPUT_DIR=""
FAIL_ON="None"
SKIP_APPLICABILITY=false
LOG_DIR="${SCRIPT_DIR}/Logs"
EXECUTION_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || date +%s%N)"
readonly EXECUTION_ID

usage() {
    printf 'Usage: %s [--env Test|Prod] [--whatif] [--profile auto|ubuntu2404|rhel9] [--level L1|L2] [--id PATTERN]... [--root DIR] [--output-dir DIR] [--fail-on None|Fail|FailOrError] [--skip-applicability] [--log-dir DIR] [-h|--help]\n' "$(basename "$0")"
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

csv_field() {
    local raw="${1//\"/\"\"}"
    printf '"%s"' "$raw"
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
        "$timestamp" "$(json_escape "$(hostname 2>/dev/null || uname -n)")" "$SCRIPT_NAME" "$SCRIPT_VERSION" "$EXECUTION_ID" \
        "$TARGET_ENVIRONMENT" "$level" "$(json_escape "$message")" >> "${LOG_DIR}/${SCRIPT_NAME}.ndjson"
}

root_path() {
    printf '%s/%s' "${AUDIT_ROOT%/}" "${1#/}"
}

is_live() {
    [[ "$AUDIT_ROOT" == "/" ]]
}

os_release_value() {
    local key="$1" file
    file="$(root_path etc/os-release)"
    [[ -r "$file" ]] || return 0
    awk -F= -v k="$key" '$1 == k { v = $2; gsub(/^"|"$/, "", v); print v; exit }' "$file"
}

# --- Result collection ---
RESULTS_JSON=()
RESULTS_CSV=()
COUNT_PASS=0
COUNT_FAIL=0
COUNT_ERROR=0
COUNT_NA=0
CURRENT_ID=""
CURRENT_LEVEL=""
CURRENT_TITLE=""

# Record the result of the current recommendation. Arguments: status expected actual source detail.
Write-Result() {
    local status="$1" expected="$2" actual="$3" source="$4" detail="${5:-}"
    local section="${CURRENT_ID%%.*}" level="INFO" timestamp
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    case "$status" in
        Pass) COUNT_PASS=$((COUNT_PASS + 1)) ;;
        Fail) COUNT_FAIL=$((COUNT_FAIL + 1)); level="WARN" ;;
        Error) COUNT_ERROR=$((COUNT_ERROR + 1)); level="ERROR" ;;
        *) COUNT_NA=$((COUNT_NA + 1)) ;;
    esac
    RESULTS_JSON+=("$(printf '{"Id":"%s","Title":"%s","Level":"%s","Section":"%s","Status":"%s","Expected":"%s","Actual":"%s","Source":"%s","Detail":"%s"}' \
        "$CURRENT_ID" "$(json_escape "$CURRENT_TITLE")" "$CURRENT_LEVEL" "$section" "$status" "$(json_escape "$expected")" \
        "$(json_escape "$actual")" "$(json_escape "$source")" "$(json_escape "$detail")")")
    RESULTS_CSV+=("$(printf '%s,%s,%s,%s,%s,%s,%s,%s,%s' "$(csv_field "$CURRENT_ID")" "$(csv_field "$CURRENT_TITLE")" \
        "$CURRENT_LEVEL" "$section" "$status" "$(csv_field "$expected")" "$(csv_field "$actual")" "$(csv_field "$source")" "$(csv_field "$detail")")")
    local line
    line="$(printf '{"timestamp":"%s","host":"%s","tool":"%s","version":"%s","execution_id":"%s","level":"%s","message":"CIS %s %s","environment":"%s","action":"cis.check","target":"%s","result":"%s","benchmark":"%s","benchmark_version":"%s","os_edition":"%s","os_build":"%s","elevated":%s,"profile":"%s","cis_id":"%s","title":"%s","section":"%s","expected":"%s","actual":"%s","source":"%s","detail":"%s"}\n' \
        "$timestamp" "$(json_escape "$AUDITED_HOST")" "$SCRIPT_NAME" "$SCRIPT_VERSION" "$EXECUTION_ID" "$level" "$CURRENT_ID" "$status" \
        "$TARGET_ENVIRONMENT" "$CURRENT_ID" "$status" "$(json_escape "$BENCHMARK")" "$BENCHMARK_VERSION" "$(json_escape "$OS_EDITION")" \
        "$(json_escape "$OS_BUILD")" "$ELEVATED" "$CURRENT_LEVEL" "$CURRENT_ID" "$(json_escape "$CURRENT_TITLE")" "$section" \
        "$(json_escape "$expected")" "$(json_escape "$actual")" "$(json_escape "$source")" "$(json_escape "$detail")")"
    NDJSON_LINES+=("$line")
    printf '%s
' "$line"
}

# --- Kernel modules (modprobe.d(5)) ---
# "Not available": not loaded, and either not on disk or both "install <mod> /bin/false|/bin/true" and
# "blacklist <mod>" are configured.
Test-KernelModule() {
    local module="$1" underscored="${1//-/_}" loaded="no" on_disk="no" install_rule="no" blacklisted="no" dir file
    if [[ -r "$(root_path proc/modules)" ]] && awk -v m="$underscored" '$1 == m { found = 1 } END { exit !found }' "$(root_path proc/modules)"; then
        loaded="yes"
    fi
    if [[ -d "$(root_path lib/modules)" || -d "$(root_path usr/lib/modules)" ]]; then
        if find "$(root_path lib/modules)" "$(root_path usr/lib/modules)" -name "${module}.ko*" -print -quit 2>/dev/null | grep -q .; then on_disk="yes"; fi
        if find "$(root_path lib/modules)" "$(root_path usr/lib/modules)" -name "${underscored}.ko*" -print -quit 2>/dev/null | grep -q .; then on_disk="yes"; fi
    fi
    for dir in etc/modprobe.d run/modprobe.d usr/local/lib/modprobe.d usr/lib/modprobe.d lib/modprobe.d; do
        for file in "$(root_path "$dir")"/*.conf; do
            [[ -r "$file" ]] || continue
            if awk -v a="$module" -v b="$underscored" '$1 == "install" && ($2 == a || $2 == b) && $3 ~ /^(\/usr)?\/bin\/(false|true)$/ { f = 1 } END { exit !f }' "$file"; then install_rule="yes"; fi
            if awk -v a="$module" -v b="$underscored" '$1 == "blacklist" && ($2 == a || $2 == b) { f = 1 } END { exit !f }' "$file"; then blacklisted="yes"; fi
        done
    done
    local actual="loaded=$loaded on_disk=$on_disk install_false=$install_rule blacklist=$blacklisted"
    if [[ "$loaded" == "no" && ( "$on_disk" == "no" || ( "$install_rule" == "yes" && "$blacklisted" == "yes" ) ) ]]; then
        Write-Result Pass "not loaded; absent, or install /bin/false + blacklist" "$actual" "modprobe.d"
    else
        Write-Result Fail "not loaded; absent, or install /bin/false + blacklist" "$actual" "modprobe.d"
    fi
}

# --- Mounts (proc(5) /proc/mounts) ---
mount_options() {
    local mount_point="$1" file
    file="$(root_path proc/mounts)"
    [[ -r "$file" ]] || return 2
    awk -v p="$mount_point" '$2 == p { o = $4 } END { if (o == "") exit 1; print o }' "$file"
}

Test-SeparateMount() {
    local mount_point="$1" options rc=0
    options="$(mount_options "$mount_point")" || rc=$?
    case "$rc" in
        0) Write-Result Pass "separate mount" "mounted ($options)" "/proc/mounts" ;;
        1) Write-Result Fail "separate mount" "not a separate mount" "/proc/mounts" ;;
        *) Write-Result Error "separate mount" "unreadable" "/proc/mounts" ;;
    esac
}

Test-MountOption() {
    local mount_point="$1" option="$2" options rc=0
    options="$(mount_options "$mount_point")" || rc=$?
    if [[ "$rc" -eq 1 ]]; then
        Write-Result NotApplicable "$option" "not a separate mount" "/proc/mounts" "Covered by the separate-partition recommendation."
    elif [[ "$rc" -ne 0 ]]; then
        Write-Result Error "$option" "unreadable" "/proc/mounts"
    elif [[ ",$options," == *",$option,"* ]]; then
        Write-Result Pass "$option" "$options" "/proc/mounts"
    else
        Write-Result Fail "$option" "$options" "/proc/mounts"
    fi
}

# --- sysctl (runtime /proc/sys + persisted sysctl.d(5)) ---
# Persisted value: files from the sysctl.d directories ordered by file name (a name in /etc hides the same
# name in /run and /usr/lib), then /etc/sysctl.conf; the last assignment wins.
declare -A SYSCTL_PERSISTED=()
SYSCTL_LOADED=false
load_persisted_sysctl() {
    $SYSCTL_LOADED && return 0
    SYSCTL_LOADED=true
    declare -A seen=()
    local names=() dir file base key value line
    for dir in etc/sysctl.d run/sysctl.d usr/local/lib/sysctl.d usr/lib/sysctl.d lib/sysctl.d; do
        for file in "$(root_path "$dir")"/*.conf; do
            [[ -r "$file" ]] || continue
            base="$(basename "$file")"
            [[ -n "${seen[$base]:-}" ]] && continue
            seen[$base]="$file"
            names+=("$base")
        done
    done
    local ordered=()
    if [[ "${#names[@]}" -gt 0 ]]; then
        while IFS= read -r base; do ordered+=("${seen[$base]}"); done < <(printf '%s\n' "${names[@]}" | LC_ALL=C sort)
    fi
    [[ -r "$(root_path etc/sysctl.conf)" ]] && ordered+=("$(root_path etc/sysctl.conf)")
    for file in "${ordered[@]}"; do
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%%#*}"
            [[ "$line" == *=* ]] || continue
            key="${line%%=*}"; value="${line#*=}"
            key="$(printf '%s' "$key" | tr -d '[:space:]' | tr '/' '.')"; key="${key#-}"
            value="$(printf '%s' "$value" | xargs)"
            [[ -n "$key" ]] && SYSCTL_PERSISTED[$key]="$value"
        done < "$file"
    done
}

# Arguments: "key op value" triples as single words: key=value or key>=value. IPv6 keys are skipped when
# IPv6 is not present at runtime.
Test-Sysctl() {
    load_persisted_sysctl
    local spec key op want runtime persisted path ok=true actual="" expected=""
    for spec in "$@"; do
        if [[ "$spec" == *">="* ]]; then op=">="; key="${spec%%>=*}"; want="${spec#*>=}"
        else op="="; key="${spec%%=*}"; want="${spec#*=}"; fi
        expected+="${expected:+, }${key} ${op} ${want}"
        path="$(root_path "proc/sys/${key//.//}")"
        if [[ ! -r "$path" ]]; then
            if [[ "$key" == net.ipv6.* && ! -d "$(root_path proc/sys/net/ipv6)" ]]; then
                actual+="${actual:+; }${key}=n/a (no IPv6)"
                continue
            fi
            Write-Result Error "$expected" "${key}: runtime value unreadable" "/proc/sys + sysctl.d"
            return 0
        fi
        runtime="$(tr -d '[:space:]' < "$path")"
        persisted="${SYSCTL_PERSISTED[$key]:-unset}"
        actual+="${actual:+; }${key}=${runtime} (persisted ${persisted})"
        if [[ "$op" == ">=" ]]; then
            [[ "$runtime" =~ ^[0-9]+$ && "$runtime" -ge "$want" && "$persisted" =~ ^[0-9]+$ && "$persisted" -ge "$want" ]] || ok=false
        else
            [[ "$runtime" == "$want" && "$persisted" == "$want" ]] || ok=false
        fi
    done
    if $ok; then
        Write-Result Pass "$expected (runtime and persisted)" "$actual" "/proc/sys + sysctl.d"
    else
        Write-Result Fail "$expected (runtime and persisted)" "$actual" "/proc/sys + sysctl.d"
    fi
}

# --- File permissions ---
# Arguments: path max_mode(octal) allowed_groups(comma list). Owner must be root (UID 0). A missing file
# passes when optional=optional is given (backup files such as /etc/shadow-).
Test-FilePermission() {
    local path="$1" max_mode="$2" groups="$3" optional="${4:-}" file mode uid group
    file="$(root_path "$path")"
    if [[ ! -e "$file" ]]; then
        if [[ "$optional" == "optional" ]]; then
            Write-Result NotApplicable "mode <= $max_mode, owner root, group $groups" "file absent" "$path"
        else
            Write-Result Fail "mode <= $max_mode, owner root, group $groups" "file absent" "$path"
        fi
        return 0
    fi
    if ! mode="$(stat -c '%a' "$file" 2>/dev/null)"; then
        Write-Result Error "mode <= $max_mode, owner root, group $groups" "stat failed" "$path"
        return 0
    fi
    uid="$(stat -c '%u' "$file")"
    group="$(stat -c '%G' "$file" 2>/dev/null || stat -c '%g' "$file")"
    local actual
    actual="$(printf 'mode %04o, uid %s, group %s' "$((8#$mode))" "$uid" "$group")"
    if (( (8#$mode & ~8#$max_mode) == 0 )) && [[ "$uid" == "0" && ",$groups," == *",$group,"* ]]; then
        Write-Result Pass "mode <= $max_mode, owner root, group $groups" "$actual" "$path"
    else
        Write-Result Fail "mode <= $max_mode, owner root, group $groups" "$actual" "$path"
    fi
}

# --- sshd (sshd_config(5): the first value obtained for a keyword is used) ---
declare -A SSHD=()
SSHD_SOURCE=""
SSHD_LOADED=false

sshd_parse_file() {
    local file="$1" depth="${2:-0}" line keyword value pattern included
    [[ "$depth" -gt 8 || ! -r "$file" ]] && return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        [[ -z "$line" ]] && continue
        keyword="$(printf '%s' "${line%%[[:space:]=]*}" | tr '[:upper:]' '[:lower:]')"
        value="$(printf '%s' "${line#*[[:space:]=]}" | sed -e 's/^[[:space:]=]*//')"
        if [[ "$keyword" == "match" ]]; then
            SSHD_MATCH=true
            return 0
        fi
        if [[ "$keyword" == "include" ]]; then
            for pattern in $value; do
                [[ "$pattern" != /* ]] && pattern="/etc/ssh/$pattern"
                for included in $(root_path "$pattern"); do
                    sshd_parse_file "$included" $((depth + 1))
                    $SSHD_MATCH && return 0
                done
            done
            continue
        fi
        [[ -z "${SSHD[$keyword]:-}" ]] && SSHD[$keyword]="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
    done < "$file"
}

# sshd -T prints times in seconds; config files may use 1m / 2h forms (sshd_config(5) TIME FORMATS).
to_seconds() {
    local value="$1" total=0 number unit
    [[ "$value" =~ ^[0-9]+$ ]] && { printf '%s' "$value"; return 0; }
    while [[ "$value" =~ ^([0-9]+)([smhdw])(.*)$ ]]; do
        number="${BASH_REMATCH[1]}"; unit="${BASH_REMATCH[2]}"; value="${BASH_REMATCH[3]}"
        case "$unit" in s) total=$((total + number)) ;; m) total=$((total + number * 60)) ;; h) total=$((total + number * 3600)) ;; d) total=$((total + number * 86400)) ;; w) total=$((total + number * 604800)) ;; esac
    done
    printf '%s' "$total"
}

load_sshd() {
    $SSHD_LOADED && return 0
    SSHD_LOADED=true
    SSHD_MATCH=false
    if is_live && [[ "$(id -u)" -eq 0 ]] && command -v sshd >/dev/null 2>&1; then
        local keyword value
        while read -r keyword value; do
            [[ -n "$keyword" && -z "${SSHD[$keyword]:-}" ]] && SSHD[$keyword]="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
        done < <(sshd -T 2>/dev/null < /dev/null || true)
        SSHD_SOURCE="sshd -T"
    fi
    if [[ "${#SSHD[@]}" -eq 0 ]]; then
        sshd_parse_file "$(root_path etc/ssh/sshd_config)"
        SSHD_SOURCE="/etc/ssh/sshd_config (+ Include, global section)"
    fi
    # OpenSSH defaults for keywords that are not set (sshd_config(5)).
    local defaults=(permitrootlogin=prohibit-password maxauthtries=6 permitemptypasswords=no hostbasedauthentication=no
        ignorerhosts=yes logingracetime=120 clientaliveinterval=0 clientalivecountmax=3 loglevel=info maxsessions=10
        maxstartups=10:30:100 usepam=no permituserenvironment=no banner=none disableforwarding=no)
    local pair
    for pair in "${defaults[@]}"; do
        [[ -z "${SSHD[${pair%%=*}]:-}" ]] && SSHD[${pair%%=*}]="${pair#*=}"
    done
}

# Arguments: keyword op value; op is eq | in (comma list) | le | range (min-max) | ne | maxstartups | clientalive.
Test-Sshd() {
    local keyword="$1" op="$2" want="$3" actual ok=false
    if [[ ! -r "$(root_path etc/ssh/sshd_config)" ]]; then
        if [[ -e "$(root_path etc/ssh/sshd_config)" ]]; then
            Write-Result Error "$keyword $op $want" "sshd_config unreadable" "/etc/ssh/sshd_config"
        else
            Write-Result NotApplicable "$keyword $op $want" "OpenSSH server not installed" "/etc/ssh/sshd_config"
        fi
        return 0
    fi
    load_sshd
    actual="${SSHD[$keyword]}"
    case "$op" in
        eq) [[ "$actual" == "$want" ]] && ok=true ;;
        ne) [[ "$actual" != "$want" ]] && ok=true ;;
        in) [[ ",$want," == *",$actual,"* ]] && ok=true ;;
        le) [[ "$actual" =~ ^[0-9]+$ && "$actual" -le "$want" ]] && ok=true ;;
        range)
            actual="$(to_seconds "$actual")"
            [[ "$actual" -ge "${want%-*}" && "$actual" -le "${want#*-}" ]] && ok=true ;;
        maxstartups)
            local start rate full w1 w2 w3
            IFS=: read -r start rate full <<< "$actual"
            IFS=: read -r w1 w2 w3 <<< "$want"
            rate="${rate:-$w2}"; full="${full:-$start}"
            [[ "$start" -le "$w1" && "$rate" -le "$w2" && "$full" -le "$w3" ]] && ok=true ;;
        clientalive)
            actual="clientaliveinterval $(to_seconds "${SSHD[clientaliveinterval]}"), clientalivecountmax ${SSHD[clientalivecountmax]}"
            [[ "$(to_seconds "${SSHD[clientaliveinterval]}")" -gt 0 && "${SSHD[clientalivecountmax]}" -gt 0 ]] && ok=true ;;
    esac
    if $ok; then Write-Result Pass "$keyword $op $want" "$actual" "$SSHD_SOURCE"
    else Write-Result Fail "$keyword $op $want" "$actual" "$SSHD_SOURCE"; fi
}

# --- Accounts ---
Test-RootOnlyUid0() {
    local file others
    file="$(root_path etc/passwd)"
    [[ -r "$file" ]] || { Write-Result Error "only root has UID 0" "unreadable" "/etc/passwd"; return 0; }
    others="$(awk -F: '$3 == 0 && $1 != "root" { printf "%s%s", s, $1; s = "," }' "$file")"
    if [[ -z "$others" ]]; then Write-Result Pass "only root has UID 0" "root" "/etc/passwd"
    else Write-Result Fail "only root has UID 0" "also: $others" "/etc/passwd"; fi
}

Test-ShadowedPassword() {
    local file others
    file="$(root_path etc/passwd)"
    [[ -r "$file" ]] || { Write-Result Error "password field is x for every account" "unreadable" "/etc/passwd"; return 0; }
    others="$(awk -F: 'NF > 1 && $2 != "x" { printf "%s%s", s, $1; s = "," }' "$file")"
    if [[ -z "$others" ]]; then Write-Result Pass "password field is x for every account" "all shadowed" "/etc/passwd"
    else Write-Result Fail "password field is x for every account" "not shadowed: $others" "/etc/passwd"; fi
}

Test-ShadowNotEmpty() {
    local file others
    file="$(root_path etc/shadow)"
    [[ -r "$file" ]] || { Write-Result Error "no empty password field" "unreadable (run as root)" "/etc/shadow"; return 0; }
    others="$(awk -F: 'NF > 1 && $2 == "" { printf "%s%s", s, $1; s = "," }' "$file")"
    if [[ -z "$others" ]]; then Write-Result Pass "no empty password field" "none empty" "/etc/shadow"
    else Write-Result Fail "no empty password field" "empty: $others" "/etc/shadow"; fi
}

# --- Mandatory access control and boot ---
boot_entries() {
    local file
    for file in "$(root_path "$GRUB_CFG")" "$(root_path boot/loader/entries)"/*.conf; do
        [[ -r "$file" ]] && printf '%s\n' "$file"
    done
    return 0
}

Test-AppArmorBoot() {
    local file
    file="$(root_path "$GRUB_CFG")"
    [[ -r "$file" ]] || { Write-Result Error "apparmor=1 security=apparmor on every linux line" "grub.cfg unreadable" "/$GRUB_CFG"; return 0; }
    local missing
    missing="$(awk '$1 == "linux" && !(/apparmor=1/ && /security=apparmor/) { n++ } END { print n + 0 }' "$file")"
    if [[ "$missing" -eq 0 ]] && grep -q '^[[:space:]]*linux' "$file"; then
        Write-Result Pass "apparmor=1 security=apparmor on every linux line" "all linux lines" "/$GRUB_CFG"
    else
        Write-Result Fail "apparmor=1 security=apparmor on every linux line" "$missing linux line(s) without both" "/$GRUB_CFG"
    fi
}

Test-SelinuxBoot() {
    local file hits="" found=false
    while IFS= read -r file; do
        found=true
        if grep -Eq '(^|[[:space:]])(selinux|enforcing)=0([[:space:]]|$)' "$file"; then hits+="${hits:+, }${file#"${AUDIT_ROOT%/}"}"; fi
    done < <(boot_entries)
    if ! $found; then
        Write-Result Error "no selinux=0 or enforcing=0 on the kernel command line" "no readable grub.cfg or BLS entry" "/$GRUB_CFG, /boot/loader/entries"
    elif [[ -z "$hits" ]]; then
        Write-Result Pass "no selinux=0 or enforcing=0 on the kernel command line" "none found" "/$GRUB_CFG, /boot/loader/entries"
    else
        Write-Result Fail "no selinux=0 or enforcing=0 on the kernel command line" "found in: $hits" "/$GRUB_CFG, /boot/loader/entries"
    fi
}

# Argument: notdisabled | enforcing. Uses SELINUX= in /etc/selinux/config and, when present, the runtime
# /sys/fs/selinux/enforce (1 = enforcing, 0 = permissive).
Test-SelinuxMode() {
    local want="$1" config runtime="absent" ok=false offline=false
    is_live || offline=true
    config="$(awk -F= '$1 == "SELINUX" { print tolower($2) }' "$(root_path etc/selinux/config)" 2>/dev/null | tail -n 1 || true)"
    [[ -r "$(root_path sys/fs/selinux/enforce)" ]] && runtime="$(tr -d '[:space:]' < "$(root_path sys/fs/selinux/enforce)")"
    if [[ "$want" == "enforcing" ]]; then
        [[ "$config" == "enforcing" && ( "$runtime" == "1" || ( "$runtime" == "absent" && "$offline" == "true" ) ) ]] && ok=true
    else
        [[ ( "$config" == "enforcing" || "$config" == "permissive" ) && ( "$runtime" == "1" || "$runtime" == "0" || ( "$runtime" == "absent" && "$offline" == "true" ) ) ]] && ok=true
    fi
    if $ok; then Write-Result Pass "SELinux $want" "config ${config:-unset}, runtime enforce ${runtime}" "/etc/selinux/config"
    else Write-Result Fail "SELinux $want" "config ${config:-unset}, runtime enforce ${runtime}" "/etc/selinux/config"; fi
}

# --- Core dumps ---
Test-CoreDumpLimits() {
    local hard="unset" file
    for file in "$(root_path etc/security/limits.conf)" "$(root_path etc/security/limits.d)"/*.conf; do
        [[ -r "$file" ]] || continue
        local value
        value="$(awk '$1 == "*" && $2 == "hard" && $3 == "core" { v = $4 } END { if (v != "") print v }' "$file")"
        [[ -n "$value" ]] && hard="$value"
    done
    load_persisted_sysctl
    local runtime="unreadable" persisted="${SYSCTL_PERSISTED[fs.suid_dumpable]:-unset}"
    [[ -r "$(root_path proc/sys/fs/suid_dumpable)" ]] && runtime="$(tr -d '[:space:]' < "$(root_path proc/sys/fs/suid_dumpable)")"
    local actual="* hard core ${hard}; fs.suid_dumpable=${runtime} (persisted ${persisted})"
    if [[ "$hard" == "0" && "$runtime" == "0" && "$persisted" == "0" ]]; then
        Write-Result Pass "* hard core 0; fs.suid_dumpable = 0" "$actual" "limits.conf + sysctl"
    else
        Write-Result Fail "* hard core 0; fs.suid_dumpable = 0" "$actual" "limits.conf + sysctl"
    fi
}

# coredump.conf(5): [Coredump] in /etc/systemd/coredump.conf, overridden by coredump.conf.d drop-ins.
Test-CoredumpConf() {
    local key="$1" want="$2" value="" file
    for file in "$(root_path etc/systemd/coredump.conf)" "$(root_path usr/lib/systemd/coredump.conf.d)"/*.conf "$(root_path etc/systemd/coredump.conf.d)"/*.conf; do
        [[ -r "$file" ]] || continue
        local v
        v="$(awk -F= -v k="$key" '{ gsub(/[[:space:]]/, "", $1) } $1 == k { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); val = $2 } END { print val }' "$file")"
        [[ -n "$v" ]] && value="$v"
    done
    if [[ "${value,,}" == "${want,,}" ]]; then Write-Result Pass "$key=$want" "$key=${value}" "coredump.conf"
    else Write-Result Fail "$key=$want" "$key=${value:-unset}" "coredump.conf"; fi
}

# --- Services ---
Test-ServiceEnabled() {
    local unit="$1" enabled="no" active="not checked"
    if is_live && command -v systemctl >/dev/null 2>&1; then
        systemctl is-enabled --quiet "$unit" 2>/dev/null && enabled="yes"
        if systemctl is-active --quiet "$unit" 2>/dev/null; then active="active"; else active="inactive"; fi
    else
        compgen -G "$(root_path etc/systemd/system)/*.wants/${unit}.service" >/dev/null && enabled="yes"
    fi
    if [[ "$enabled" == "yes" && "$active" != "inactive" ]]; then
        Write-Result Pass "$unit enabled and active" "enabled=$enabled, $active" "systemd"
    else
        Write-Result Fail "$unit enabled and active" "enabled=$enabled, $active" "systemd"
    fi
}

# --- Profiles: id|level|title|check function and arguments ---
# Titles and levels (server profile) from the ComplianceAsCode control files for each benchmark version.
COMMON_SYSCTL_CHECKS='3.3.1|L1|Ensure ip forwarding is disabled|Test-Sysctl net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0
3.3.2|L1|Ensure packet redirect sending is disabled|Test-Sysctl net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0
3.3.3|L1|Ensure bogus icmp responses are ignored|Test-Sysctl net.ipv4.icmp_ignore_bogus_error_responses=1
3.3.4|L1|Ensure broadcast icmp requests are ignored|Test-Sysctl net.ipv4.icmp_echo_ignore_broadcasts=1
3.3.5|L1|Ensure icmp redirects are not accepted|Test-Sysctl net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0 net.ipv6.conf.all.accept_redirects=0 net.ipv6.conf.default.accept_redirects=0
3.3.6|L1|Ensure secure icmp redirects are not accepted|Test-Sysctl net.ipv4.conf.all.secure_redirects=0 net.ipv4.conf.default.secure_redirects=0
3.3.7|L1|Ensure reverse path filtering is enabled|Test-Sysctl net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1
3.3.8|L1|Ensure source routed packets are not accepted|Test-Sysctl net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.default.accept_source_route=0 net.ipv6.conf.all.accept_source_route=0 net.ipv6.conf.default.accept_source_route=0
3.3.9|L1|Ensure suspicious packets are logged|Test-Sysctl net.ipv4.conf.all.log_martians=1 net.ipv4.conf.default.log_martians=1
3.3.10|L1|Ensure tcp syn cookies is enabled|Test-Sysctl net.ipv4.tcp_syncookies=1'

COMMON_FILE_CHECKS='2.4.1.2|L1|Ensure permissions on /etc/crontab are configured|Test-FilePermission /etc/crontab 600 root optional
5.4.2.1|L1|Ensure root is the only UID 0 account|Test-RootOnlyUid0
7.1.1|L1|Ensure permissions on /etc/passwd are configured|Test-FilePermission /etc/passwd 644 root
7.1.2|L1|Ensure permissions on /etc/passwd- are configured|Test-FilePermission /etc/passwd- 644 root optional
7.1.3|L1|Ensure permissions on /etc/group are configured|Test-FilePermission /etc/group 644 root
7.1.4|L1|Ensure permissions on /etc/group- are configured|Test-FilePermission /etc/group- 644 root optional
7.2.1|L1|Ensure accounts in /etc/passwd use shadowed passwords|Test-ShadowedPassword
7.2.2|L1|Ensure /etc/shadow password fields are not empty|Test-ShadowNotEmpty'

COMMON_MOUNT_CHECKS='1.1.1.1|L1|Ensure cramfs kernel module is not available|Test-KernelModule cramfs
1.1.1.2|L1|Ensure freevxfs kernel module is not available|Test-KernelModule freevxfs
1.1.1.3|L1|Ensure hfs kernel module is not available|Test-KernelModule hfs
1.1.1.4|L1|Ensure hfsplus kernel module is not available|Test-KernelModule hfsplus
1.1.1.5|L1|Ensure jffs2 kernel module is not available|Test-KernelModule jffs2
1.1.2.1.1|L1|Ensure /tmp is a separate partition|Test-SeparateMount /tmp
1.1.2.1.2|L1|Ensure nodev option set on /tmp partition|Test-MountOption /tmp nodev
1.1.2.1.3|L1|Ensure nosuid option set on /tmp partition|Test-MountOption /tmp nosuid
1.1.2.1.4|L1|Ensure noexec option set on /tmp partition|Test-MountOption /tmp noexec
1.1.2.2.1|L1|Ensure /dev/shm is a separate partition|Test-SeparateMount /dev/shm
1.1.2.2.2|L1|Ensure nodev option set on /dev/shm partition|Test-MountOption /dev/shm nodev
1.1.2.2.3|L1|Ensure nosuid option set on /dev/shm partition|Test-MountOption /dev/shm nosuid
1.1.2.2.4|L1|Ensure noexec option set on /dev/shm partition|Test-MountOption /dev/shm noexec
1.1.2.5.2|L1|Ensure nodev option set on /var/tmp partition|Test-MountOption /var/tmp nodev
1.1.2.5.3|L1|Ensure nosuid option set on /var/tmp partition|Test-MountOption /var/tmp nosuid
1.1.2.5.4|L1|Ensure noexec option set on /var/tmp partition|Test-MountOption /var/tmp noexec
1.5.1|L1|Ensure address space layout randomization is enabled|Test-Sysctl kernel.randomize_va_space=2
1.5.2|L1|Ensure ptrace_scope is restricted|Test-Sysctl kernel.yama.ptrace_scope>=1'

PROFILE_UBUNTU2404="${COMMON_MOUNT_CHECKS}
1.1.1.7|L2|Ensure squashfs kernel module is not available|Test-KernelModule squashfs
1.1.1.9|L1|Ensure usb-storage kernel module is not available|Test-KernelModule usb-storage
1.3.1.2|L1|Ensure AppArmor is enabled in the bootloader configuration|Test-AppArmorBoot
1.4.2|L1|Ensure access to bootloader config is configured|Test-FilePermission /boot/grub/grub.cfg 600 root
1.5.3|L1|Ensure core dumps are restricted|Test-CoreDumpLimits
${COMMON_SYSCTL_CHECKS}
3.3.11|L1|Ensure ipv6 router advertisements are not accepted|Test-Sysctl net.ipv6.conf.all.accept_ra=0 net.ipv6.conf.default.accept_ra=0
5.1.1|L1|Ensure permissions on /etc/ssh/sshd_config are configured|Test-FilePermission /etc/ssh/sshd_config 600 root
5.1.5|L1|Ensure sshd Banner is configured|Test-Sshd banner ne none
5.1.7|L1|Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured|Test-Sshd clientaliveinterval clientalive >0
5.1.8|L2|Ensure sshd DisableForwarding is enabled|Test-Sshd disableforwarding eq yes
5.1.10|L1|Ensure sshd HostbasedAuthentication is disabled|Test-Sshd hostbasedauthentication eq no
5.1.11|L1|Ensure sshd IgnoreRhosts is enabled|Test-Sshd ignorerhosts eq yes
5.1.13|L1|Ensure sshd LoginGraceTime is configured|Test-Sshd logingracetime range 1-60
5.1.14|L1|Ensure sshd LogLevel is configured|Test-Sshd loglevel in info,verbose
5.1.16|L1|Ensure sshd MaxAuthTries is configured|Test-Sshd maxauthtries le 4
5.1.17|L1|Ensure sshd MaxSessions is configured|Test-Sshd maxsessions le 10
5.1.18|L1|Ensure sshd MaxStartups is configured|Test-Sshd maxstartups maxstartups 10:30:60
5.1.19|L1|Ensure sshd PermitEmptyPasswords is disabled|Test-Sshd permitemptypasswords eq no
5.1.20|L1|Ensure sshd PermitRootLogin is disabled|Test-Sshd permitrootlogin eq no
5.1.21|L1|Ensure sshd PermitUserEnvironment is disabled|Test-Sshd permituserenvironment eq no
5.1.22|L1|Ensure sshd UsePAM is enabled|Test-Sshd usepam eq yes
6.2.1.2|L2|Ensure auditd service is enabled and active|Test-ServiceEnabled auditd
${COMMON_FILE_CHECKS}
7.1.5|L1|Ensure permissions on /etc/shadow are configured|Test-FilePermission /etc/shadow 640 root,shadow
7.1.6|L1|Ensure permissions on /etc/shadow- are configured|Test-FilePermission /etc/shadow- 640 root,shadow optional
7.1.7|L1|Ensure permissions on /etc/gshadow are configured|Test-FilePermission /etc/gshadow 640 root,shadow
7.1.8|L1|Ensure permissions on /etc/gshadow- are configured|Test-FilePermission /etc/gshadow- 640 root,shadow optional"

PROFILE_RHEL9="${COMMON_MOUNT_CHECKS}
1.1.1.6|L2|Ensure squashfs kernel module is not available|Test-KernelModule squashfs
1.1.1.8|L1|Ensure usb-storage kernel module is not available|Test-KernelModule usb-storage
1.3.1.2|L1|Ensure SELinux is not disabled in bootloader configuration|Test-SelinuxBoot
1.3.1.4|L1|Ensure the SELinux mode is not disabled|Test-SelinuxMode notdisabled
1.3.1.5|L2|Ensure the SELinux mode is enforcing|Test-SelinuxMode enforcing
1.4.2|L1|Ensure access to bootloader config is configured|Test-FilePermission /boot/grub2/grub.cfg 600 root
1.5.3|L1|Ensure core dump backtraces are disabled|Test-CoredumpConf ProcessSizeMax 0
1.5.4|L1|Ensure core dump storage is disabled|Test-CoredumpConf Storage none
${COMMON_SYSCTL_CHECKS}
3.3.11|L1|Ensure IPv6 router advertisements are not accepted|Test-Sysctl net.ipv6.conf.all.accept_ra=0 net.ipv6.conf.default.accept_ra=0
5.1.1|L1|Ensure permissions on /etc/ssh/sshd_config are configured|Test-FilePermission /etc/ssh/sshd_config 600 root
5.1.8|L1|Ensure sshd Banner is configured|Test-Sshd banner ne none
5.1.9|L1|Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured|Test-Sshd clientaliveinterval clientalive >0
5.1.10|L2|Ensure sshd DisableForwarding is enabled|Test-Sshd disableforwarding eq yes
5.1.12|L1|Ensure sshd HostbasedAuthentication is disabled|Test-Sshd hostbasedauthentication eq no
5.1.13|L1|Ensure sshd IgnoreRhosts is enabled|Test-Sshd ignorerhosts eq yes
5.1.14|L1|Ensure sshd LoginGraceTime is configured|Test-Sshd logingracetime range 1-60
5.1.15|L1|Ensure sshd LogLevel is configured|Test-Sshd loglevel in info,verbose
5.1.16|L1|Ensure sshd MaxAuthTries is configured|Test-Sshd maxauthtries le 4
5.1.17|L1|Ensure sshd MaxStartups is configured|Test-Sshd maxstartups maxstartups 10:30:60
5.1.18|L1|Ensure sshd MaxSessions is configured|Test-Sshd maxsessions le 10
5.1.19|L1|Ensure sshd PermitEmptyPasswords is disabled|Test-Sshd permitemptypasswords eq no
5.1.20|L1|Ensure sshd PermitRootLogin is disabled|Test-Sshd permitrootlogin eq no
5.1.21|L1|Ensure sshd PermitUserEnvironment is disabled|Test-Sshd permituserenvironment eq no
5.1.22|L1|Ensure sshd UsePAM is enabled|Test-Sshd usepam eq yes
6.3.1.4|L2|Ensure auditd service is enabled and active|Test-ServiceEnabled auditd
${COMMON_FILE_CHECKS}
7.1.5|L1|Ensure permissions on /etc/shadow are configured|Test-FilePermission /etc/shadow 0 root
7.1.6|L1|Ensure permissions on /etc/shadow- are configured|Test-FilePermission /etc/shadow- 0 root optional
7.1.7|L1|Ensure permissions on /etc/gshadow are configured|Test-FilePermission /etc/gshadow 0 root
7.1.8|L1|Ensure permissions on /etc/gshadow- are configured|Test-FilePermission /etc/gshadow- 0 root optional"

detect_profile() {
    local id like version
    id="$(os_release_value ID)"; like="$(os_release_value ID_LIKE)"; version="$(os_release_value VERSION_ID)"
    if [[ "$id" == "ubuntu" && "$version" == "24.04" ]]; then printf 'ubuntu2404'
    elif [[ ( "$id" =~ ^(rhel|rocky|almalinux|ol|centos)$ || " $like " == *" rhel "* ) && "${version%%.*}" == "9" ]]; then printf 'rhel9'
    fi
    return 0
}

id_selected() {
    local id="$1" pattern
    [[ "${#ID_FILTERS[@]}" -eq 0 ]] && return 0
    for pattern in "${ID_FILTERS[@]}"; do
        # shellcheck disable=SC2053  # pattern match is intended
        [[ "$id" == $pattern ]] && return 0
    done
    return 1
}

write_reports() {
    local base="$1" summary="$2"
    mkdir -p "$OUTPUT_DIR"
    {
        printf '{"schema":"cc.cis.report/1","tool":"%s","version":"%s","execution_id":"%s","timestamp":"%s","host":"%s","environment":"%s","elevated":%s,' \
            "$SCRIPT_NAME" "$SCRIPT_VERSION" "$EXECUTION_ID" "$STARTED_UTC" "$(json_escape "$AUDITED_HOST")" "$TARGET_ENVIRONMENT" "$ELEVATED"
        printf '"osEdition":"%s","osBuild":"%s","auditRoot":"%s","benchmark":"%s","benchmarkVersion":"%s","benchmarkProfile":"%s","profile":"%s","failOn":"%s","summary":%s,"results":[' \
            "$(json_escape "$OS_EDITION")" "$(json_escape "$OS_BUILD")" "$(json_escape "$AUDIT_ROOT")" "$(json_escape "$BENCHMARK")" "$BENCHMARK_VERSION" "$PROFILE" "$LEVEL" "$FAIL_ON" "$summary"
        local i
        for i in "${!RESULTS_JSON[@]}"; do
            [[ "$i" -gt 0 ]] && printf ','
            printf '%s' "${RESULTS_JSON[$i]}"
        done
        printf ']}\n'
    } > "${base}.json"
    printf '%s\n' "${NDJSON_LINES[@]}" > "${base}.ndjson"
    {
        printf 'Id,Title,Level,Section,Status,Expected,Actual,Source,Detail\n'
        printf '%s\n' "${RESULTS_CSV[@]}"
    } > "${base}.csv"
    Write-Log "Reports written: ${base}.json, .ndjson, .csv"
}

# --- Argument Parsing ---
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --env)        TARGET_ENVIRONMENT="${2:-}"; shift ;;
        --whatif|--dry-run) WHAT_IF=true ;;
        --profile)    PROFILE="${2:-}"; shift ;;
        --level)      LEVEL="${2:-}"; shift ;;
        --id)         ID_FILTERS+=("${2:-}"); shift ;;
        --root)       AUDIT_ROOT="${2:-}"; shift ;;
        --output-dir) OUTPUT_DIR="${2:-}"; shift ;;
        --fail-on)    FAIL_ON="${2:-}"; shift ;;
        --skip-applicability) SKIP_APPLICABILITY=true ;;
        --log-dir)    LOG_DIR="${2:-}"; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            Write-Log "Unknown parameter: $1 (use -h for usage)" "WARN"; exit 2 ;;
    esac
    shift
done

if [[ "$TARGET_ENVIRONMENT" != "Test" && "$TARGET_ENVIRONMENT" != "Prod" ]]; then Write-Log "--env must be Test or Prod." "ERROR"; exit 2; fi
if [[ "$LEVEL" != "L1" && "$LEVEL" != "L2" ]]; then Write-Log "--level must be L1 or L2." "ERROR"; exit 2; fi
if [[ ! "$FAIL_ON" =~ ^(None|Fail|FailOrError)$ ]]; then Write-Log "--fail-on must be None, Fail or FailOrError." "ERROR"; exit 2; fi
if [[ -z "$AUDIT_ROOT" || ! -d "$AUDIT_ROOT" ]]; then Write-Log "--root must be an existing directory." "ERROR"; exit 2; fi

# --- Begin ---
DETECTED="$(detect_profile)"
if [[ "$PROFILE" == "auto" ]]; then
    if [[ -z "$DETECTED" ]]; then
        Write-Log "No CIS profile for '$(os_release_value PRETTY_NAME)'. Pass --profile ubuntu2404|rhel9 with --skip-applicability to audit anyway." "ERROR"
        exit 2
    fi
    PROFILE="$DETECTED"
fi
case "$PROFILE" in
    ubuntu2404) BENCHMARK="CIS Ubuntu Linux 24.04 LTS"; BENCHMARK_VERSION="1.0.0"; GRUB_CFG="boot/grub/grub.cfg"; CHECKS="$PROFILE_UBUNTU2404" ;;
    rhel9)      BENCHMARK="CIS Red Hat Enterprise Linux 9"; BENCHMARK_VERSION="2.0.0"; GRUB_CFG="boot/grub2/grub.cfg"; CHECKS="$PROFILE_RHEL9" ;;
    *) Write-Log "--profile must be auto, ubuntu2404 or rhel9." "ERROR"; exit 2 ;;
esac
if [[ "$DETECTED" != "$PROFILE" ]]; then
    if ! $SKIP_APPLICABILITY; then
        Write-Log "Host OS '$(os_release_value PRETTY_NAME)' is not covered by profile $PROFILE. Use --skip-applicability to audit anyway." "ERROR"
        exit 2
    fi
    Write-Log "Host is outside the profile scope; results are indicative only." "WARN"
fi

if [[ "$WHAT_IF" == "true" ]]; then
    Write-Log "[WHATIF] Would audit $BENCHMARK v$BENCHMARK_VERSION ($PROFILE, $LEVEL) under ${AUDIT_ROOT}: /proc/modules, modprobe.d, /proc/mounts, /proc/sys + sysctl.d, /$GRUB_CFG, sshd_config (or sshd -T), limits.conf/coredump.conf, /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow, /etc/crontab, systemd units. Nothing is changed."
    exit 0
fi

STARTED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ELEVATED=false; [[ "$(id -u)" -eq 0 ]] && ELEVATED=true
OS_EDITION="$(os_release_value PRETTY_NAME)"
OS_BUILD="$(if is_live; then uname -r; else printf 'offline tree'; fi)"
if is_live; then AUDITED_HOST="$(hostname 2>/dev/null || uname -n)"
else AUDITED_HOST="$(head -n 1 "$(root_path etc/hostname)" 2>/dev/null || printf 'offline')"; fi
Write-Log "Starting ${SCRIPT_NAME} ${SCRIPT_VERSION}: $BENCHMARK v$BENCHMARK_VERSION, $PROFILE $LEVEL, root ${AUDIT_ROOT}, [${TARGET_ENVIRONMENT}] (read-only)."
if ! $ELEVATED && is_live; then
    Write-Log "Not running as root: /etc/shadow, grub.cfg and sshd -T are unreadable; those checks report Error." "WARN"
fi

NDJSON_LINES=()
while IFS='|' read -r CURRENT_ID CURRENT_LEVEL CURRENT_TITLE command_line; do
    [[ -z "$CURRENT_ID" ]] && continue
    [[ "$LEVEL" == "L1" && "$CURRENT_LEVEL" == "L2" ]] && continue
    id_selected "$CURRENT_ID" || continue
    read -r -a command_words <<< "$command_line"
    "${command_words[@]}" < /dev/null
done < <(printf '%s
' "$CHECKS" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n -k5,5n)

TOTAL=$((COUNT_PASS + COUNT_FAIL + COUNT_ERROR + COUNT_NA))
SCORED=$((COUNT_PASS + COUNT_FAIL))
SCORE="0"
[[ "$SCORED" -gt 0 ]] && SCORE="$(awk -v p="$COUNT_PASS" -v s="$SCORED" 'BEGIN { printf "%.1f", 100 * p / s }')"
SUMMARY="$(printf '{"total":%d,"pass":%d,"fail":%d,"error":%d,"notApplicable":%d,"scorePct":%s}'     "$TOTAL" "$COUNT_PASS" "$COUNT_FAIL" "$COUNT_ERROR" "$COUNT_NA" "$SCORE")"
Write-Log "Summary: $TOTAL checks, $COUNT_PASS pass, $COUNT_FAIL fail, $COUNT_ERROR error, $COUNT_NA n/a - score ${SCORE}% (pass / (pass + fail))"
if [[ -n "$OUTPUT_DIR" ]]; then
    write_reports "${OUTPUT_DIR%/}/cis-${AUDITED_HOST}-${LEVEL}-$(date -u -d "$STARTED_UTC" +%Y%m%dT%H%M%SZ 2>/dev/null || date -u +%Y%m%dT%H%M%SZ)" "$SUMMARY"
fi

# --- End ---
EXIT_CODE=0
if [[ "$FAIL_ON" == "FailOrError" && "$COUNT_ERROR" -gt 0 ]]; then EXIT_CODE=2
elif [[ "$FAIL_ON" != "None" && "$COUNT_FAIL" -gt 0 ]]; then EXIT_CODE=1; fi
Write-Log "Script completed (exit $EXIT_CODE)."
exit "$EXIT_CODE"
