#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# .SYNOPSIS
#     Read-only audit of Linux service accounts: login shells, passwords, sudo grants, systemd identities, credstore.
#
# .DESCRIPTION
#     Script Name: FUNC_BASH_AUDIT_SERVICE_ACCOUNT
#     Reads local account and service configuration and prints one NDJSON finding per issue on stdout
#     (GOLDEN_STANDARDS 4.7). Same result schema as FUNC_PS_AUDIT_SERVICE_ACCOUNT.ps1.
#
#       SA-UID0-DUPLICATE        an account other than root has UID 0
#       SA-SYSTEM-SHELL          system-range account (UID < UID_MIN, or 65534) with a real login shell
#       SA-EMPTY-PASSWORD        any account with an empty password field in shadow (logs in without a password)
#       SA-SYSTEM-PASSWORD       system-range account with a usable password hash in shadow
#       SA-SUDO-NOPASSWD         sudoers rule with NOPASSWD or !authenticate (high when it grants ALL)
#       SA-SUDO-ALL              sudoers rule that grants every command (ALL), other than root
#       SA-UNIT-ROOT             systemd service without User= (runs as root); low when added under /etc
#       SA-UNIT-USER             systemd service with User= or DynamicUser= (inventory)
#       SA-UNIT-USER-SHELL       service account used by a unit that also has a real login shell
#       SA-CREDSTORE-READABLE    world-readable file in a systemd credential store (/etc|/run|/usr/lib credstore*)
#       SA-COLLECTION            a source could not be read, e.g. shadow without root (NeedsReview)
#
#     Nothing is changed. --root points at another file tree (a mounted image or a test fixture).
#     Requires Bash 4+ (associative arrays) and GNU find/stat.
#
# .PARAMETER --env
#     'Test' or 'Prod'. Defaults to 'Test'. The audit is read-only in both; 'Prod' asks for confirmation.
#
# .PARAMETER --whatif
#     Dry run: lists the sources that would be read and reads none of them.
#
# .PARAMETER --root DIR
#     File tree to audit instead of / (offline image or fixture). Default /.
#
# .PARAMETER --uid-min N
#     First regular-user UID. Default: UID_MIN from <root>/etc/login.defs, else 1000.
#
# .PARAMETER --log-dir DIR
#     Directory for ScriptLog.log and the run-log NDJSON. Default Logs/ beside the script.
#
# .PARAMETER --force
#     Skip the Prod confirmation (approved unattended runners only).
#
# .EXAMPLE
#     sudo ./FUNC_BASH_AUDIT_SERVICE_ACCOUNT.sh --whatif
#
# .EXAMPLE
#     sudo ./FUNC_BASH_AUDIT_SERVICE_ACCOUNT.sh | jq -c 'select(.result != "Info") | {check, severity, account, message}'
#
# .EXAMPLE
#     ./FUNC_BASH_AUDIT_SERVICE_ACCOUNT.sh --root /mnt/image --uid-min 500 > findings.ndjson
#
# .OUTPUTS
#     NDJSON findings on stdout; logs to stderr, <log-dir>/ScriptLog.log and <log-dir>/<ScriptName>.ndjson.
#
# .NOTES
#     Purpose: Inventory service identities and flag the settings attackers abuse after a foothold.
#     Security Context: system accounts with shells or passwords and broad sudo grants are valid-account and
#         privilege-escalation paths (T1078.003, T1548.003); readable credential files leak service secrets (T1552.001).
#     Security Domain: Identity
#     Author: RJGProjectz
#     Version: 1.0
#     Created: 2026-10-18T23:00:00Z
#     Last Modified: 2026-10-18T23:00:00Z
#     KB Article: [Service account audit](../../docs/tasks/assurance/service-account-audit.md)
#     Source Repo: shadow(5), login.defs(5), sudoers(5), systemd.exec(5), systemd.unit(5)
# -----------------------------------------------------------------------------
set -euo pipefail

# --- Configuration & Defaults ---
readonly SCRIPT_NAME="FUNC_BASH_AUDIT_SERVICE_ACCOUNT"
readonly SCRIPT_VERSION="1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
TARGET_ENVIRONMENT="Test"
WHAT_IF=false
FORCE=false
AUDIT_ROOT="/"
UID_MIN_OVERRIDE=""
LOG_DIR="${SCRIPT_DIR}/Logs"
EXECUTION_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || date +%s%N)"
readonly EXECUTION_ID

# Shells that do not give an interactive login (sync/shutdown/halt are the classic special accounts).
readonly NOLOGIN_SHELLS=" /usr/sbin/nologin /sbin/nologin /bin/false /usr/bin/false /bin/sync /usr/bin/sync /sbin/shutdown /usr/sbin/shutdown /sbin/halt /usr/sbin/halt "
# systemd unit search path, lowest precedence first; a same-named file later in the list replaces an earlier one.
readonly UNIT_DIRS=(usr/lib/systemd/system lib/systemd/system run/systemd/system etc/systemd/system)
# systemd.exec(5): LoadCredential= / LoadCredentialEncrypted= search paths for the system manager.
readonly CREDSTORE_DIRS=(etc/credstore etc/credstore.encrypted run/credstore run/credstore.encrypted usr/lib/credstore usr/lib/credstore.encrypted)

usage() {
    printf 'Usage: %s [--env Test|Prod] [--whatif] [--root DIR] [--uid-min N] [--log-dir DIR] [--force] [-h|--help]\n' "$(basename "$0")"
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
        "$timestamp" "$(json_escape "$(collector_host)")" "$SCRIPT_NAME" "$SCRIPT_VERSION" "$EXECUTION_ID" \
        "$TARGET_ENVIRONMENT" "$level" "$(json_escape "$message")" >> "${LOG_DIR}/${SCRIPT_NAME}.ndjson"
}

collector_host() {
    hostname 2>/dev/null || uname -n
}

# Host named in findings: the audited tree's hostname when --root is used, else this machine.
audited_host() {
    if [[ "$AUDIT_ROOT" != "/" && -r "$(root_path etc/hostname)" ]]; then
        head -n 1 "$(root_path etc/hostname)"
    else
        collector_host
    fi
}

root_path() {
    local relative="$1"
    printf '%s/%s' "${AUDIT_ROOT%/}" "$relative"
}

# Emit one finding. Arguments: check severity result target account message [key=value ...] (details, strings).
Write-Finding() {
    local check="$1" severity="$2" result="$3" target="$4" account="$5" message="$6"
    shift 6
    local level="WARN"
    [[ "$result" == "Info" ]] && level="INFO"
    local details="" pair key value
    for pair in "$@"; do
        key="${pair%%=*}"
        value="${pair#*=}"
        details+="${details:+,}\"$(json_escape "$key")\":\"$(json_escape "$value")\""
    done
    printf '{"timestamp":"%s","host":"%s","tool":"%s","version":"%s","execution_id":"%s","environment":"%s","level":"%s","action":"audit","check":"%s","severity":"%s","result":"%s","target":"%s","account":"%s","message":"%s","details":{%s}}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(json_escape "$AUDITED_HOST")" "$SCRIPT_NAME" "$SCRIPT_VERSION" "$EXECUTION_ID" \
        "$TARGET_ENVIRONMENT" "$level" "$check" "$severity" "$result" "$(json_escape "$target")" \
        "$(json_escape "$account")" "$(json_escape "$message")" "$details"
    FINDING_COUNT=$((FINDING_COUNT + 1))
    [[ "$result" != "Info" ]] && ISSUE_COUNT=$((ISSUE_COUNT + 1))
    return 0
}

is_real_shell() {
    local shell="$1"
    [[ -n "$shell" && "$NOLOGIN_SHELLS" != *" ${shell} "* ]]
}

is_system_uid() {
    local uid="$1"
    [[ "$uid" -gt 0 && ( "$uid" -lt "$UID_MIN" || "$uid" -eq 65534 ) ]]
}

# --- Checks ---
declare -A ACCOUNT_UID=()
declare -A ACCOUNT_SHELL=()

Get-PasswdAccount() {
    local passwd_file
    passwd_file="$(root_path etc/passwd)"
    if [[ ! -r "$passwd_file" ]]; then
        Write-Finding "SA-COLLECTION" "medium" "NeedsReview" "/etc/passwd" "" "Cannot read /etc/passwd; account checks skipped."
        return 0
    fi
    local name uid shell
    while IFS=: read -r name _ uid _ _ _ shell || [[ -n "$name" ]]; do
        [[ -z "$name" || "$name" == \#* || ! "$uid" =~ ^[0-9]+$ ]] && continue
        ACCOUNT_UID["$name"]="$uid"
        ACCOUNT_SHELL["$name"]="$shell"
        if [[ "$uid" -eq 0 && "$name" != "root" ]]; then
            Write-Finding "SA-UID0-DUPLICATE" "high" "Finding" "/etc/passwd" "$name" \
                "Account '$name' has UID 0: it is root under another name." "uid=$uid" "shell=$shell"
        elif is_system_uid "$uid" && is_real_shell "$shell"; then
            Write-Finding "SA-SYSTEM-SHELL" "medium" "Finding" "/etc/passwd" "$name" \
                "System account '$name' (UID $uid) has login shell $shell; set it to /usr/sbin/nologin." "uid=$uid" "shell=$shell"
        fi
    done < "$passwd_file"
}

Get-ShadowPassword() {
    local shadow_file
    shadow_file="$(root_path etc/shadow)"
    if [[ ! -r "$shadow_file" ]]; then
        Write-Finding "SA-COLLECTION" "medium" "NeedsReview" "/etc/shadow" "" "Cannot read /etc/shadow (run as root); password checks skipped."
        return 0
    fi
    local name hash uid
    while IFS=: read -r name hash _ || [[ -n "$name" ]]; do
        [[ -z "$name" || "$name" == \#* ]] && continue
        uid="${ACCOUNT_UID[$name]:-}"
        # shadow(5): empty = no password needed; leading '!' = locked; '*' or '!!' = no usable password.
        if [[ -z "$hash" ]]; then
            Write-Finding "SA-EMPTY-PASSWORD" "high" "Finding" "/etc/shadow" "$name" \
                "Account '$name' has an empty password field: it may log in without a password." "uid=$uid"
        elif [[ -n "$uid" ]] && is_system_uid "$uid" && [[ "$hash" != \!* && "$hash" != \** ]]; then
            local severity="medium"
            is_real_shell "${ACCOUNT_SHELL[$name]:-}" && severity="high"
            Write-Finding "SA-SYSTEM-PASSWORD" "$severity" "Finding" "/etc/shadow" "$name" \
                "System account '$name' (UID $uid) has a usable password; lock it (passwd -l) unless a person really logs in with it." \
                "uid=$uid" "shell=${ACCOUNT_SHELL[$name]:-}"
        fi
    done < "$shadow_file"
}

Get-SudoersFile() {
    local main_file include_dir candidate base
    main_file="$(root_path etc/sudoers)"
    include_dir="$(root_path etc/sudoers.d)"
    [[ -e "$main_file" ]] && printf '%s\n' "$main_file"
    [[ -d "$include_dir" ]] || return 0
    for candidate in "$include_dir"/*; do
        [[ -f "$candidate" ]] || continue
        base="$(basename "$candidate")"
        # sudoers(5): @includedir skips file names that end in '~' or contain a '.'.
        [[ "$base" == *"~" || "$base" == *.* ]] && continue
        printf '%s\n' "$candidate"
    done
}

Test-SudoRule() {
    local file="$1" line_number="$2" rule="$3"
    local display_file="${file#"${AUDIT_ROOT%/}"}"
    local principal="${rule%%[[:space:]]*}"
    local target="${display_file}:${line_number}"
    # A rule grants every command when its (last) command list is ALL, optionally after a runas list and tags.
    local grants_all=false
    if [[ "$rule" =~ =[[:space:]]*(\([^\)]*\)[[:space:]]*)?([A-Z_]+:[[:space:]]*)*ALL[[:space:]]*$ ]]; then
        grants_all=true
    fi

    if [[ "$rule" == *NOPASSWD* || "$rule" == *'!authenticate'* ]]; then
        local severity="medium"
        [[ "$grants_all" == "true" ]] && severity="high"
        Write-Finding "SA-SUDO-NOPASSWD" "$severity" "Finding" "$target" "$principal" \
            "sudo rule for '$principal' runs commands without a password: $rule" "rule=$rule" "grants_all=$grants_all"
    elif [[ "$grants_all" == "true" && "$principal" != "root" && "$principal" != "Defaults"* ]]; then
        local severity="medium"
        # The distribution admin groups are expected to have ALL; still listed so the membership gets reviewed.
        [[ "$principal" == "%sudo" || "$principal" == "%wheel" || "$principal" == "%admin" ]] && severity="low"
        Write-Finding "SA-SUDO-ALL" "$severity" "Finding" "$target" "$principal" \
            "sudo rule gives '$principal' every command as root: $rule" "rule=$rule"
    fi
}

Get-SudoersGrant() {
    local sudo_file
    local -a sudo_files=()
    mapfile -t sudo_files < <(Get-SudoersFile)
    for sudo_file in "${sudo_files[@]}"; do
        if [[ ! -r "$sudo_file" ]]; then
            Write-Finding "SA-COLLECTION" "medium" "NeedsReview" "${sudo_file#"${AUDIT_ROOT%/}"}" "" "Cannot read sudoers file (run as root)."
            continue
        fi
        local line logical="" line_number=0 start_line=0
        while IFS= read -r line || [[ -n "$line" ]]; do
            line_number=$((line_number + 1))
            [[ -z "$logical" ]] && start_line="$line_number"
            # sudoers(5): a backslash as the last character continues the line.
            if [[ "$line" == *\\ ]]; then
                logical+="${line%\\} "
                continue
            fi
            logical+="$line"
            local rule="${logical#"${logical%%[![:space:]]*}"}"
            logical=""
            # Comments and #include/#includedir directives start with '#'; aliases and @include are not grants.
            [[ -z "$rule" || "$rule" == \#* || "$rule" == @* ]] && continue
            [[ "$rule" =~ ^(User|Runas|Host|Cmnd|Cmd)_Alias[[:space:]] ]] && continue
            if [[ "$rule" == Defaults* ]]; then
                [[ "$rule" == *'!authenticate'* ]] && Test-SudoRule "$sudo_file" "$start_line" "$rule"
                continue
            fi
            Test-SudoRule "$sudo_file" "$start_line" "$rule"
        done < "$sudo_file"
    done
}

# Prints the effective User= and DynamicUser= of a unit file plus its drop-ins: "<user>|<dynamic>".
Get-UnitIdentity() {
    local unit_file="$1" unit_name="$2"
    local user="" dynamic="no" config_file line section="" key value
    local -a config_files=("$unit_file")
    local dir dropin
    for dir in "${UNIT_DIRS[@]}"; do
        for dropin in "$(root_path "$dir")/${unit_name}.d"/*.conf; do
            [[ -f "$dropin" ]] && config_files+=("$dropin")
        done
    done
    for config_file in "${config_files[@]}"; do
        section=""
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line#"${line%%[![:space:]]*}"}"
            [[ -z "$line" || "$line" == \#* || "$line" == \;* ]] && continue
            if [[ "$line" =~ ^\[(.+)\]$ ]]; then section="${BASH_REMATCH[1]}"; continue; fi
            [[ "$section" == "Service" ]] || continue
            key="${line%%=*}"
            value="${line#*=}"
            key="${key%"${key##*[![:space:]]}"}"
            value="${value#"${value%%[![:space:]]*}"}"
            case "$key" in
                User) user="$value" ;;
                DynamicUser) dynamic="$value" ;;
            esac
        done < "$config_file"
    done
    printf '%s|%s\n' "$user" "$dynamic"
}

Get-SystemdUnitUser() {
    declare -A unit_source=()
    local dir unit_file unit_name
    for dir in "${UNIT_DIRS[@]}"; do
        for unit_file in "$(root_path "$dir")"/*.service; do
            [[ -e "$unit_file" ]] || continue
            unit_name="$(basename "$unit_file")"
            # A unit linked to /dev/null is masked: it cannot run.
            if [[ -L "$unit_file" && "$(readlink "$unit_file")" == "/dev/null" ]]; then
                unset 'unit_source[$unit_name]'
                continue
            fi
            unit_source["$unit_name"]="$unit_file"
        done
    done

    local identity user dynamic display_path
    for unit_name in "${!unit_source[@]}"; do
        unit_file="${unit_source[$unit_name]}"
        display_path="${unit_file#"${AUDIT_ROOT%/}"}"
        identity="$(Get-UnitIdentity "$unit_file" "$unit_name")"
        user="${identity%%|*}"
        dynamic="${identity#*|}"
        case "${dynamic,,}" in yes|true|on|1) dynamic="yes" ;; *) dynamic="no" ;; esac

        if [[ "$dynamic" == "yes" ]]; then
            Write-Finding "SA-UNIT-USER" "info" "Info" "$unit_name" "${user:-dynamic}" \
                "Unit $unit_name runs as a transient DynamicUser account." "unit_file=$display_path" "dynamic_user=yes"
        elif [[ -z "$user" || "$user" == "root" || "$user" == "0" ]]; then
            # Units an admin added under /etc deserve a look; vendor units running as root are inventory.
            if [[ "$display_path" == /etc/* ]]; then
                Write-Finding "SA-UNIT-ROOT" "low" "Finding" "$unit_name" "root" \
                    "Locally added unit $unit_name runs as root; give it its own account with User=." "unit_file=$display_path"
            else
                Write-Finding "SA-UNIT-ROOT" "info" "Info" "$unit_name" "root" \
                    "Unit $unit_name runs as root." "unit_file=$display_path"
            fi
        else
            Write-Finding "SA-UNIT-USER" "info" "Info" "$unit_name" "$user" \
                "Unit $unit_name runs as '$user'." "unit_file=$display_path" "dynamic_user=no"
            if is_real_shell "${ACCOUNT_SHELL[$user]:-}"; then
                Write-Finding "SA-UNIT-USER-SHELL" "medium" "Finding" "$unit_name" "$user" \
                    "Service account '$user' (unit $unit_name) has login shell ${ACCOUNT_SHELL[$user]}; set it to /usr/sbin/nologin." \
                    "shell=${ACCOUNT_SHELL[$user]}" "unit_file=$display_path"
            fi
        fi
    done
}

Get-CredstoreExposure() {
    local dir store_path credential_file mode severity
    for dir in "${CREDSTORE_DIRS[@]}"; do
        store_path="$(root_path "$dir")"
        [[ -d "$store_path" ]] || continue
        # Encrypted credentials need the host key/TPM to decrypt, so exposure is medium rather than high.
        severity="high"
        [[ "$dir" == *.encrypted ]] && severity="medium"
        while IFS= read -r -d '' credential_file; do
            mode="$(stat -c '%a' "$credential_file" 2>/dev/null || printf 'unknown')"
            Write-Finding "SA-CREDSTORE-READABLE" "$severity" "Finding" "/${dir}" "" \
                "Credential file ${credential_file#"${AUDIT_ROOT%/}"} is world-readable (mode $mode); set it to 0400/0600 root." \
                "file=${credential_file#"${AUDIT_ROOT%/}"}" "mode=$mode"
        done < <(find "$store_path" -type f -perm -0004 -print0 2>/dev/null)
    done
}

# --- Argument Parsing ---
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --env)     TARGET_ENVIRONMENT="${2:-}"; shift ;;
        --whatif|--dry-run) WHAT_IF=true ;;
        --root)    AUDIT_ROOT="${2:-}"; shift ;;
        --uid-min) UID_MIN_OVERRIDE="${2:-}"; shift ;;
        --log-dir) LOG_DIR="${2:-}"; shift ;;
        --force)   FORCE=true ;;
        -h|--help) usage; exit 0 ;;
        *)         Write-Log "Unknown parameter: $1 (use -h for usage)" "WARN"; exit 2 ;;
    esac
    shift
done

if [[ "$TARGET_ENVIRONMENT" != "Test" && "$TARGET_ENVIRONMENT" != "Prod" ]]; then
    Write-Log "--env must be Test or Prod (use -h for usage)." "ERROR"
    exit 2
fi
if [[ -z "$AUDIT_ROOT" || ! -d "$AUDIT_ROOT" ]]; then
    Write-Log "--root must be an existing directory (use -h for usage)." "ERROR"
    exit 2
fi
if [[ -n "$UID_MIN_OVERRIDE" && ! "$UID_MIN_OVERRIDE" =~ ^[0-9]+$ ]]; then
    Write-Log "--uid-min must be a number (use -h for usage)." "ERROR"
    exit 2
fi

# --- Begin ---
Write-Log "Starting ${SCRIPT_NAME} in [${TARGET_ENVIRONMENT}] mode (read-only, root ${AUDIT_ROOT})."

if [[ "$TARGET_ENVIRONMENT" == "Prod" && "$WHAT_IF" == "false" && "$FORCE" == "false" ]]; then
    read -r -p "PRODUCTION ENVIRONMENT: run the read-only service account audit? (y/N) " confirm || confirm=""
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        Write-Log "Operation cancelled by user." "WARN"
        exit 1
    fi
fi

main() {
    if [[ "$WHAT_IF" == "true" ]]; then
        Write-Log "[WHATIF] Would read: /etc/login.defs, /etc/passwd, /etc/shadow, /etc/sudoers, /etc/sudoers.d/*, ${UNIT_DIRS[*]/#//} (*.service + drop-ins), ${CREDSTORE_DIRS[*]/#//} under ${AUDIT_ROOT}."
        return 0
    fi

    if [[ -n "$UID_MIN_OVERRIDE" ]]; then
        UID_MIN="$UID_MIN_OVERRIDE"
    else
        UID_MIN="$(awk '$1 == "UID_MIN" && $2 ~ /^[0-9]+$/ { print $2; exit }' "$(root_path etc/login.defs)" 2>/dev/null || true)"
        UID_MIN="${UID_MIN:-1000}"
    fi
    [[ "$(id -u)" -ne 0 && "$AUDIT_ROOT" == "/" ]] && Write-Log "Not running as root: shadow and sudoers.d may be unreadable (reported as NeedsReview)." "WARN"

    Get-PasswdAccount
    Get-ShadowPassword
    Get-SudoersGrant
    Get-SystemdUnitUser
    Get-CredstoreExposure
    Write-Log "Audit complete: ${FINDING_COUNT} events, ${ISSUE_COUNT} findings or review items (UID_MIN ${UID_MIN})."
}

FINDING_COUNT=0
ISSUE_COUNT=0
UID_MIN=1000
AUDITED_HOST="$(audited_host)"
main

# --- End ---
Write-Log "Script completed."
