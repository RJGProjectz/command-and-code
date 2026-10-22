#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# .SYNOPSIS
#     Passive OSINT enumeration for one or many web targets.
#
# .DESCRIPTION
#     Gathers everything that can be learned about a domain WITHOUT sending any
#     traffic to the target itself. Every lookup hits a third-party / public
#     data source only:
#       - DNS records            (A/AAAA/MX/NS/TXT/SOA/CAA) via a public resolver
#       - WHOIS / RDAP           registration, registrar, dates, nameservers
#       - Certificate Transparency (crt.sh)  -> subdomains + certificate history
#       - Wayback Machine (CDX)  -> historical URLs and paths
#       - Shodan InternetDB      -> open ports / CPEs / known CVEs per resolved IP
#     The target host is never contacted directly: no homepage GET, no robots.txt,
#     no port scan. This keeps the run strictly passive.
#
# .PARAMETER TARGET
#     A domain, host, or URL (scheme/path are stripped). Repeatable.
#
# .PARAMETER -f, --file FILE
#     File with one target per line ('#' comments and blank lines ignored).
#
# .PARAMETER -o, --out DIR
#     Write raw evidence + reports under DIR (default: ./webosint_<date>).
#
# .PARAMETER --format text|json|both
#     stdout summary format (default: text). NDJSON is always written to the
#     output directory as results.ndjson.
#
# .PARAMETER --resolver IP
#     Public DNS resolver to query (default: 1.1.1.1).
#
# .PARAMETER --no-ct | --no-wayback | --no-shodan | --no-whois
#     Skip individual passive sources.
#
# .EXAMPLE
#     ./FUNC_BASH_GET_WEB_OSINT.sh example.com
#     ./FUNC_BASH_GET_WEB_OSINT.sh -f targets.txt -o ./recon --format both
#
# .NOTES
#     Author: RJGProjectz
#     Created: 2026-10-21T00:00:00Z
#     Last Modified: 2026-10-21T00:00:00Z
#     security_domain: Application
#     AUTHORIZED USE ONLY. Passive reconnaissance can still be restricted by law
#     and by engagement scope. Only enumerate targets you own or are authorized
#     to assess, and respect each data provider's terms and rate limits.
# -----------------------------------------------------------------------------

set -euo pipefail

# --- Defaults ---------------------------------------------------------------
OUTPUT_DIR=""
FORMAT="text"
RESOLVER="1.1.1.1"
DO_CT=true
DO_WAYBACK=true
DO_SHODAN=true
DO_WHOIS=true
DO_DNS=true
CURL_TIMEOUT=25
UA="Mozilla/5.0 (compatible; passive-osint/1.0)"
TARGETS=()

RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; NC='\033[0m'

log()  { printf '%b[%s] %s%b\n' "$CYAN"  "$(date -Iseconds)" "$*" "$NC" >&2; }
warn() { printf '%b[%s] WARN %s%b\n' "$YELLOW" "$(date -Iseconds)" "$*" "$NC" >&2; }
err()  { printf '%b[%s] ERROR %s%b\n' "$RED" "$(date -Iseconds)" "$*" "$NC" >&2; }

usage() { sed -n '2,46p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# --- Argument parsing -------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--file)     [[ -r "${2:-}" ]] || { err "cannot read file: ${2:-}"; exit 1; }
                       while IFS= read -r line; do
                           line="${line%%#*}"; line="$(echo "$line" | xargs || true)"
                           [[ -n "$line" ]] && TARGETS+=("$line")
                       done < "$2"; shift 2 ;;
        -o|--out)      OUTPUT_DIR="${2:-}"; shift 2 ;;
        --format)      FORMAT="${2:-text}"; shift 2 ;;
        --resolver)    RESOLVER="${2:-1.1.1.1}"; shift 2 ;;
        --no-ct)       DO_CT=false; shift ;;
        --no-wayback)  DO_WAYBACK=false; shift ;;
        --no-shodan)   DO_SHODAN=false; shift ;;
        --no-whois)    DO_WHOIS=false; shift ;;
        -h|--help)     usage 0 ;;
        -*)            err "unknown option: $1"; usage 1 ;;
        *)             TARGETS+=("$1"); shift ;;
    esac
done

if (( ${#TARGETS[@]} == 0 )); then err "no targets given"; usage 1; fi

case "$FORMAT" in text|json|both) ;; *) err "invalid --format: $FORMAT"; exit 1 ;; esac

# --- Dependency checks ------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
for bin in curl jq; do
    have "$bin" || { err "required dependency missing: $bin"; exit 1; }
done
have dig   || warn "dig not found (dnsutils) — DNS section limited"
have whois || warn "whois not found — WHOIS falls back to RDAP over HTTP"

OUTPUT_DIR="${OUTPUT_DIR:-./webosint_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTPUT_DIR"
NDJSON="$OUTPUT_DIR/results.ndjson"
: > "$NDJSON"
log "output directory: $OUTPUT_DIR"

# Safe third-party GET: fixed timeout, generic UA, never aimed at the target host.
fetch() { curl -fsS --max-time "$CURL_TIMEOUT" -A "$UA" "$@" 2>/dev/null || true; }

# normalize a URL/host into a bare domain
to_domain() {
    local t="$1"
    t="${t#http://}"; t="${t#https://}"
    t="${t%%/*}"; t="${t%%\?*}"; t="${t##*@}"; t="${t%%:*}"
    echo "$t" | tr '[:upper:]' '[:lower:]'
}

# --- Passive collectors -----------------------------------------------------
dns_records() {
    local domain="$1" out="$2" rr
    have dig || { echo "{}"; return; }
    local json="{}"
    for rr in A AAAA MX NS TXT SOA CAA; do
        local vals
        vals="$(dig +short "@$RESOLVER" "$domain" "$rr" 2>/dev/null | sed '/^$/d')"
        printf '%s\n' "$vals" > "$out/dns_${rr}.txt"
        json="$(jq -cn --arg rr "$rr" --arg v "$vals" \
                '{($rr): ($v | split("\n") | map(select(length>0)))}' | jq -cs --argjson base "$json" '$base + .[0]')"
    done
    echo "$json"
}

resolve_ips() {
    local domain="$1"
    if have dig; then
        dig +short "@$RESOLVER" "$domain" A 2>/dev/null | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort -u
    fi
}

whois_rdap() {
    local domain="$1" out="$2"
    # RDAP is structured and rate-friendly; fall back to classic whois text.
    local rdap
    rdap="$(fetch "https://rdap.org/domain/$domain")"
    if [[ -n "$rdap" ]] && echo "$rdap" | jq -e . >/dev/null 2>&1; then
        echo "$rdap" > "$out/rdap.json"
        echo "$rdap" | jq -c '{
            handle: .handle,
            status: (.status // []),
            registrar: ([.entities[]? | select(.roles[]? == "registrar") | .vcardArray[1][]? | select(.[0]=="fn") | .[3]][0] // null),
            events: ([.events[]? | {action: .eventAction, date: .eventDate}]),
            nameservers: ([.nameservers[]?.ldhName])
        }'
    elif have whois; then
        whois "$domain" > "$out/whois.txt" 2>/dev/null || true
        jq -cn --arg src "whois-text" '{source: $src, file: "whois.txt"}'
    else
        echo "{}"
    fi
}

ct_subdomains() {
    local domain="$1" out="$2"
    local raw
    raw="$(fetch "https://crt.sh/?q=%25.$domain&output=json")"
    if [[ -n "$raw" ]] && echo "$raw" | jq -e . >/dev/null 2>&1; then
        echo "$raw" | jq -r '.[].name_value' 2>/dev/null \
            | sed 's/\*\.//g' | tr '[:upper:]' '[:lower:]' | sort -u > "$out/subdomains.txt"
    else
        : > "$out/subdomains.txt"
    fi
    wc -l < "$out/subdomains.txt" | tr -d ' '
}

wayback_urls() {
    local domain="$1" out="$2"
    fetch "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey&limit=5000" \
        | sort -u > "$out/wayback_urls.txt"
    wc -l < "$out/wayback_urls.txt" | tr -d ' '
}

shodan_internetdb() {
    local out="$1"; shift
    local ip merged="[]"
    for ip in "$@"; do
        local data
        data="$(fetch "https://internetdb.shodan.io/$ip")"
        if [[ -n "$data" ]] && echo "$data" | jq -e . >/dev/null 2>&1; then
            echo "$data" >> "$out/shodan_internetdb.ndjson"
            merged="$(jq -cs --argjson m "$merged" '$m + [.[0]]' <<<"$data")"
        fi
    done
    echo "$merged"
}

# --- Per-target workflow ----------------------------------------------------
process_target() {
    local raw_target="$1" domain tdir
    domain="$(to_domain "$raw_target")"
    [[ -n "$domain" ]] || { warn "skipping empty target: '$raw_target'"; return; }
    tdir="$OUTPUT_DIR/$domain"; mkdir -p "$tdir"
    log "==> $domain"

    local ips_list dns_json="{}" whois_json="{}" ct_count=0 wb_count=0 shodan_json="[]"
    ips_list="$(resolve_ips "$domain" || true)"
    printf '%s\n' "$ips_list" | sed '/^$/d' > "$tdir/ips.txt"

    $DO_DNS     && dns_json="$(dns_records "$domain" "$tdir")"
    $DO_WHOIS   && whois_json="$(whois_rdap "$domain" "$tdir")"
    $DO_CT      && ct_count="$(ct_subdomains "$domain" "$tdir")"
    $DO_WAYBACK && wb_count="$(wayback_urls "$domain" "$tdir")"

    if $DO_SHODAN && [[ -n "$ips_list" ]]; then
        # shellcheck disable=SC2086
        shodan_json="$(shodan_internetdb "$tdir" $ips_list)"
    fi

    # Assemble the structured record
    jq -cn \
        --arg domain "$domain" \
        --arg scanned "$(date -Iseconds)" \
        --argjson ips "$(jq -Rsc 'split("\n") | map(select(length>0))' "$tdir/ips.txt")" \
        --argjson dns "${dns_json:-{}}" \
        --argjson whois "${whois_json:-{}}" \
        --argjson subdomain_count "${ct_count:-0}" \
        --argjson wayback_count "${wb_count:-0}" \
        --argjson shodan "${shodan_json:-[]}" \
        '{domain:$domain, scanned:$scanned, ips:$ips, dns:$dns, registration:$whois,
          subdomain_count:$subdomain_count, wayback_count:$wayback_count, shodan:$shodan}' \
        >> "$NDJSON"

    if [[ "$FORMAT" == "text" || "$FORMAT" == "both" ]]; then
        printf '%b--- %s ---%b\n' "$GREEN" "$domain" "$NC"
        printf '  IPs            : %s\n' "$(paste -sd', ' "$tdir/ips.txt" 2>/dev/null || echo '-')"
        printf '  NS             : %s\n' "$(paste -sd', ' "$tdir/dns_NS.txt" 2>/dev/null || echo '-')"
        printf '  MX             : %s\n' "$(paste -sd', ' "$tdir/dns_MX.txt" 2>/dev/null || echo '-')"
        printf '  Subdomains (CT): %s\n' "$ct_count"
        printf '  Wayback URLs   : %s\n' "$wb_count"
        if [[ -f "$tdir/shodan_internetdb.ndjson" ]]; then
            printf '  Shodan ports   : %s\n' "$(jq -r '.ports | join(",")' "$tdir/shodan_internetdb.ndjson" 2>/dev/null | paste -sd'; ' || echo '-')"
            printf '  Shodan CVEs    : %s\n' "$(jq -r '(.vulns // []) | join(",")' "$tdir/shodan_internetdb.ndjson" 2>/dev/null | sed '/^$/d' | paste -sd'; ' || echo '-')"
        fi
        echo
    fi
}

# --- Main -------------------------------------------------------------------
log "passive web OSINT — ${#TARGETS[@]} target(s); sources never touch the target host"
for t in "${TARGETS[@]}"; do
    process_target "$t"
done

if [[ "$FORMAT" == "json" || "$FORMAT" == "both" ]]; then
    jq -s '.' "$NDJSON"
fi

log "done — structured results: $NDJSON"
