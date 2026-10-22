#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# .SYNOPSIS
#     Scope- and rate-limit-aware web API surface discovery.
#
# .DESCRIPTION
#     Maps the surface of ONE authorized HTTP API with a hard request-rate cap
#     and a strict in-scope guard. It performs enumeration only — read-only GET
#     probes plus a single standard GraphQL introspection query. It does NOT:
#     brute-force authorization, enumerate object IDs, mutate state, or send any
#     payload beyond introspection. Those steps belong in a scoped, authorized
#     exploitation phase, not here.
#
#       - Spec discovery     openapi/swagger/api-docs at the usual locations
#       - Root discovery     /api, /api/v1, /api/v2, /graphql, ...
#       - Endpoint listing   parsed from an exposed OpenAPI/Swagger spec
#       - GraphQL schema     one introspection query (records enabled/disabled)
#       - Auth + posture      WWW-Authenticate, CORS, and rate-limit headers
#
#     Every probe is throttled to --rate requests/second and every URL is
#     checked against the target host before it is sent (off-scope => skipped).
#
# .PARAMETER TARGET
#     The in-scope API base URL, e.g. https://api.example.com (required).
#
# .PARAMETER -o, --out DIR
#     Evidence + NDJSON directory (default: ./apisurface_<date>).
#
# .PARAMETER --rate N
#     Max requests per second (default: 2). The script sleeps 1/N between calls.
#
# .PARAMETER --token TOKEN
#     Optional bearer token (engagement-issued) sent as Authorization: Bearer.
#
# .PARAMETER --header 'H: V'
#     Extra header, repeatable (e.g. an API key header).
#
# .PARAMETER --no-graphql
#     Skip the GraphQL endpoint probe and introspection query.
#
# .PARAMETER --format text|json|both
#     stdout summary (default: text). NDJSON is always written to results.ndjson.
#
# .EXAMPLE
#     ./FUNC_BASH_GET_API_SURFACE.sh https://api.example.com
#     ./FUNC_BASH_GET_API_SURFACE.sh https://api.example.com --rate 1 --token "$T" --format both
#
# .NOTES
#     Author: RJGProjectz
#     Created: 2026-10-21T00:00:00Z
#     Last Modified: 2026-10-21T00:00:00Z
#     security_domain: Application
#     AUTHORIZED USE ONLY. This contacts the target directly. Run it only against
#     an API you own or are explicitly authorized to test, inside the agreed
#     scope, rate and time window, and keep a log of what you ran.
# -----------------------------------------------------------------------------

set -euo pipefail

# --- Defaults ---------------------------------------------------------------
OUTPUT_DIR=""
RATE=2
TOKEN=""
DO_GRAPHQL=true
FORMAT="text"
EXTRA_HEADERS=()
CURL_TIMEOUT=20
UA="Mozilla/5.0 (compatible; api-surface-recon/1.0)"
TARGET=""

RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; NC='\033[0m'
log()  { printf '%b[%s] %s%b\n' "$CYAN"   "$(date -Iseconds)" "$*" "$NC" >&2; }
warn() { printf '%b[%s] WARN %s%b\n' "$YELLOW" "$(date -Iseconds)" "$*" "$NC" >&2; }
err()  { printf '%b[%s] ERROR %s%b\n' "$RED"  "$(date -Iseconds)" "$*" "$NC" >&2; }

usage() { sed -n '2,52p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# --- Argument parsing -------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--out)     OUTPUT_DIR="${2:-}"; shift 2 ;;
        --rate)       RATE="${2:-2}"; shift 2 ;;
        --token)      TOKEN="${2:-}"; shift 2 ;;
        --header)     EXTRA_HEADERS+=("${2:-}"); shift 2 ;;
        --no-graphql) DO_GRAPHQL=false; shift ;;
        --format)     FORMAT="${2:-text}"; shift 2 ;;
        -h|--help)    usage 0 ;;
        -*)           err "unknown option: $1"; usage 1 ;;
        *)            TARGET="$1"; shift ;;
    esac
done

[[ -n "$TARGET" ]] || { err "no target URL given"; usage 1; }
case "$FORMAT" in text|json|both) ;; *) err "invalid --format: $FORMAT"; exit 1 ;; esac
[[ "$RATE" =~ ^[0-9]+$ ]] && (( RATE >= 1 )) || { err "--rate must be a positive integer"; exit 1; }

# --- Dependencies -----------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
for bin in curl jq; do have "$bin" || { err "required dependency missing: $bin"; exit 1; }; done

# --- Scope guard ------------------------------------------------------------
# Derive scheme + host[:port] from TARGET; refuse any probe that leaves that origin.
TARGET="${TARGET%/}"
SCHEME="${TARGET%%://*}"; [[ "$SCHEME" == "$TARGET" ]] && { SCHEME="https"; TARGET="https://$TARGET"; }
rest="${TARGET#*://}"
SCOPE_HOST="${rest%%/*}"                       # host[:port]
BASE="$SCHEME://$SCOPE_HOST"
log "scope locked to origin: $BASE  (rate ${RATE}/s)"

in_scope() {
    # true only when the URL's origin equals the locked origin
    local u="$1" uh
    uh="${u#*://}"; uh="${uh%%/*}"
    [[ "$u" == "$SCHEME://"* && "$uh" == "$SCOPE_HOST" ]]
}

OUTPUT_DIR="${OUTPUT_DIR:-./apisurface_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTPUT_DIR"
NDJSON="$OUTPUT_DIR/results.ndjson"
: > "$NDJSON"
SLEEP="$(awk -v r="$RATE" 'BEGIN{printf "%.3f", 1.0/r}')"

# --- Rate-limited, in-scope probe ------------------------------------------
# Emits one NDJSON record per probe. Never follows redirects off-origin.
probe() {
    local path="$1" kind="${2:-rest}"
    local url="$BASE/$path"
    if ! in_scope "$url"; then warn "off-scope, skipped: $url"; return; fi

    local hdr=(-A "$UA" --max-time "$CURL_TIMEOUT")
    [[ -n "$TOKEN" ]] && hdr+=(-H "Authorization: Bearer $TOKEN")
    local h; for h in "${EXTRA_HEADERS[@]:-}"; do [[ -n "$h" ]] && hdr+=(-H "$h"); done

    # headers + status only (read-only GET); capture select posture headers
    local raw code ctype auth cors ratelimit
    raw="$(curl -sS -D - -o /dev/null -w $'\nHTTP_CODE:%{http_code}\n' "${hdr[@]}" "$url" 2>/dev/null || true)"
    code="$(sed -n 's/^HTTP_CODE:\([0-9]*\).*/\1/p' <<<"$raw" | tail -1)"; code="${code:-000}"
    ctype="$(grep -i '^content-type:'  <<<"$raw" | head -1 | cut -d: -f2- | xargs || true)"
    auth="$(grep -i  '^www-authenticate:' <<<"$raw" | head -1 | cut -d: -f2- | xargs || true)"
    cors="$(grep -i  '^access-control-allow-origin:' <<<"$raw" | head -1 | cut -d: -f2- | xargs || true)"
    ratelimit="$(grep -iE '^(x-ratelimit|ratelimit|retry-after)' <<<"$raw" | head -1 | xargs || true)"

    jq -cn --arg target "$BASE" --arg scanned "$(date -Iseconds)" --arg url "$url" \
       --arg path "/$path" --arg kind "$kind" --arg code "$code" --arg ctype "$ctype" \
       --arg auth "$auth" --arg cors "$cors" --arg ratelimit "$ratelimit" \
       '{target:$target, scanned:$scanned, kind:$kind, url:$url, path:$path,
         status:($code|tonumber), content_type:$ctype, www_authenticate:$auth,
         cors_allow_origin:$cors, rate_limit_header:$ratelimit}' >> "$NDJSON"

    printf '  %-4s %-6s /%s\n' "$code" "$kind" "$path"
    [[ "$FORMAT" != "json" ]] || true
    sleep "$SLEEP"
    echo "$code"
}

# --- Spec discovery ---------------------------------------------------------
SPEC_PATHS=(openapi.json openapi.yaml swagger.json swagger.yaml v3/api-docs
            api-docs swagger/v1/swagger.json .well-known/openapi)
ROOT_PATHS=(api api/v1 api/v2 api/latest rest graphql graphql/console playground)

log "== spec discovery =="
SPEC_HIT=""
for p in "${SPEC_PATHS[@]}"; do
    code="$(probe "$p" spec)"
    if [[ "$code" == "200" && -z "$SPEC_HIT" ]]; then SPEC_HIT="$p"; fi
done

log "== root discovery =="
for p in "${ROOT_PATHS[@]}"; do probe "$p" root >/dev/null; done

# --- Parse an exposed spec into endpoints -----------------------------------
ENDPOINT_COUNT=0
if [[ -n "$SPEC_HIT" ]] && [[ "$SPEC_HIT" == *.json || "$SPEC_HIT" == *api-docs* ]]; then
    log "== parsing spec: /$SPEC_HIT =="
    if curl -sS -A "$UA" --max-time "$CURL_TIMEOUT" "$BASE/$SPEC_HIT" -o "$OUTPUT_DIR/openapi.json" 2>/dev/null \
       && jq -e . "$OUTPUT_DIR/openapi.json" >/dev/null 2>&1; then
        jq -r '.paths // {} | to_entries[] | .key as $p | .value | keys[] | "\(.|ascii_upcase) \($p)"' \
            "$OUTPUT_DIR/openapi.json" 2>/dev/null | sort -u > "$OUTPUT_DIR/endpoints.txt" || true
        ENDPOINT_COUNT="$(wc -l < "$OUTPUT_DIR/endpoints.txt" | tr -d ' ')"
        log "spec lists $ENDPOINT_COUNT documented endpoint(s) -> endpoints.txt"
    fi
    sleep "$SLEEP"
fi

# --- GraphQL introspection (standard enumeration only) ----------------------
GRAPHQL_INTROSPECTION="unknown"
if $DO_GRAPHQL && in_scope "$BASE/graphql"; then
    log "== graphql introspection =="
    q='{"query":"query{__schema{queryType{name} mutationType{name} types{name kind}}}"}'
    gql="$(curl -sS -A "$UA" --max-time "$CURL_TIMEOUT" \
            ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
            -H 'Content-Type: application/json' -d "$q" "$BASE/graphql" 2>/dev/null || true)"
    if echo "$gql" | jq -e '.data.__schema' >/dev/null 2>&1; then
        echo "$gql" > "$OUTPUT_DIR/graphql-introspection.json"
        GRAPHQL_INTROSPECTION="enabled"
        TYPES="$(echo "$gql" | jq '[.data.__schema.types[].name] | length')"
        log "introspection ENABLED — $TYPES types -> graphql-introspection.json"
    elif [[ -n "$gql" ]]; then
        GRAPHQL_INTROSPECTION="disabled"
        log "introspection appears disabled (no __schema in response)"
    fi
    sleep "$SLEEP"
fi

# --- Summary record ---------------------------------------------------------
jq -cn --arg target "$BASE" --arg scanned "$(date -Iseconds)" \
   --arg spec "${SPEC_HIT:-none}" --argjson endpoints "${ENDPOINT_COUNT:-0}" \
   --arg graphql "$GRAPHQL_INTROSPECTION" \
   '{kind:"summary", target:$target, scanned:$scanned, openapi_spec:$spec,
     documented_endpoints:$endpoints, graphql_introspection:$graphql}' >> "$NDJSON"

if [[ "$FORMAT" == "json" || "$FORMAT" == "both" ]]; then jq -s '.' "$NDJSON"; fi

printf '%b== summary ==%b\n' "$GREEN" "$NC"
printf '  Origin                : %s\n' "$BASE"
printf '  OpenAPI/Swagger spec  : %s\n' "${SPEC_HIT:-none found}"
printf '  Documented endpoints  : %s\n' "$ENDPOINT_COUNT"
printf '  GraphQL introspection : %s\n' "$GRAPHQL_INTROSPECTION"
log "done — structured results: $NDJSON"
