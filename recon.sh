#!/usr/bin/env bash
#
# recon.sh — Blackbox domain reconnaissance (lite / deep).
#
# Unified successor to the old v2 (lite) and v3 (deep) scripts: one tool, two
# depths, single-target or mass mode, with a shared helper library.
#
#   lite  → IP · whois · HTTP(S) status · quick nmap (-sV -sC, open ports)
#   deep  → the above + WhatWeb fingerprint + full SSL/SAN + nmap -p- + vuln NSE
#
# USE ONLY against systems you own or are explicitly authorised to test.
# See the disclaimer in README.md.
#
# Usage:
#   ./recon.sh                      # interactive menu
#   ./recon.sh example.com          # lite scan of one domain
#   ./recon.sh -m deep example.com  # deep scan of one domain
#   ./recon.sh -m deep -f list.txt  # deep scan of every domain in list.txt
#   ./recon.sh -o out example.com   # also save a stripped report under ./out/
#
# Flags: -m lite|deep   -f <file>   -o <outdir>   -h

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

MODE="lite"
LISTFILE=""
DOMAIN=""
IP=""

usage() {
    sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ---- Per-service analysis ----------------------------------------------
show_ip() {
    IP="$(resolve_ip "$DOMAIN")"
    if [[ -n "$IP" ]]; then ok "IP: $IP"; else err "IP not resolved"; fi
}

show_whois() {
    [[ -z "$IP" ]] && IP="$(resolve_ip "$DOMAIN")"
    [[ -z "$IP" ]] && { err "No IP for whois"; return; }
    ok "Whois (top 5):"
    run_whois "$IP"
}

show_http() {
    ok "HTTP / HTTPS:"
    local h s
    h="$(http_status "http://$DOMAIN")"
    s="$(http_status "https://$DOMAIN")"
    printf '    80:  %s\n' "${h:-Timeout}"
    printf '    443: %s\n' "${s:-Timeout}"
}

show_whatweb() {
    command -v whatweb >/dev/null 2>&1 || { muted "WhatWeb not installed, skipping."; return; }
    ok "Web technologies (WhatWeb):"
    whatweb -a 1 "https://$DOMAIN" 2>/dev/null | sed 's/^/    /' || muted "WhatWeb returned nothing."
}

show_ssl() {
    ok "SSL certificate (SAN + metadata):"
    timeout 8 openssl s_client -showcerts -servername "$DOMAIN" -connect "$DOMAIN:443" </dev/null 2>/dev/null \
        | openssl x509 -inform pem -noout -text 2>/dev/null \
        | grep -iE 'Subject:|Subject Alternative Name:|Not Before:|Not After:|DNS:' \
        | sed 's/^/    /' \
        || muted "No SSL response or timeout."
}

show_nmap() {
    local out
    if [[ "$MODE" == "deep" ]]; then
        ok "Nmap deep (all ports + safe vuln NSE):"
        muted "(tuned timings to ride out WAF/latency — this can take a while)"
        out="$(nmap -Pn -p- -sV -T4 --max-retries 2 --min-rate 300 \
               --host-timeout 20m --script "vuln and safe" --open "$DOMAIN" 2>/dev/null \
               | grep -vE '^Starting Nmap|^Host is up|^Nmap done|^Service detection|^SF:|^SF-Port')"
    else
        ok "Nmap (services + default scripts):"
        out="$(nmap -Pn -sV -sC --open "$DOMAIN" 2>/dev/null \
               | grep -vE '^Starting Nmap|^Host is up|^Nmap done|^Service detection|^SF:|^SF-Port')"
    fi

    if [[ -z "$out" ]] || grep -q '0 IP addresses' <<<"$out"; then
        muted "No open ports found, or the scan was blocked by a firewall."
        return
    fi
    sed 's/^/    /' <<<"$out"

    grep -qE '8443/tcp open|8080/tcp open|8000/tcp open' <<<"$out" \
        && warn "Alternate web ports detected."
    grep -qiE 'cms|wordpress|joomla|drupal|admin' <<<"$out" \
        && warn "Possible CMS detected."
}

# ---- Orchestration ------------------------------------------------------
scan_one() {
    IP=""
    hr; title "TARGET: $DOMAIN"; hr
    show_ip
    show_whois
    show_http
    if [[ "$MODE" == "deep" ]]; then
        show_whatweb
        show_ssl
    fi
    show_nmap
    echo
}

# In mass mode we first cheaply decide whether a host is even up, so a long
# list isn't dominated by dead domains. A host is "down" only when it has no
# IP *and* neither HTTP nor HTTPS answers.
is_up() {
    local d="$1"
    [[ -n "$(resolve_ip "$d")" ]] && return 0
    [[ -n "$(http_status "http://$d")" ]] && return 0
    [[ -n "$(http_status "https://$d")" ]] && return 0
    return 1
}

scan_file() {
    local file="$1" dom
    [[ -f "$file" ]] || { err "File not found: $file"; return 1; }
    info "Mass scan in $MODE mode — down hosts are skipped. (Ctrl+C aborts.)"
    echo
    while IFS= read -r dom || [[ -n "$dom" ]]; do
        dom="$(tr -d '\r' <<<"$dom" | xargs)"
        [[ -z "$dom" ]] && continue
        [[ "$dom" == \#* ]] && continue
        if is_up "$dom"; then
            DOMAIN="$dom"
            report scan_one
        else
            muted "[-] $dom -> DOWN (skipping)"
        fi
    done < "$file"
    ok "Mass scan complete."
}

# report <fn>: run an analysis function, echoing to screen and — when OUTDIR is
# set — also to a per-target, ANSI-stripped log file.
report() {
    if [[ -n "$OUTDIR" ]]; then
        local safe="${DOMAIN//[^a-zA-Z0-9._-]/_}"
        local log="$OUTDIR/${safe}_$(date +%Y%m%d_%H%M%S).txt"
        "$@" | tee >(strip_ansi >"$log")
        muted "saved: $log"
    else
        "$@"
    fi
}

ask_domain() {
    echo
    read -r -p "Target domain: " DOMAIN
    DOMAIN="$(tr -d '\r' <<<"$DOMAIN" | xargs)"
    [[ -z "$DOMAIN" ]] && { err "Domain cannot be empty."; return 1; }
    valid_domain "$DOMAIN" || warn "That doesn't look like a valid domain — continuing anyway."
    IP=""
}

menu() {
    while true; do
        echo
        printf '%b=== MENU (mode: %s | target: %s) ===%b\n' "$C_BLUE" "$MODE" "${DOMAIN:-none}" "$C_RESET"
        echo "  1. IP + whois"
        echo "  2. HTTP/HTTPS status"
        echo "  3. Nmap ($MODE)"
        echo "  4. Web fingerprint (WhatWeb + SSL)"
        echo "  5. Run ALL (current target)"
        echo "  6. Change target"
        echo "  7. Toggle lite/deep"
        printf '%b  8. Mass scan from .txt%b\n' "$C_MAGENTA" "$C_RESET"
        echo "  0. Exit"
        read -r -p "Choice: " choice
        case "$choice" in
            1) [[ -n "$DOMAIN" ]] && { show_ip; show_whois; } || warn "Set a target first (6)." ;;
            2) [[ -n "$DOMAIN" ]] && show_http || warn "Set a target first (6)." ;;
            3) [[ -n "$DOMAIN" ]] && show_nmap || warn "Set a target first (6)." ;;
            4) [[ -n "$DOMAIN" ]] && { show_whatweb; show_ssl; } || warn "Set a target first (6)." ;;
            5) [[ -n "$DOMAIN" ]] && report scan_one || warn "Set a target first (6)." ;;
            6) ask_domain ;;
            7) [[ "$MODE" == "lite" ]] && MODE="deep" || MODE="lite"; ok "Mode: $MODE" ;;
            8) read -r -p "Path to .txt list: " f; scan_file "$f" ;;
            0) ok "Bye."; exit 0 ;;
            *) err "Invalid option." ;;
        esac
    done
}

# ---- Entry point --------------------------------------------------------
main() {
    while getopts ":m:f:o:h" opt; do
        case "$opt" in
            m) MODE="$OPTARG" ;;
            f) LISTFILE="$OPTARG" ;;
            o) OUTDIR="$OPTARG" ;;
            h) usage 0 ;;
            :) err "Option -$OPTARG needs an argument"; usage 1 ;;
            \?) err "Unknown option -$OPTARG"; usage 1 ;;
        esac
    done
    shift $((OPTIND - 1))
    [[ "$MODE" == "lite" || "$MODE" == "deep" ]] || { err "mode must be lite or deep"; exit 1; }

    init_colors
    local deps=(dig whois curl nmap openssl)
    [[ "$MODE" == "deep" ]] && deps+=(whatweb)
    require_deps "${deps[@]}" || exit 1
    setup_outdir

    hr; title "BLACKBOX RECON — mode: $MODE"; hr

    if [[ -n "$LISTFILE" ]]; then
        scan_file "$LISTFILE"
    elif [[ $# -ge 1 ]]; then
        DOMAIN="$1"
        report scan_one
    else
        ask_domain || exit 1
        menu
    fi
}

main "$@"
