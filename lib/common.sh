#!/usr/bin/env bash
# common.sh — shared helpers for the Blackbox Recon Toolkit.
# This file is meant to be *sourced* by recon.sh and ip-audit.sh, not run directly.

# ---- Defaults (overridable via environment before sourcing) ----
: "${USE_COLOR:=auto}"      # auto | 1 | 0
: "${OUTDIR:=}"             # when set, per-target reports are written here
: "${HTTP_TIMEOUT:=5}"      # seconds for curl probes
: "${UA:=Mozilla/5.0 (compatible; blackbox-recon/1.0)}"

# ---- Colors -------------------------------------------------------------
# Decided once, at startup, while stdout is still the terminal. Keeping the
# values global means later pipes (tee into log files) still render colour on
# screen while the saved copy is stripped of ANSI codes.
init_colors() {
    local enable=1
    if [[ -n "${NO_COLOR:-}" || "$USE_COLOR" == "0" ]]; then
        enable=0
    elif [[ "$USE_COLOR" == "auto" && ! -t 1 ]]; then
        enable=0
    fi
    if (( enable )); then
        C_RESET=$'\e[0m'; C_BLUE=$'\e[34m'; C_GREEN=$'\e[32m'
        C_RED=$'\e[31m';  C_YELLOW=$'\e[33m'; C_GRAY=$'\e[90m'; C_MAGENTA=$'\e[35m'
    else
        C_RESET=''; C_BLUE=''; C_GREEN=''; C_RED=''
        C_YELLOW=''; C_GRAY=''; C_MAGENTA=''
    fi
}

# ---- Print helpers ------------------------------------------------------
hr()    { printf '%b%s%b\n' "$C_BLUE" "=================================================" "$C_RESET"; }
title() { printf '%b[*] %s%b\n' "$C_GREEN"  "$1" "$C_RESET"; }
ok()    { printf '%b[+] %s%b\n' "$C_GREEN"  "$1" "$C_RESET"; }
info()  { printf '%b[>] %s%b\n' "$C_BLUE"   "$1" "$C_RESET"; }
warn()  { printf '%b[!] %s%b\n' "$C_YELLOW" "$1" "$C_RESET"; }
err()   { printf '%b[-] %s%b\n' "$C_RED"    "$1" "$C_RESET" >&2; }
muted() { printf '%b    %s%b\n' "$C_GRAY"   "$1" "$C_RESET"; }

# ---- Validation ---------------------------------------------------------
valid_domain() { [[ "$1" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; }
valid_ip()     { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

# ---- Dependency check ---------------------------------------------------
require_deps() {
    local missing=() bin
    for bin in "$@"; do
        command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
    done
    if (( ${#missing[@]} )); then
        err "Missing required tool(s): ${missing[*]}"
        err "Install them and re-run."
        return 1
    fi
}

# ---- Recon primitives ---------------------------------------------------
resolve_ip() {
    # First IPv4 answer for a host (CNAMEs and AAAA are ignored).
    dig +short "$1" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1
}

run_whois() {
    local ip="$1"
    [[ -z "$ip" ]] && return 1
    whois "$ip" 2>/dev/null \
        | grep -iE 'org-name|orgname|descr|netname|organization' \
        | head -n5 | awk '{$1=$1; print}' | sed 's/^/    /'
}

http_status() {
    # Status line for a URL, or empty string on timeout/failure.
    curl -I -k -s -m "$HTTP_TIMEOUT" -A "$UA" "$1" 2>/dev/null | head -n1 | tr -d '\r'
}

# ---- Output helpers -----------------------------------------------------
setup_outdir() {
    [[ -z "$OUTDIR" ]] && return 0
    mkdir -p "$OUTDIR" || { err "Cannot create output dir: $OUTDIR"; exit 1; }
}

strip_ansi() { sed -r 's/\x1b\[[0-9;]*m//g'; }
