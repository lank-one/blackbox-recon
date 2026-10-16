#!/usr/bin/env bash
#
# ip-audit.sh — Interactive IP + port auditor.
#
# Successor to my "shodan_check" script. The old name pointed at the *source*
# of the targets — IPs surfaced by a Shodan query — not to any Shodan API call.
# This audits a host:port directly: nmap for state, whois for the owner, the
# SSL subject, safe vuln NSE scripts, and a final verdict. Pairs naturally with
# a Shodan export as its input list.
#
# Verdict codes (my own triage convention — tweak to taste):
#   VU  — vulnerable / needs reporting (NSE finding, or exposed plaintext/mgmt port)
#   CHK — up and reachable, nothing critical, or mitigated by a CDN/WAF
#   FP  — port closed/filtered (perimeter block), likely a false positive
#
# The "flagged ports" list below encodes a generic good-practice policy
# (plaintext or remote-management services that generally shouldn't be exposed
# to the internet). Adjust FLAGGED_CRITICAL / FLAGGED_PLAINTEXT for your own
# rules of engagement — it is deliberately not tied to any client's methodology.
#
# USE ONLY against systems you own or are explicitly authorised to test.
#
# Usage:
#   ./ip-audit.sh                         # interactive loop
#   ./ip-audit.sh -i 1.2.3.4 -p 443       # one-shot
#   ./ip-audit.sh -i 1.2.3.4 -p 123 -P udp

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

# Remote-management / plaintext services that generally shouldn't face the net.
FLAGGED_CRITICAL=(20 21 22 23 161 3389 5900)   # FTP/Telnet/SNMP/RDP/VNC...
FLAGGED_PLAINTEXT=(25 110 143)                  # SMTP/POP3/IMAP without TLS

contains() { local n="$1"; shift; local x; for x in "$@"; do [[ "$x" == "$n" ]] && return 0; done; return 1; }

audit() {
    local ip="$1" port="$2" proto="$3"
    local nmap_out whois_out vuln_out domain verdict motive

    hr; title "Auditing $ip : $port/$proto"; hr

    ok "1. Owner (whois):"
    whois_out="$(run_whois "$ip")"
    [[ -n "$whois_out" ]] && echo "$whois_out" || muted "No whois org data."

    ok "2. Port state:"
    if [[ "$proto" == "udp" ]]; then
        nmap_out="$(sudo nmap -Pn -sU -p "$port" -sV --version-light "$ip" 2>/dev/null)"
    else
        nmap_out="$(nmap -Pn -sT -p "$port" -sV --version-light "$ip" 2>/dev/null)"
    fi
    sed 's/^/    /' <<<"$nmap_out"

    # Reverse-resolved name, if nmap printed one that isn't the bare IP.
    domain="$(grep -oP '(?<=Nmap scan report for )[^ ]+' <<<"$nmap_out" | head -n1)"
    [[ "$domain" == "$ip" ]] && domain=""

    verdict="CHK"; motive="Reachable, no critical findings."

    if grep -qE "$port/$proto[[:space:]]+open" <<<"$nmap_out"; then
        ok "3. Port OPEN — running safe vuln NSE..."
        if [[ "$proto" == "udp" ]]; then
            vuln_out="$(sudo nmap -Pn -sU -p "$port" --script "vuln and safe" "$ip" 2>/dev/null)"
        else
            vuln_out="$(nmap -Pn -sT -p "$port" --script "vuln and safe" "$ip" 2>/dev/null)"
        fi
        sed 's/^/    /' <<<"$vuln_out"
        if grep -iq "VULNERABLE:" <<<"$vuln_out"; then
            verdict="VU"; motive="NSE vuln script reported a finding."
        fi

        # Generic policy checks (see FLAGGED_* above).
        if contains "$port" "${FLAGGED_CRITICAL[@]}"; then
            warn "Exposed management/plaintext port — report as high risk."
            verdict="VU"; motive="Flagged port exposed (remote mgmt / plaintext)."
        elif contains "$port" "${FLAGGED_PLAINTEXT[@]}"; then
            warn "Cleartext mail protocol exposed — susceptible to MITM; recommend TLS variant."
            verdict="VU"; motive="Cleartext mail protocol exposed (MITM risk)."
        fi
        case "$port" in
            53)  muted "DNS: consider checking for open recursion (e.g. dns-recursion NSE)." ;;
            465) muted "SMTPS: verify it isn't accepting default credentials." ;;
            514) muted "Syslog: verify authentication to rule out log tampering." ;;
        esac

        # Don't cry wolf on a CDN/WAF edge: downgrade unless NSE already fired.
        if grep -iqE "Akamai|Cloudfront|Cloudflare|WebSEAL|F5 BIG-IP" <<<"$nmap_out$whois_out"; then
            if [[ "$verdict" != "VU" ]]; then
                verdict="CHK"; motive="Behind CDN/WAF — direct-scan finding likely mitigated."
            fi
        fi
    else
        err "Port not fully open."
        verdict="FP"; motive="Port closed or filtered (perimeter block)."
    fi

    ok "4. SSL certificate:"
    local sni="${domain:-$ip}"
    timeout 6 openssl s_client -showcerts -servername "$sni" -connect "$ip:$port" </dev/null 2>/dev/null \
        | openssl x509 -inform pem -noout -text 2>/dev/null \
        | grep -iE "Subject:|Not Before:|Not After:" | head -n5 | sed 's/^/    /' \
        || muted "No certificate retrieved."

    hr; title "VERDICT"; printf '    %-8s %s\n    %-8s %s\n' "CODE:" "$verdict" "REASON:" "$motive"; hr
}

main() {
    local ip="" port="" proto="tcp" oneshot=0
    while getopts ":i:p:P:h" opt; do
        case "$opt" in
            i) ip="$OPTARG"; oneshot=1 ;;
            p) port="$OPTARG" ;;
            P) proto="$OPTARG" ;;
            h) sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
            *) err "Bad option"; exit 1 ;;
        esac
    done

    init_colors
    require_deps whois nmap openssl || exit 1

    if (( oneshot )); then
        [[ -n "$port" ]] || { err "-p <port> required with -i"; exit 1; }
        valid_ip "$ip" || { err "Invalid IP: $ip"; exit 1; }
        audit "$ip" "$port" "${proto:-tcp}"
        exit 0
    fi

    while true; do
        echo
        read -r -p "[?] IP (blank to quit): " ip
        [[ -z "$ip" ]] && { ok "Done."; exit 0; }
        valid_ip "$ip" || { err "Invalid IP."; continue; }
        read -r -p "[?] Port: " port
        [[ -z "$port" ]] && { err "Port is required."; continue; }
        read -r -p "[?] Protocol (tcp/udp) [tcp]: " proto; proto="${proto:-tcp}"
        audit "$ip" "$port" "$proto"
        read -r -p "[?] Enter for next, Ctrl+C to stop..."
    done
}

main "$@"
