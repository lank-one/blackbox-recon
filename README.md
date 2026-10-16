# Blackbox Recon Toolkit

A small, dependency-light Bash toolkit for the **reconnaissance** phase of an
authorised penetration test or bug-bounty engagement. It wraps standard tools
(`dig`, `whois`, `curl`, `nmap`, `whatweb`, `openssl`) into two focused
workflows with a shared helper library, consistent output, and optional
per-target logging.

> Built from scripts I use during live pentesting work, cleaned up and
> generalised for public use.

---

## ⚠️ Legal / authorised use only

These tools actively scan hosts. Port scanning and service probing against
systems you do **not** own or have **explicit written authorisation** to test
may be illegal in your jurisdiction.

**You are solely responsible for how you use this software.** Only run it
against assets that are in scope of an engagement you are authorised for, or
against your own lab. The authors accept no liability for misuse. See
[`LICENSE`](LICENSE).

`scanme.nmap.org` (used in the example list) is a host Nmap provides
explicitly for scan testing.

---

## Contents

| Script | What it does |
|---|---|
| `recon.sh` | Domain recon in **lite** or **deep** mode — single target or a list. |
| `ip-audit.sh` | Interactive **IP + port** auditor: nmap, whois, SSL, safe vuln NSE, verdict. |
| `lib/common.sh` | Shared helpers (colours, validation, dep-check, recon primitives). Sourced, not run. |

### `recon.sh` modes

| | lite | deep |
|---|---|---|
| IP · whois · HTTP(S) status | ✅ | ✅ |
| Nmap | `-sV -sC --open` | `-p- -sV --script "vuln and safe"` (tuned timings) |
| WhatWeb fingerprint | — | ✅ |
| Full SSL / SAN dump | — | ✅ |

---

## Requirements

- Bash 4+
- `dig` (dnsutils / bind-utils), `whois`, `curl`, `nmap`, `openssl`
- `whatweb` (only for `recon.sh` deep mode)
- `sudo` only if you scan **UDP** ports in `ip-audit.sh`

Debian/Ubuntu:

```bash
sudo apt install dnsutils whois curl nmap openssl whatweb
```

The scripts check their dependencies on startup and exit cleanly if one is
missing.

---

## Usage

```bash
git clone https://github.com/lank-one/blackbox-recon.git
cd blackbox-recon
chmod +x recon.sh ip-audit.sh
```

### Domain recon

```bash
./recon.sh                         # interactive menu
./recon.sh example.com             # lite scan, one domain
./recon.sh -m deep example.com     # deep scan, one domain
./recon.sh -m deep -f domains.txt  # deep scan every domain in a file
./recon.sh -o out example.com      # also save a clean report under ./out/
```

In mass mode (`-f`), unreachable hosts (no IP and no HTTP/HTTPS response) are
skipped so a long list isn't dominated by dead domains.

### IP + port audit

```bash
./ip-audit.sh                      # interactive loop
./ip-audit.sh -i 1.2.3.4 -p 443    # one-shot TCP
./ip-audit.sh -i 1.2.3.4 -p 123 -P udp
```

**Verdict codes** (my own triage convention — adjust to your rules of engagement):

- `VU` — vulnerable / needs reporting (NSE finding, or an exposed
  management/plaintext port).
- `CHK` — reachable, nothing critical, or mitigated behind a CDN/WAF.
- `FP` — port closed/filtered; likely a false positive from an upstream feed.

The "flagged ports" policy lives in `FLAGGED_CRITICAL` / `FLAGGED_PLAINTEXT`
at the top of `ip-audit.sh`. It's a generic good-practice default — edit it
for your own engagement rules.

---

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `USE_COLOR` | `auto` | `0` / `1` to force colour off/on. |
| `NO_COLOR` | — | If set, disables colour (honours the [NO_COLOR](https://no-color.org) convention). |
| `HTTP_TIMEOUT` | `5` | Seconds for `curl` probes. |
| `OUTDIR` | — | Same as `-o`: directory for saved reports. |

Saved reports are ANSI-stripped so they're clean to read and grep.

---

## Notes & limitations

- Recon only — no exploitation. `nmap` NSE is limited to `vuln and safe`.
- Heuristics (CMS detection, CDN/WAF downgrade) are best-effort hints, not
  ground truth. Always verify by hand.
- `whois` field names vary by registrar/RIR; the org extraction is a
  best-effort grep.

## Roadmap ideas

- JSON/CSV output for pipelines
- Optional passive sources (e.g. Shodan API via env-var key) to enrich without
  touching the target
- Subdomain enumeration front-end

## License

MIT — see [`LICENSE`](LICENSE).
