# W4 — WPA/WPA2/PMKID Capture → Crack Pipeline

Production-grade password-audit orchestration for **your own lab-captured**
WPA/WPA2/PMKID traffic. The pipeline detects a handshake or PMKID in a capture,
converts it (hcxpcapngtool), prechecks the wordlist, cracks with hashcat
(straight mode + best64 rules), parses results, and records every attempt in a
SQLite + JSONL results store.

## Overview

- Consumes `.cap` / `.pcap` / `.pcapng` captures and pre-converted `hc22000` hash files
- Detects **4-way handshake** and **PMKID** material via `hcxpcapngtool` (fallback `aircrack-ng`)
- Converts to hashcat mode `22000` (WPA-PBKDF2 PMKID+EAPOL), the one mode that
  handles both handshakes and PMKIDs
- Cracks with hashcat **attack 0 (straight)** + **best64 rules**; progress
  (keys/s, %, ETA) is parsed from hashcat stdout and streamed to the log
- Persists every attempt to a SQLite database (`logs/results.db`) and a JSONL
  sidecar (`logs/results.jsonl`), then renders JSON + Markdown reports
- Strict safety rails: refuses to run as root, requires owned/lab-marked
  captures, verifies every external binary before invoking it, and offers
  `--dry-run` that prints the exact command sequence without executing anything
- Clean exit codes: `0` ok · `1` config/arg error · `2` missing tool · `3` no handshake found

Every network constant in this repo is a **documentation lab placeholder**
(`192.0.2.x` range, example MACs `00:11:22:33:44:55`, SSIDs `lab-ap`/`lab-guest`).
Real-world identifiers never appear as defaults.

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before running password audits
- Attempting to crack WPA handshakes on networks you do not own is illegal
- This tool should ONLY be used on networks you own or have written authorization to test
- Verify legal authorization before processing any captured handshake data

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Captured network data may be subject to privacy regulations

### Acceptable Use
- Testing password strength of your own WiFi networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training demonstrations

### Prohibited Use
- Cracking WPA handshakes on networks you don't own
- Attempting to recover passwords without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover weak passwords using this tool, follow responsible disclosure practices:
1. Report to the network owner privately
2. Allow reasonable time for remediation
3. Do not exploit recovered credentials beyond proof of concept

## Toolchain Requirements

The pipeline orchestrates external tools via `subprocess`; every binary is
detected up-front (`crack selftest` reports PRESENT/MISSING) and a missing
required tool exits cleanly with code `2` instead of crashing.

| Binary | Package (Debian/Ubuntu) | Needed for | Notes |
| --- | --- | --- | --- |
| `hcxpcapngtool` | `hcxtools` | detect + convert | converts `.cap` → `hc22000`; PMKID authority |
| `hashcat` | `hashcat` | crack | mode 22000, attack 0 |
| `aircrack-ng` | `aircrack-ng` | handshake detect fallback | used when `hcxpcapngtool` is absent |
| `hcxdumptool` | `hcxtools` | capture (lab) | not required by the pipeline; used to capture your own traffic |

Optional data:

- Wordlist: default `/usr/share/wordlists/rockyou.txt` (Debian: `apt install wordlists`, then
  `sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz`)
- Rules: default `/usr/share/hashcat/rules/best64.rule` (ships with the `hashcat` package;
  the pipeline warns and cracks rules-less if absent)

Overrides are always possible: `crack -w <wordlist> -r <rules> ...` or edit `config/crack.yaml`.

## Installation

```bash
# only third-party dependency is PyYAML (config parsing); everything else is stdlib
pip install -r requirements.txt
# or
pip install -e .

# no external tools needed for --help / audit dry-run / selftest / report
crack --help
crack selftest
```

You can run the CLI without installing via `python3 -m firmware.crack_pipeline ...`
from the repository root.

## Usage

Run from the repository root so the gitignored `logs/` artifacts stay inside the repo.

### `crack audit <capfile>` — smoke-test a capture
Tells you whether a capture contains a usable 4-way handshake or PMKID.

```bash
crack audit lab-ap-home.cap
# capture : lab-ap-home.cap
# allow   : owner (own-lab requirement satisfied)
# pmkid   : 2
# 4-way   : 1
# ssid    : lab-ap
# kind    : handshake
# [+] audit OK: viable handshake/PMKID target present -- exit 0
```

Exit `3` (no handshake/PMKID), `1` (unauthorized/unreadable capture), or `2` (no detector installed).

### `crack pmkid <input>` — crack PMKID material
Accepts a capture file **or** an already-converted `hc22000`/hash file.

```bash
crack -w /usr/share/wordlists/rockyou.txt pmkid lab-ap-home.cap
crack -w /usr/share/wordlists/rockyou.txt pmkid lab-ap-home.hc22000
```

### `crack wpa <cap>` — crack a WPA handshake capture
Full six-stage flow: detect → convert → wordlist precheck → hashcat (best64) →

result parse → results DB.

```bash
crack wpa lab-ap-home.cap
# wpa: lab-ap-home.cap: CRACKED -> 'winter2020' time=4.2 s keys/s=155000
# [+] passphrase recovered -- recorded to results DB -- exit 0
```

A completed run that does **not** recover a password still exits `0` with
status `NOT_CRACKED` recorded in the DB — see [Metrics](#metrics).

### `crack batch <dir>` — many captures, one run
Processes every `*.cap` / `*.pcap` / `*.pcapng` under a directory, logging each
attempt to the results DB.

```bash
crack -w /usr/share/wordlists/rockyou.txt batch ~/lab-captures/
```

### `crack report <db>` — render the results DB
Generates `logs/report.json` and `logs/report.md` with attempt-level and
summary metrics (counts, time-to-crack range, avg keys/s, recovered passphrases).

```bash
crack report logs/results.db
# attempts : 12    cracked : 3    not cracked : 7    no handshake : 2
```

### `crack selftest` — offline self-test
Validates config, insists on unprivileged execution, reports which external
tools are PRESENT/MISSING, and — when `hashcat` is installed — cracks a tiny
synthetic WPA hash with a known password (hashcat's documented example hash) in
straight mode. Exits `0` either way and completes in seconds.

### `--dry-run` — safety-first preview
Prints the exact command sequence for a job without executing anything
(nothing is written, no subprocess runs):

```bash
crack --dry-run wpa lab-ap-home.cap
# [1/4] detect handshake/PMKID in lab-ap-home.cap (hcxpcapngtool)
#       $ hcxpcapngtool --show-summary lab-ap-home.cap
# [2/4] detect handshake in lab-ap-home.cap (aircrack-ng)
#       $ /usr/bin/aircrack-ng lab-ap-home.cap
# [3/4] convert lab-ap-home.cap -> lab-ap-home.hc22000 (hcxpcapngtool, hc22000)
#       $ hcxpcapngtool -o logs/work/lab-ap-home.hc22000 lab-ap-home.cap
# [4/4] crack (hashcat mode 22000, straight + best64 rules)
#       $ hashcat -m 22000 -a 0 -w 3 --potfile-path logs/crack.potfile \
#         --status --status-timer 5 logs/work/lab-ap-home.hc22000 \
#         /usr/share/wordlists/rockyou.txt
```

### Common options

```bash
crack [--config PATH] [--wordlist PATH] [--rules PATH] [--db PATH] [--dry-run] \
      [--log-level INFO] [--log-file logs/crack.log] <subcommand>
```

Structured logging goes to both `logs/crack.log` and stdout.

## Metrics

Reported per attempt in the results DB, `report.json`, and `report.md`:

| Metric | Meaning | Source |
| --- | --- | --- |
| **time-to-crack** | wall time of the hashcat stage (ms) | pipeline timer |
| **keys/s** | last speed line parsed from hashcat status output | hashcat stdout |
| **candidates tested** | `Progress` value parsed from hashcat (when available) | hashcat stdout |
| **success / fail** | `CRACKED` / `NOT_CRACKED` / `NO_HANDSHAKE` status per capture | potfile / detection |
| **clean exit** | `0` ok · `1` config/arg · `2` missing tool · `3` no handshake | pipeline exit codes |

Example report excerpt:

```markdown
| Attempts | 12 |
| Cracked | 3 |
| Avg keys/s (cracked) | 155000 |
| Time-to-crack range | 2.1 s – 14 min |
```

A "successful" pipeline run is a **clean exit `0`** with a status row in the DB;
the passphrase is either recovered (`CRACKED`) or the run completes without a
crack (`NOT_CRACKED`, still exit `0` because the pipeline itself ran correctly).

## Live Lab Test Plan

Every live test is executed against **our own** lab infrastructure only — an AP
we own and a passphrase we chose, picked from the rockyou wordlist.

1. **Setup.** Lab AP broadcasting an SSID we control (`lab-ap`). Client joins
   with a passphrase chosen from `rockyou.txt` (e.g. a cracked/known rockyou
   entry so the wordlist contains it and the crack must succeed).
2. **Capture.** Own-lab capture: `hcxdumptool` (or `airodump-ng`) on the lab
   client/AP association to obtain a 4-way handshake; optionally request a PMKID
   from our own AP for the PMKID path. Name the file with the lab marker, e.g.
   `lab-ap-assoc.cap`, so the own-lab authorization check passes.
3. **Audit.** `crack audit lab-ap-assoc.cap` → must report a usable `kind`.
4. **Dry-run first.** `crack --dry-run wpa lab-ap-assoc.cap` → confirm the exact
   command sequence before executing anything.
5. **Crack.**
   `crack -w /usr/share/wordlists/rockyou.txt wpa lab-ap-assoc.cap` →
   expect `CRACKED -> '<chosen passphrase>'`, with keys/s and time-to-crack
   metrics; verify the matching `logs/results.jsonl` line and SQLite row.
6. **Report.** `crack report logs/results.db` → JSON + Markdown reflect the run.
7. **PMKID path.** `crack pmkid lab-ap-pmkid.cap` against a PMKID we captured
   from our own AP; the same hashcat mode covers it.
8. **Negative.** Run `crack wpa` on a capture of a lab network **without** a
   handshake/PMKID → confirm clean `exit 3` and `NO_HANDSHAKE` handling.

Record the numbers (time-to-crack, keys/s, passphrases recovered, exit codes)
in `METRICS.md` after each live test.

## Configuration

`config/crack.yaml`:

```yaml
tools:           # paths/names of external binaries
  hcxpcapngtool: hcxpcapngtool
  hashcat: hashcat
  aircrack: aircrack-ng
wordlist: /usr/share/wordlists/rockyou.txt
rules: /usr/share/hashcat/rules/best64.rule
hashcat:
  mode: 22000      # WPA-PBKDF2 PMKID+EAPOL
  workload: 3      # hashcat -w (1..4)
  devices: ""      # optional hashcat -D
  potfile: logs/crack.potfile
capture:
  allowed_owner: null   # extra trusted owner uid/username, or null
  marker: lab           # filename token that marks a capture as own-lab
db:
  path: logs/results.db      # SQLite results DB (gitignored)
  jsonl: logs/results.jsonl  # JSONL sidecar (gitignored)
```

Relative paths resolve against the directory the CLI is run from.

## Testing

```bash
python3 -m unittest discover -s tests
```

Stdlib-only unit tests cover config validation, the exit-code contract,
report rendering, and dry-run command-sequence building (asserting no
subprocess is ever executed in dry-run mode).

`python3 -m py_compile firmware/*.py tests/*.py` must stay clean.

## License

MIT