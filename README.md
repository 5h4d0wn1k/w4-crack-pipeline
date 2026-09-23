> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# W4 — WPA/WPA2/PMKID Crack Pipeline

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub Stars](https://img.shields.io/github/stars/5h4d0wn1k/w4-crack-pipeline)
![Last Commit](https://img.shields.io/github/last-commit/5h4d0wn1k/w4-crack-pipeline)
![GitHub Issues](https://img.shields.io/github/issues/5h4d0wn1k/w4-crack-pipeline)

> **Wireless password-audit crack pipeline for WiFi security testing** — detects
> 4-way handshakes and PMKIDs in lab-captured traffic, converts with
> `hcxpcapngtool`, cracks with `hashcat` (straight + best64 rules), and records
> every attempt in a SQLite + JSONL results store.

## Why

Wi-Fi security relies on WPA/WPA2 passphrases, and weak passphrases are the
single most common way wireless networks are compromised. W4 turns that reality
into a repeatable, safe lab exercise: feed it a capture from **your own AP**,
and it assembles the exact professional pipeline — handshake/PMKID detection,
`hc22000` conversion, wordlist precheck, `hashcat` mode 22000 with the `best64`
rule set, and result parsing that persists each attempt alongside keys/s and
time-to-crack metrics. Strict safety rails (root refusal, owned-capture markers,
binary pre-checks, `--dry-run`) keep every run inside an authorized, self-owned
lab. All network constants are RFC 5737 / `lab-` documentation placeholders.

## Features

- **`crack audit <cap>`** — smoke-test a capture for viable handshake/PMKID.
- **`crack pmkid <input>`** — crack PMKID material (capture or `hc22000`).
- **`crack wpa <cap>`** — full flow: detect → convert → precheck → hashcat →
  parse/DB.
- **`crack batch <dir>`** — process every `.cap`/`.pcap`/`.pcapng` in a dir.
- **`crack report <db>`** — render JSON + Markdown reports with metrics.
- **`crack selftest`** — offline, unprivileged, tool-presence self-test (cracks
  a synthetic hash when `hashcat` is present).
- **`--dry-run`** — prints the exact command sequence, executes nothing.
- **Clean exit codes** — `0` ok · `1` config/arg · `2` missing tool ·
  `3` no handshake.
- **Results store** — SQLite `logs/results.db` + JSONL sidecar (gitignored).

## Requirements

| Binary | Package (Debian/Ubuntu) | Purpose |
|---|---|---|
| `hcxpcapngtool` | `hcxtools` | detect + convert to `hc22000` |
| `hashcat` | `hashcat` | mode 22000, attack 0 + best64 |
| `aircrack-ng` | `aircrack-ng` | handshake-detect fallback |
| `hcxdumptool` | `hcxtools` | (optional) capture your own lab traffic |

Wordlist default: `/usr/share/wordlists/rockyou.txt`. Rules default:
`/usr/share/hashcat/rules/best64.rule`. Override with `crack -w ... -r ...` or
edit `config/crack.yaml`.

## Quickstart

```bash
pip install -r requirements.txt
crack selftest                 # needs no root/network/tools for the offline part

# Lab capture only (own AP, filename carries the lab marker)
crack audit lab-ap-assoc.cap
crack --dry-run wpa lab-ap-assoc.cap
crack -w /usr/share/wordlists/rockyou.txt wpa lab-ap-assoc.cap
crack -w /usr/share/wordlists/rockyou.txt pmkid lab-ap-hc22000
crack report logs/results.db
```

Run from the repo root so gitignored `logs/` artifacts stay internal. The CLI is
also available as `python3 -m firmware.crack_pipeline ...` from the repo root.

## Configuration

`config/crack.yaml` sets tool paths, wordlist/rules, `hashcat` mode (22000),
workload, potfile, the lab filename marker, and DB paths.

## Tests

```bash
python3 -m unittest discover -s tests
python3 -m py_compile firmware/*.py tests/*.py   # must stay clean
```

## Project structure

```
firmware/     # pipeline, config, toolchain, selftest, report modules
config/       # crack.yaml
tests/        # config, exit-code, dry-run, report tests
logs/         # working artifacts (gitignored)
```

## Documentation

- [ETHICS.md](ETHICS.md) — ethical-use policy, read first
- [SCOPE.md](SCOPE.md) — authorized-scope definition
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [SECURITY.md](SECURITY.md) — vulnerability reporting

## Contributing

Wordlist precheck logic, report formats, and new toolchain adapters are welcome.
See [CONTRIBUTING.md](CONTRIBUTING.md); keep `--dry-run` and the own-lab guard
inviolable.

## License

MIT — see [LICENSE](LICENSE).