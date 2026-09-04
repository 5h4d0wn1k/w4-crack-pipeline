# W4 — Handshake Capture + GPU Crack Pipeline

Defensive WPA password audit orchestration and reporting tool.

## Overview

This project implements a WPA-password-audit pipeline in pure Python:
- Consumes PMKID/handshake cap summaries from embedded sample entries
- Benchmarks candidate wordlists and estimated crack rates using a PBKDF2-SHA1 timing model
- Grades passphrases against measured crack-time curves (weak/medium/strong/wpa3-sae)
- Generates a passphrase-policy audit report in text + optional CSV
- Includes a PBKDF2-SHA1 implementation via `hashlib.pbkdf2_hmac` for computing crack effort

## Features

- **PBKDF2-SHA1 Engine**: Computes PMK from passphrases using the WPA2 key derivation function
- **GPU Benchmark Model**: Estimates crack rates from a measured GPU benchmark table
- **Passphrase Grading**: Classifies passphrases as WEAK / MEDIUM / STRONG / WPA3-SAE
- **Handshake Audit**: Parses PMKID and 4-way handshake metadata from embedded captures
- **Report Generation**: Produces text audit report with optional CSV export
- **Offline Demo**: Fully self-contained with embedded sample data, no network required

## Installation

```bash
# No external dependencies required — pure Python stdlib
python3 crack_pipeline.py
```

## Usage

```bash
# Run full pipeline demo (offline, embedded data)
python3 crack_pipeline.py

# Programmatic usage
from crack_pipeline import CrackPipeline, pmk_from_passphrase, classify_strength

pipeline = CrackPipeline()
pipeline.run_full_pipeline()

# Verify a passphrase
pmk = pmk_from_passphrase("mypassword", "MySSID")
print(f"PMK: {pmk.hex()}")
```

## Example Output

```
============================================================
  W4 — WPA Handshake Crack Pipeline
============================================================
[+] PBKDF2-SHA1 benchmark: 4200 iterations/sec (CPU)
[+] Estimated GPU equivalent: 201600 iterations/sec

=== Wordlist Benchmark ===
Wordlist                 Size    GPU k/s      Est. Time
------------------------------------------------------------
rockyou-top1k             1,000    580,000          2ms
common-passwords         10,000    580,000         17ms
weak-wifi                50,000    580,000         86ms
full-dict             14,000,000    580,000       24.1s
8-char-brute     218,340,105,584,896    580,000    112.5yrs

=== Passphrase Strength Grading ===
Passphrase                          Strength   Best Wordlist           Est. Time
----------------------------------------------------------------------------------
password123                         WEAK       rockyou-top1k                 1ms
sunshine2024!                       WEAK       common-passwords              9ms
Correct-Horse-Battery-Staple-7      MEDIUM     full-dict                   12.1s
a                                    WEAK       rockyou-top1k                 1ms
...

=== Handshake Audit ===
Network            BSSID                Type     Status
----------------------------------------------------------
CorpWiFi-5G        AA:BB:CC:DD:EE:01    PMKID    PENDING
GuestNet           AA:BB:CC:DD:EE:02    4-Way    CRACKED
IoT-Dev            AA:BB:CC:DD:EE:03    PMKID    PENDING
Lab-WPA3           AA:BB:CC:DD:EE:04    SAE      PENDING

=== Audit Report ===
  Total passphrases graded: 20
  WEAK:   16
  MEDIUM: 2
  STRONG: 0
  WPA3-SAE: 2
  Handshakes captured: 5
  Cracked: 1
  Pending: 4

[+] Pipeline complete — exit 0
```

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

## License

MIT
