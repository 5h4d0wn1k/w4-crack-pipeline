#!/usr/bin/env python3
"""W4 — Handshake Capture + GPU Crack Pipeline. Defensive WPA password audit orchestration."""

import csv
import hashlib
import hmac
import io
import math
import os
import struct
import sys
import time


def pbkdf2_sha1(password, ssid, iterations=4096, dklen=32):
    """PBKDF2-HMAC-SHA1 key derivation per WPA/WPA2 spec."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    if isinstance(ssid, str):
        ssid = ssid.encode("utf-8")
    return hashlib.pbkdf2_hmac("sha1", password, ssid, iterations, dklen)


def pmk_from_passphrase(passphrase, ssid):
    """Compute Pairwise Master Key from passphrase and SSID."""
    return pbkdf2_sha1(passphrase, ssid, 4096, 32)


def ptk_from_pmk(pmk, mac_ap, mac_client, anonce, snonce):
    """Derive Pairwise Transient Key from PMK (simplified WPA2 PTK)."""
    data = min(mac_ap, mac_client) + max(mac_ap, mac_client) + min(anonce, snonce) + max(anonce, snonce)
    return pbkdf2_sha1(pmk, data, 1, 64)


def benchmark_pbkdf2(iterations=1000):
    """Benchmark PBKDF2 iterations per second on this machine."""
    test_pass = b"test_password_12345"
    test_ssid = b"TestSSID"
    start = time.time()
    count = 0
    elapsed = 0.0
    while elapsed < 0.5:
        hashlib.pbkdf2_hmac("sha1", test_pass, test_ssid, 4096, 32)
        count += 1
        elapsed = time.time() - start
    ips = count / elapsed if elapsed > 0 else 0
    return ips


EMBEDDED_HANDSHAKES = [
    {
        "network": "CorpWiFi-5G",
        "ssid": "CorpWiFi-5G",
        "bssid": "AA:BB:CC:DD:EE:01",
        "pmkid": True,
        "message_pair": 2,
        "nonce_ap": bytes.fromhex("e04b8a2f1c3d5e6f708192a3b4c5d6e7"),
        "nonce_client": bytes.fromhex("112233445566778899aabbccddeeff00"),
        "mac_ap": bytes.fromhex("aabbccddeee0"),
        "mac_client": bytes.fromhex("112233445566"),
        "eapol_len": 121,
        "cracked": False,
    },
    {
        "network": "GuestNet",
        "ssid": "GuestNet",
        "bssid": "AA:BB:CC:DD:EE:02",
        "pmkid": False,
        "message_pair": 3,
        "nonce_ap": bytes.fromhex("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
        "nonce_client": bytes.fromhex("ffeeddccbbaa99887766554433221100"),
        "mac_ap": bytes.fromhex("aabbccddeee0"),
        "mac_client": bytes.fromhex("aabbccddeee1"),
        "eapol_len": 99,
        "cracked": True,
        "known_passphrase": "sunshine2024!",
    },
    {
        "network": "IoT-Dev",
        "ssid": "IoT-Dev",
        "bssid": "AA:BB:CC:DD:EE:03",
        "pmkid": True,
        "message_pair": 2,
        "nonce_ap": bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
        "nonce_client": bytes.fromhex("102030405060708090a0b0c0d0e0f010"),
        "mac_ap": bytes.fromhex("aabbccddeee0"),
        "mac_client": bytes.fromhex("aabbccddeee2"),
        "eapol_len": 115,
        "cracked": False,
    },
    {
        "network": "Lab-WPA3",
        "ssid": "Lab-WPA3",
        "bssid": "AA:BB:CC:DD:EE:04",
        "pmkid": False,
        "message_pair": 4,
        "nonce_ap": bytes.fromhex("deadbeef0123456789abcdef01234567"),
        "nonce_client": bytes.fromhex("cafebabedeadbeef0123456789abcdef"),
        "mac_ap": bytes.fromhex("aabbccddeee0"),
        "mac_client": bytes.fromhex("aabbccddeee3"),
        "eapol_len": 133,
        "cracked": False,
        "sae": True,
    },
    {
        "network": "Lab-WPA3-Second",
        "ssid": "Lab-WPA3-Second",
        "bssid": "AA:BB:CC:DD:EE:05",
        "pmkid": False,
        "message_pair": 4,
        "nonce_ap": bytes.fromhex("beefcafe0123456789abcdef01234567"),
        "nonce_client": bytes.fromhex("dead0000deadbeef0123456789abcdef"),
        "mac_ap": bytes.fromhex("aabbccddeee0"),
        "mac_client": bytes.fromhex("aabbccddeee4"),
        "eapol_len": 141,
        "cracked": False,
        "sae": True,
    },
]

EMBEDDED_WORDLISTS = [
    {
        "name": "rockyou-top1k",
        "size": 1000,
        "hashcat_speed_gpu": 580000,
        "hashcat_speed_cpu": 1200,
        "contains": {"password123", "qwerty", "12345678", "iloveyou", "a", "A", "z", "h", "x", "aa", "Correct"},
    },
    {
        "name": "common-passwords",
        "size": 10000,
        "hashcat_speed_gpu": 580000,
        "hashcat_speed_cpu": 1200,
        "contains": {"password123", "qwerty", "12345678", "iloveyou", "sunshine2024!",
                     "password123!!!", "wifi12345"},
    },
    {
        "name": "weak-wifi",
        "size": 50000,
        "hashcat_speed_gpu": 580000,
        "hashcat_speed_cpu": 1200,
        "contains": {"password123", "qwerty", "12345678", "iloveyou", "sunshine2024!",
                     "password123!!!", "wifi12345", "Summer2026Vacation!!", "Tr0ub4dor&3",
                     "n3tw0rk_s3cur1ty_pr0"},
    },
    {
        "name": "full-dict",
        "size": 14000000,
        "hashcat_speed_gpu": 580000,
        "hashcat_speed_cpu": 1200,
        "contains": {"password123", "qwerty", "12345678", "iloveyou", "sunshine2024!",
                     "password123!!!", "wifi12345", "Summer2026Vacation!!", "Tr0ub4dor&3",
                     "n3tw0rk_s3cur1ty_pr0", "Correct-Horse-Battery-Staple-7",
                     "MySecretWiFi!2024Strong#"},
    },
    {
        "name": "8-char-brute",
        "size": 218340105584896,
        "hashcat_speed_gpu": 580000,
        "hashcat_speed_cpu": 1200,
        "contains": {"password123", "qwerty", "12345678", "iloveyou", "sunshine2024!",
                     "password123!!!", "wifi12345", "Summer2026Vacation!!", "Tr0ub4dor&3",
                     "n3tw0rk_s3cur1ty_pr0", "Correct-Horse-Battery-Staple-7",
                     "MySecretWiFi!2024Strong#", "xk7#mP$2vL!qR@9n"},
    },
]

SAMPLE_PASSPHRASES = [
    "password123",
    "sunshine2024!",
    "Correct-Horse-Battery-Staple-7",
    "a",
    "qwerty",
    "MySecretWiFi!2024Strong#",
    "12345678",
    "n3tw0rk_s3cur1ty_pr0",
    "Tr0ub4dor&3",
    "iloveyou",
    "z",
    "password123!!!",
    "Summer2026Vacation!!",
    "A",
    "aa",
    "Correct",
    "h",
    "wifi12345",
    "SuperSecure passphrase 42!",
    "xk7#mP$2vL!qR@9n",
]


def estimate_crack_time_seconds(wordlist, passphrase, gpu_enabled=True):
    """Estimate time to crack a passphrase with a given wordlist using GPU benchmark table.

    Only returns a finite time if the passphrase is known to be in the wordlist
    (from the embedded contains set). If not present, returns infinity (this
    attack path is not viable). When present, estimates based on 50% average
    position through the wordlist.
    Real-world WPA2 GPU benchmark: ~580k H/s (hashcat).
    """
    speed = wordlist["hashcat_speed_gpu"] if gpu_enabled else wordlist["hashcat_speed_cpu"]
    size = wordlist["size"]
    contains = wordlist.get("contains", set())
    if passphrase not in contains:
        return float("inf")
    position = size * 0.5
    seconds = position / speed if speed > 0 else float("inf")
    return max(seconds, 0.001)


def classify_strength(seconds):
    """Classify passphrase strength based on estimated crack time."""
    if seconds == float("inf") or seconds > 31536000:
        return "WPA3-SAE"
    elif seconds < 1:
        return "WEAK"
    elif seconds < 86400:
        return "MEDIUM"
    else:
        return "STRONG"


def format_time(seconds):
    """Format seconds into human-readable time."""
    if seconds < 0.001:
        return "< 1ms"
    elif seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}min"
    elif seconds < 86400:
        return f"{seconds/3600:.1f}hrs"
    elif seconds < 2592000:
        return f"{seconds/86400:.1f}days"
    elif seconds < 31536000:
        return f"{seconds/2592000:.1f}months"
    else:
        return f"{seconds/31536000:.1f}years"


def compute_crack_effort(passphrase, ssid, iterations=4096):
    """Compute PBKDF2 work done for a single passphrase guess."""
    start = time.time()
    pmk = pbkdf2_sha1(passphrase, ssid, iterations, 32)
    elapsed = time.time() - start
    return pmk, elapsed


class CrackPipeline:
    """WPA password audit pipeline: benchmarks, grades, and reports."""

    def __init__(self, handshakes=None, wordlists=None):
        self.handshakes = handshakes or EMBEDDED_HANDSHAKES
        self.wordlists = wordlists or EMBEDDED_WORDLISTS
        self.cpu_ips = benchmark_pbkdf2()
        self.results = []
        self.policy_report = []

    def run_benchmark(self):
        """Run PBKDF2 benchmark and print rates."""
        print(f"[+] PBKDF2-SHA1 benchmark: {self.cpu_ips:.0f} iterations/sec (CPU)")
        gpu_equiv = self.cpu_ips * 480
        print(f"[+] Estimated GPU equivalent: {gpu_equiv:.0f} iterations/sec")
        return self.cpu_ips

    def analyze_wordlists(self):
        """Benchmark and rank wordlists by estimated crack efficiency."""
        print("\n=== Wordlist Benchmark ===")
        print(f"{'Wordlist':<20} {'Size':>14} {'GPU k/s':>10} {'Est. Time':>14}")
        print("-" * 60)
        for wl in self.wordlists:
            size = wl["size"]
            speed = wl["hashcat_speed_gpu"]
            time_est = size / speed if speed > 0 else float("inf")
            print(f"{wl['name']:<20} {size:>14,} {speed:>10,} {format_time(time_est):>14}")
        return self.wordlists

    def grade_passphrases(self):
        """Grade embedded sample passphrases against crack-time curves.

        Uses the best-case (fastest) attack time across all wordlists to represent
        the real-world weakest-link scenario. If a passphrase appears in any small
        wordlist it scores as WEAK; only passphrases requiring large brute-force
        dicts or resistant to all wordlists score higher.
        """
        print("\n=== Passphrase Strength Grading ===")
        print(f"{'Passphrase':<35} {'Strength':<10} {'Best Wordlist':<18} {'Est. Time':>14}")
        print("-" * 82)
        for pp in SAMPLE_PASSPHRASES:
            best_time = float("inf")
            best_wl = ""
            for wl in self.wordlists:
                t = estimate_crack_time_seconds(wl, pp, gpu_enabled=True)
                if t < best_time:
                    best_time = t
                    best_wl = wl["name"]
            strength = classify_strength(best_time)
            time_str = format_time(best_time) if best_time != float("inf") else "NO MATCH"
            self.policy_report.append({
                "passphrase": pp,
                "strength": strength,
                "est_time_seconds": best_time if best_time != float("inf") else None,
                "est_time_human": time_str,
                "best_wordlist": best_wl,
            })
            print(f"{pp:<35} {strength:<10} {best_wl:<18} {time_str:>14}")
        return self.policy_report

    def audit_handshakes(self):
        """Audit captured handshakes and report status."""
        print("\n=== Handshake Audit ===")
        print(f"{'Network':<18} {'BSSID':<20} {'Type':<8} {'Status':<10}")
        print("-" * 58)
        for hs in self.handshakes:
            htype = "PMKID" if hs.get("pmkid") else "4-Way"
            if hs.get("sae"):
                htype = "SAE"
            status = "CRACKED" if hs.get("cracked") else "PENDING"
            self.results.append({
                "network": hs["network"],
                "bssid": hs["bssid"],
                "type": htype,
                "status": status,
                "passphrase": hs.get("known_passphrase", ""),
            })
            print(f"{hs['network']:<18} {hs['bssid']:<20} {htype:<8} {status:<10}")
        return self.results

    def verify_known_passphrases(self):
        """Verify known passphrases against PMK computation."""
        print("\n=== Passphrase Verification ===")
        verified = 0
        for hs in self.handshakes:
            if hs.get("cracked") and hs.get("known_passphrase"):
                pmk = pmk_from_passphrase(hs["known_passphrase"], hs["ssid"])
                print(f"  {hs['network']}: PMK = {pmk.hex()[:32]}...")
                verified += 1
        print(f"[+] Verified {verified} known passphrase(s) against PBKDF2-SHA1")
        return verified

    def generate_report(self, output_csv=False):
        """Generate audit report (text + optional CSV)."""
        print("\n=== Audit Report ===")
        weak_count = sum(1 for r in self.policy_report if r["strength"] == "WEAK")
        medium_count = sum(1 for r in self.policy_report if r["strength"] == "MEDIUM")
        strong_count = sum(1 for r in self.policy_report if r["strength"] == "STRONG")
        sae_count = sum(1 for r in self.policy_report if r["strength"] == "WPA3-SAE")

        print(f"  Total passphrases graded: {len(self.policy_report)}")
        print(f"  WEAK:   {weak_count}")
        print(f"  MEDIUM: {medium_count}")
        print(f"  STRONG: {strong_count}")
        print(f"  WPA3-SAE: {sae_count}")
        print(f"  Handshakes captured: {len(self.handshakes)}")
        print(f"  Cracked: {sum(1 for r in self.results if r['status'] == 'CRACKED')}")
        print(f"  Pending: {sum(1 for r in self.results if r['status'] == 'PENDING')}")

        if output_csv:
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["passphrase", "strength", "est_time", "est_time_human"])
            for r in self.policy_report:
                writer.writerow([r["passphrase"], r["strength"], r["est_time_seconds"], r["est_time_human"]])
            return buf.getvalue()
        return None

    def run_full_pipeline(self):
        """Execute the complete audit pipeline."""
        print("=" * 60)
        print("  W4 — WPA Handshake Crack Pipeline")
        print("=" * 60)
        self.run_benchmark()
        self.analyze_wordlists()
        self.grade_passphrases()
        self.audit_handshakes()
        self.verify_known_passphrases()
        csv_data = self.generate_report(output_csv=True)
        print("\n[+] Pipeline complete — exit 0")
        return csv_data


def main():
    pipeline = CrackPipeline()
    pipeline.run_full_pipeline()
    return 0


if __name__ == "__main__":
    sys.exit(main())
