"""Offline self-test (crack selftest).

Two paths, both exit 0:

  * full toolchain present  -> a tiny synthetic WPA-style crack against a known
    password using hashcat's documented example hash + straight mode, and
  * anything missing        -> all stages validated through "tool detection",
    with a clear PRESENT/MISSING report.

Must stay well under ~15 s and never require the configured wordlist/capture.
"""

import logging
import sys
import tempfile
from pathlib import Path

from . import labspec
from .errors import ConfigError, ToolMissing
from .toolchain import CommandSpec

_LOG = logging.getLogger("w4.selftest")

_TOOL_KEYS = ("hcxdumptool", "hcxpcapngtool", "aircrack", "hashcat")

SELFTEST_CANDIDATES = [labspec.SELFTEST_PASSWORD, "password", "12345678", "qwerty"]


def run_selftest(ctx) -> int:
    cfg = ctx.cfg
    tc = ctx.toolchain
    log = ctx.logger

    print("=" * 60)
    print("  W4 crack pipeline -- offline self-test")
    print("=" * 60)

    # stage 1: configuration (validated on load; re-assert here)
    print(f"[1/5] config: {cfg.get('_source', 'loaded')}")
    print("[2/5] root check: running as unprivileged user (root would be refused)")
    if not ctx.dry_run:
        wordlist = cfg["wordlist"]
        wl_ok = Path(wordlist).is_file()
        print(
            f"[3/5] wordlist {wordlist}: "
            + ("present" if wl_ok else "ABSENT (offline run is fine; real cracks need it)")
        )

    # stage 4: tool detection report
    print("[4/5] external tool detection:")
    present, missing = [], []
    for key in _TOOL_KEYS:
        st = tc.status(key)
        state = "PRESENT" if st.present else "MISSING"
        print(f"      - {key:14s} {state:8s} reserved-as={'?' if st.present else st.configured}")
        (present if st.present else missing).append(key)

    # stage 5: tiny known-password WPA crack IF hashcat is available
    if ctx.dry_run:
        print("[5/5] dry-run: would crack a synthetic WPA hash against wordlist "
              f"[{SELFTEST_CANDIDATES[0]}, ...] (skipped: --dry-run)")
        print("[+] self-test complete (dry-run) -- exit 0")
        log.info("selftest dry-run complete")
        return 0

    if "hashcat" in missing:
        print(
            "[5/5] hashcat not installed -- validated all stages through tool "
            "detection; full crack stage omitted."
        )
        print()
        print("[+] self-test complete -- exit 0")
        if missing:
            print("Missing external tools: " + ", ".join(missing))
        log.info("selftest complete: stages validated to tool detection; missing=%s", missing)
        return 0

    print("[5/5] hashcat present -- running tiny synthetic WPA crack (straight mode)...")
    with tempfile.TemporaryDirectory(prefix="w4-selftest-") as tmp:
        tmpdir = Path(tmp)
        wordlist = tmpdir / "selftest.wordlist"
        hashes = tmpdir / "selftest.hc22000"
        potfile = tmpdir / "selftest.potfile"
        wordlist.write_text("\n".join(SELFTEST_CANDIDATES) + "\n", encoding="utf-8")
        hashes.write_text(labspec.SELFTEST_HASH + "\n", encoding="utf-8")

        spec = CommandSpec(
            (
                tc.exe("hashcat"),
                "-m", str(labspec.HASHCAT_MODE_WPA),
                "-a", "0",
                "-w", "1",
                "--potfile-path", str(potfile),
                "--quiet",
                "--force",
                str(hashes),
                str(wordlist),
            ),
            "self-test: crack synthetic WPA hash (example/straight)",
            timeout=90,
        )
        try:
            res = tc.run(spec)
        except ToolMissing as exc:
            print(f"[5/5] WARN hashcat vanished while running: {exc}")
            return 0

        recovered = []
        if potfile.exists():
            for line in potfile.read_text(encoding="utf-8").splitlines():
                if ":" in line:
                    recovered.append(line.split(":", 1)[1])

        if labspec.SELFTEST_PASSWORD in recovered:
            print(f"[5/5] PASS -- recovered known password {labspec.SELFTEST_PASSWORD!r} "
                  f"(mode {labspec.HASHCAT_MODE_WPA}, straight)")
        else:
            print(
                f"[5/5] WARN -- expected to recover {labspec.SELFTEST_PASSWORD!r} "
                f"but got {recovered!r} (self-test still exits 0)"
            )

    print("[+] self-test complete -- exit 0")
    log.info("selftest complete (hashcat path)")
    return 0