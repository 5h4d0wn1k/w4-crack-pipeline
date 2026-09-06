#!/usr/bin/env python3
"""W4 -- WPA/PMKID cracking pipeline CLI (production).

Own-lab traffic only. CLI:  crack audit|pmkid|wpa|batch|report|selftest

The first implementation's pure-Python helpers (pbkdf2_sha1,
pmk_from_passphrase, classify_strength, format_time) are preserved below so
legacy programmatic imports keep working; all cracking now drives real
external tooling (hcxpcapngtool / aircrack-ng / hashcat) via subprocess.
"""

import argparse
import hashlib
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .errors import EXIT_CONFIG, EXIT_OK, ConfigError, NoHandshake, PipelineError
from .pipeline import (
    Context,
    Pipeline,
    STATUS_CRACKED,
    STATUS_DRY_RUN,
    build_detect_command,
    capture_authorization,
    detect_capture,
    no_handshake_message,
    print_plan,
    require_detector,
)
from .report import ResultStore, format_duration_ms
from .selftest import run_selftest
from .toolchain import Toolchain

log = logging.getLogger("w4.cli")


# --------------------------------------------------------------------------
# legacy pure-Python helpers (kept for backward compatibility)
# --------------------------------------------------------------------------

def pbkdf2_sha1(password, ssid, iterations=4096, dklen=32):
    """PBKDF2-HMAC-SHA1 key derivation per WPA/WPA2 spec."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    if isinstance(ssid, str):
        ssid = ssid.encode("utf-8")
    return hashlib.pbkdf2_hmac("sha1", password, ssid, iterations, dklen)


def pmk_from_passphrase(passphrase, ssid):
    return pbkdf2_sha1(passphrase, ssid, 4096, 32)


def classify_strength(seconds):
    """Back-compat strength rubric used by the original offline demo."""
    if seconds == float("inf") or seconds > 31536000:
        return "WPA3-SAE"
    if seconds < 1:
        return "WEAK"
    if seconds < 86400:
        return "MEDIUM"
    return "STRONG"


def format_time(seconds):
    """Back-compat human duration formatter."""
    if seconds < 0.001:
        return "< 1ms"
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{seconds/60:.1f}min"
    if seconds < 86400:
        return f"{seconds/3600:.1f}hrs"
    if seconds < 2592000:
        return f"{seconds/86400:.1f}days"
    if seconds < 31536000:
        return f"{seconds/2592000:.1f}months"
    return f"{seconds/31536000:.1f}years"


# --------------------------------------------------------------------------
# logging
# --------------------------------------------------------------------------

def setup_logging(level_name, log_file):
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(getattr(logging, (level_name or "INFO").upper(), logging.INFO))
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter("%(levelname)-7s %(name)s: %(message)s"))
    root.addHandler(sh)


# --------------------------------------------------------------------------
# root safety
# --------------------------------------------------------------------------

_ROOT_GUIDANCE = (
    "refusing to run as root. Password-cracking runs (hashcat, aircrack-ng) must "
    "never run with elevated privileges, and root-owned capture files defeat the "
    "own-lab authorization check.\n"
    "Run everything as an unprivileged user instead, e.g.:\n"
    "    sudo useradd -m w4lab && sudo -u w4lab crack selftest\n"
    "    sudo -u w4lab crack audit  /home/w4lab/captures/lab-ap.cap\n"
    "    sudo -u w4lab crack wpa    /home/w4lab/captures/lab-ap.cap\n"
    "If your own capture is root-owned, chown it to the unprivileged account "
    "first (chown w4lab: ...) so the authorization check passes."
)


def refuse_root():
    if os.geteuid() == 0:
        raise ConfigError(_ROOT_GUIDANCE)


# --------------------------------------------------------------------------
# subcommand implementations
# --------------------------------------------------------------------------

def summarize(record, kind):
    status = record.get("status")
    if status == STATUS_DRY_RUN:
        return f"{kind}: dry-run -- no commands executed (sequence printed above)"
    extra = f" -> {record['passphrase']!r}" if record.get("passphrase") else ""
    ttc = format_duration_ms(record.get("time_to_crack_ms"))
    kps = record.get("keys_per_sec") or 0.0
    return (
        f"{kind}: {record.get('input')}: {status}{extra} "
        f"time={ttc} keys/s={kps:.0f}"
    )


def cmd_audit(args, ctx):
    cap = args.capfile
    if not Path(cap).is_file():
        raise ConfigError(f"capture file not found: {cap}")
    how = capture_authorization(cap, ctx.cfg)
    log.info("audit: capture authorized by %s", how)
    if ctx.dry_run:
        commands = []
        for key in ("hcxpcapngtool", "aircrack"):
            commands.append(build_detect_command(cap, ctx.toolchain, key))
        print("--- planned detection commands (dry-run, nothing executed) ---")
        print_plan(commands)
        print("[+] audit dry-run: no commands executed -- exit 0")
        return EXIT_OK
    require_detector(ctx.toolchain)
    det = detect_capture(cap, ctx)
    print(f"capture : {cap}")
    print(f"allow   : {how} (own-lab requirement satisfied)")
    print(f"pmkid   : {det.pmkid_count}")
    print(f"4-way   : {det.handshake_count}")
    if det.ssid:
        print(f"ssid    : {det.ssid}")
    if det.bssid:
        print(f"bssid   : {det.bssid}")
    print(f"kind    : {det.kind}")
    if det.kind == "unknown":
        raise NoHandshake(no_handshake_message(cap))
    print("[+] audit OK: viable handshake/PMKID target present -- exit 0")
    return EXIT_OK


def cmd_crack(args, ctx):
    pipeline = Pipeline(ctx)
    record = pipeline.crack(args.input, args.kind)
    print(summarize(record, args.kind))
    if record.get("status") == STATUS_CRACKED:
        print("[+] passphrase recovered -- recorded to results DB -- exit 0")
    return EXIT_OK


def cmd_batch(args, ctx):
    pipeline = Pipeline(ctx)
    pipeline.batch(args.directory)
    return EXIT_OK


def cmd_report(args, ctx):
    db = args.db
    if not Path(db).is_file():
        raise ConfigError(f"results database not found: {db} (run a pipeline first)")
    read_cfg = {"db": {"path": db, "jsonl": str(Path(db).with_suffix(".jsonl"))}}
    store = ResultStore(read_cfg, dry_run=ctx.dry_run, logger=log)
    rows = store.all()
    stats = store.stats(rows)
    print(f"report for {db}")
    print(f"  attempts         : {stats['total']}")
    print(f"  cracked          : {stats['cracked']}")
    print(f"  not cracked      : {stats['not_cracked']}")
    print(f"  no handshake     : {stats['no_handshake']}")
    print(f"  avg keys/s       : {stats['avg_keys_per_sec']:.0f}")
    if stats["cracked"]:
        print(
            "  time-to-crack    : "
            f"{format_duration_ms(stats['min_time_to_crack_ms'])} - "
            f"{format_duration_ms(stats['max_time_to_crack_ms'])}"
        )
    if stats["passphrases"]:
        print("  passphrases      : " + ", ".join(stats["passphrases"]))
    if ctx.dry_run:
        print("[+] report dry-run: file rendering skipped -- exit 0")
        return EXIT_OK
    json_path = Path(args.json or "logs/report.json")
    md_path = Path(args.markdown or "logs/report.md")
    stats = store.write_report(rows, json_path, md_path)
    print(f"[+] wrote {json_path}")
    print(f"[+] wrote {md_path}")
    return EXIT_OK


# --------------------------------------------------------------------------
# argument parser
# --------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="crack",
        description="W4 -- WPA/WPA2/PMKID password-audit cracking pipeline "
                    "(OWN-lab captured traffic only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exit codes: 0 ok | 1 config/arg error | 2 missing tool | 3 no "
            "handshake found\n"
            "safety: refuses to run as root; --dry-run prints commands without "
            "executing anything."
        ),
    )
    parser.add_argument("--version", action="version", version=f"crack {__version__}")
    parser.add_argument("-c", "--config", default=None, help="path to config YAML "
                        "(default config/crack.yaml, or $W4_CRACK_CONFIG)")
    parser.add_argument("-w", "--wordlist", default=None,
                        help="override wordlist path (default from config)")
    parser.add_argument("-r", "--rules", default=None,
                        help="override best64 rules file path")
    parser.add_argument("--db", default=None, help="override results DB path")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the exact command sequence WITHOUT executing "
                             "anything (safety-first default posture)")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--log-file", default="logs/crack.log",
                        help="log file (default logs/crack.log)")

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_audit = sub.add_parser("audit", help="smoke-test a capture: handshake or PMKID present?")
    p_audit.add_argument("capfile")

    p_pmkid = sub.add_parser("pmkid", help="crack a PMKID (capture file or hc22000/hash file)")
    p_pmkid.add_argument("input")
    p_pmkid.set_defaults(kind="pmkid")

    p_wpa = sub.add_parser("wpa", help="crack a WPA handshake capture")
    p_wpa.add_argument("input")
    p_wpa.set_defaults(kind="wpa")

    p_batch = sub.add_parser("batch", help="process every *.cap/*.pcap(ng) in a directory")
    p_batch.add_argument("directory")

    p_report = sub.add_parser("report", help="render a JSON + Markdown report from the results DB")
    p_report.add_argument("db")
    p_report.add_argument("--json", default=None, help="JSON report path (default logs/report.json)")
    p_report.add_argument("--markdown", default=None,
                          help="Markdown report path (default logs/report.md)")

    sub.add_parser("selftest", help="offline self-test: validates config, tools, and "
                                    "(if present) a tiny known-password WPA crack")

    return parser


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def dispatch(args, ctx):
    log.info("command: %s argv=%s", args.cmd, [a for a in sys.argv[1:]])
    if args.cmd == "audit":
        return cmd_audit(args, ctx)
    if args.cmd in ("wpa", "pmkid"):
        return cmd_crack(args, ctx)
    if args.cmd == "batch":
        refuse_root()
        return cmd_batch(args, ctx)
    if args.cmd == "report":
        return cmd_report(args, ctx)
    if args.cmd == "selftest":
        refuse_root()
        return run_selftest(ctx)
    raise ConfigError(f"unknown command: {args.cmd}")


def main(argv=None):
    args = build_parser().parse_args(argv)
    setup_logging(args.log_level, args.log_file)

    try:
        cfg = load_config(args.config)
        if args.wordlist:
            cfg["wordlist"] = args.wordlist
        if args.rules:
            cfg["rules"] = args.rules
        if args.db:
            cfg["db"]["path"] = args.db
        cfg["_source"] = args.config or os.environ.get("W4_CRACK_CONFIG") or "config/crack.yaml"

        toolchain = Toolchain(cfg, dry_run=args.dry_run, logger=log)
        store = ResultStore(cfg, dry_run=args.dry_run, logger=log)
        ctx = Context(cfg=cfg, toolchain=toolchain, store=store, logger=log)

        if args.cmd in ("audit", "wpa", "pmkid"):
            refuse_root()

        return dispatch(args, ctx)

    except PipelineError as exc:
        log.error("%s", exc.message)
        print(f"[!] {exc.message}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 -- final safety net
        logging.getLogger("w4.cli").exception("unexpected failure")
        print(f"[!] unexpected failure: {exc} (details in logs/crack.log)", file=sys.stderr)
        return EXIT_CONFIG


if __name__ == "__main__":
    sys.exit(main())