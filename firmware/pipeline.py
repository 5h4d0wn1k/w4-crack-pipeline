"""Pipeline stages: detect -> convert -> wordlist precheck -> hashcat -> parse -> store.

Flow (one crack attempt):

  1. detect        -- is there a WPA handshake or a PMKID in this capture?
  2. convert       -- hcxpcapngtool -o <file>.hc22000 <cap>  (hcxtools hash format)
  3. wordlist      -- precheck: exists, readable, non-empty, size logged
  4. hashcat       -- mode 22000, attack 0 (straight), best64 rules, progress streamed
  5. parse         -- potfile -> recovered passphrase(s)
  6. store         -- SQLite + JSONL via firmware.report.ResultStore
"""

import logging
import os
import pwd
import re
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import labspec
from .config import check_rules, check_wordlist
from .errors import ConfigError, NoHandshake, OperationError, ToolMissing
from .report import ResultStore, utc_now
from .toolchain import CommandSpec, Toolchain

_LOG = logging.getLogger("w4.pipeline")

_MAC_RE = re.compile(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", re.IGNORECASE)


@dataclass
class Detection:
    kind: str  # "pmkid" | "handshake" | "unknown"
    pmkid_count: int = 0
    handshake_count: int = 0
    ssid: Optional[str] = None
    bssid: Optional[str] = None


@dataclass
class Context:
    """Everything a pipeline run needs, handed down from the CLI."""

    cfg: dict
    toolchain: Toolchain
    store: ResultStore
    logger: logging.Logger

    @property
    def dry_run(self):
        return self.toolchain.dry_run


# ---------------------------------------------------------------------------
# capture sanity
# ---------------------------------------------------------------------------

def capture_authorization(cap, cfg):
    """Return how the capture is authorized: 'owner' or 'lab-marker', else raise.

    Spec: strictly require the capture to be owned by us OR marked lab.
    """
    st = os.stat(cap)
    owned = st.st_uid == os.geteuid()
    owner_name = pwd.getpwuid(st.st_uid).pw_name
    allowed = cfg.get("capture", {}).get("allowed_owner")
    if not owned and allowed is not None:
        allowed_str = str(allowed)
        owned = allowed_str == str(st.st_uid) or allowed_str == owner_name
    if owned:
        return "owner"
    marker = str(cfg.get("capture", {}).get("marker") or labspec.LAB_MARKER).lower()
    if marker in Path(cap).name.lower():
        return "lab-marker"
    raise ConfigError(
        f"capture not authorized: {cap} is owned by uid {st.st_uid} ({owner_name}) "
        f"and its filename contains no '{marker}' lab marker. "
        "Only own-lab captures may be processed; rename it e.g. "
        f"lab-ap-<something>.cap or add a trusted owner under 'capture.allowed_owner' "
        "in config/crack.yaml."
    )


# ---------------------------------------------------------------------------
# detection
# ---------------------------------------------------------------------------

def parse_hcxpcapngtool_summary(text):
    """Tolerant parser for `hcxpcapngtool --show-summary <cap>` output."""
    pmkid = handshake = 0

    def count(pattern):
        m = re.findall(pattern, text, re.IGNORECASE)
        return sum(int(x) for x in m) if m else 0

    pmkid = count(r"contains\s+(\d+)\s+PMKID") or count(r"(\d+)\s+PMKID\(s\)")
    handshake = count(r"contains\s+(\d+)\s+handshake") or count(r"(\d+)\s+handshake\(s\)")

    ssid = bssid = None
    m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s*\(([^)]+)\)", text)
    if m:
        bssid = m.group(1).lower()
        ssid = m.group(2)

    kind = "pmkid" if pmkid > 0 else "handshake" if handshake > 0 else "unknown"
    return Detection(kind, pmkid, handshake, ssid, bssid)


def parse_aircrack_summary(text):
    """Parser for `aircrack-ng <cap>` analysis output (WPA (N handshake) lines)."""
    handshake = 0
    for m in re.finditer(r"WPA\s*\(\s*(\d+)\s*handshake", text, re.IGNORECASE):
        handshake = max(handshake, int(m.group(1)))
    bssid = ssid = None
    for line in text.splitlines():
        if "WPA" in line and re.search(r"handshake", line, re.IGNORECASE):
            mac = _MAC_RE.search(line)
            if mac:
                bssid = mac.group(1).lower()
                break
    kind = "handshake" if handshake > 0 else "unknown"
    return Detection(kind, 0, handshake, ssid, bssid)


def require_detector(toolchain):
    """At least one handshake/PMKID detector must be installed."""
    toolchain.require_any(("hcxpcapngtool", "aircrack"))


def detect_capture(cap, ctx: Context) -> Detection:
    """Run detection (hcxpcapngtool preferred, aircrack-ng fallback)."""
    tc = ctx.toolchain
    if tc.present("hcxpcapngtool"):
        spec = CommandSpec(
            (tc.exe("hcxpcapngtool"), "--show-summary", str(cap)),
            f"detect handshake/PMKID in {Path(cap).name} (hcxpcapngtool)",
            timeout=180,
        )
        res = tc.run(spec)
        det = parse_hcxpcapngtool_summary(res.stdout + res.stderr)
        if det.kind != "unknown":
            ctx.logger.info(
                "detected %s via hcxpcapngtool (pmkid=%s handshake=%s)",
                det.kind, det.pmkid_count, det.handshake_count,
            )
            return det
    if tc.present("aircrack"):
        spec = CommandSpec(
            (tc.exe("aircrack"), str(cap)),
            f"detect handshake in {Path(cap).name} (aircrack-ng)",
            timeout=180,
        )
        res = tc.run(spec)
        det = parse_aircrack_summary(res.stdout + res.stderr)
        if det.kind != "unknown":
            ctx.logger.info("detected %s via aircrack-ng (%s handshake)", det.kind, det.handshake_count)
            return det
    return Detection("unknown")


def no_handshake_message(cap):
    return (
        f"no WPA handshake or PMKID found in {cap} -- nothing to crack (exit 3). "
        "Capture 4-way handshakes with hcxdumptool/airodump-ng against your OWN lab AP, "
        "then re-run. 'crack audit <cap>' explains what a capture contains."
    )


# ---------------------------------------------------------------------------
# progress parsing (hashcat stdout)
# ---------------------------------------------------------------------------

_RE_SPEED = re.compile(r"Speed\.#\d+\s*[.:]+\s*([\d.]+)\s*([kMGTP]?H)/s")
_RE_PROGRESS = re.compile(r"Progress\.{3,}\s*(\d+)\s*/\s*(\d+)\s*\(\s*([\d.]+)%\)")
_RE_ETA = re.compile(r"Time\.?\s*Estimated\.{2,}\s*::?\s*([^\r\n]+)")

_UNIT_MULT = {"": 1.0, "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}


def parse_hashcat_chunk(text):
    """Extract the last speed/progress/ETA seen in a chunk of hashcat output."""
    out = {}
    speeds = list(_RE_SPEED.finditer(text))
    if speeds:
        value, unit = speeds[-1].group(1), speeds[-1].group(2)
        out["speed_hps"] = float(value) * _UNIT_MULT.get(unit or "", 1.0)
    progress = list(_RE_PROGRESS.finditer(text))
    if progress:
        m = progress[-1]
        out["tested"] = int(m.group(1))
        out["total"] = int(m.group(2))
        out["pct"] = float(m.group(3))
    eta = list(_RE_ETA.finditer(text))
    if eta:
        out["eta"] = eta[-1].group(1).strip()
    return out or None


# ---------------------------------------------------------------------------
# command building (pure, used by --dry-run AND tested directly)
# ---------------------------------------------------------------------------

def build_detect_command(cap, toolchain, key):
    if key == "hcxpcapngtool":
        return CommandSpec(
            (toolchain.exe("hcxpcapngtool"), "--show-summary", str(cap)),
            f"detect handshake/PMKID in {Path(cap).name} (hcxpcapngtool)",
            timeout=180,
        )
    return CommandSpec(
        (toolchain.exe("aircrack"), str(cap)),
        f"detect handshake in {Path(cap).name} (aircrack-ng)",
        timeout=180,
    )


def build_convert_command(cap, out_path, toolchain):
    return CommandSpec(
        (toolchain.exe("hcxpcapngtool"), "-o", str(out_path), str(cap)),
        f"convert {Path(cap).name} -> {out_path.name} (hcxpcapngtool, hc22000)",
        timeout=900,
    )


def build_hashcat_command(hash_file, wordlist, cfg, toolchain, potfile, rules_ok):
    hc = cfg["hashcat"]
    argv = [
        toolchain.exe("hashcat"),
        "-m", str(hc["mode"]),
        "-a", "0",
        "-w", str(hc["workload"]),
        "--potfile-path", potfile,
        "--status",
        "--status-timer", str(hc.get("status_timer", 5)),
    ]
    if hc.get("devices"):
        argv += ["-D", str(hc["devices"])]
    if rules_ok:
        argv += ["-r", cfg["rules"]]
    argv += [str(flag) for flag in hc.get("extra", []) if flag]
    argv += [str(hash_file), str(wordlist)]
    return CommandSpec(
        tuple(argv),
        "crack (hashcat mode 22000, straight + best64 rules)",
        timeout=7200,
    )


def plan_command_sequence(cap, cfg, toolchain, out_hash, potfile, rules_ok):
    """Assemble the exact commands for a capture crack (dry-run / preview)."""
    commands = []
    if toolchain.present("hcxpcapngtool"):
        commands.append(build_detect_command(cap, toolchain, "hcxpcapngtool"))
    else:
        commands.append(
            CommandSpec(
                ("hcxpcapngtool", "--show-summary", str(cap)),
                "detect handshake/PMKID (hcxpcapngtool) -- TOOL NOT INSTALLED",
                timeout=180,
            )
        )
    if toolchain.present("aircrack"):
        commands.append(build_detect_command(cap, toolchain, "aircrack"))
    else:
        commands.append(
            CommandSpec(
                ("aircrack-ng", str(cap)),
                "detect handshake (aircrack-ng) -- TOOL NOT INSTALLED",
                timeout=180,
            )
        )
    commands.append(build_convert_command(cap, out_hash, toolchain))
    commands.append(build_hashcat_command(out_hash, cfg["wordlist"], cfg, toolchain, potfile, rules_ok))
    return commands


def print_plan(command_list):
    total = len(command_list)
    for index, spec in enumerate(command_list, start=1):
        print(f"[{index}/{total}] {spec.description}")
        print(f"      $ {spec.shell_join()}")


# ---------------------------------------------------------------------------
# potfile parsing
# ---------------------------------------------------------------------------

def parse_potfile(potfile):
    """Return [(hash, passphrase), ...] recovered by hashcat."""
    result = []
    path = Path(potfile)
    if not path.exists():
        return result
    seen = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        hash_part, password = line.split(":", 1)
        if hash_part in seen:
            continue
        seen.add(hash_part)
        result.append((hash_part, password))
    return result


# ---------------------------------------------------------------------------
# pipeline orchestration
# ---------------------------------------------------------------------------

STATUS_CRACKED = "CRACKED"
STATUS_NOT_CRACKED = "NOT_CRACKED"
STATUS_NO_HANDSHAKE = "NO_HANDSHAKE"
STATUS_DRY_RUN = "DRY_RUN"


class Pipeline:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.log = ctx.logger

    # internal helpers ------------------------------------------------------

    def _work_path(self, name):
        return Path(self.cfg["workdir"]) / name

    def _ensure_workdir(self):
        workdir = Path(self.cfg["workdir"])
        workdir.mkdir(parents=True, exist_ok=True)
        return workdir / name

    def _precheck_wordlist(self):
        st = check_wordlist(self.cfg["wordlist"])
        self.log.info(
            "wordlist precheck OK: %s (%s bytes)", st["path"], st["size_bytes"],
        )
        return st

    def _rules_ok(self):
        _, ok = check_rules(self.cfg["rules"])
        return ok

    def _hashcat_crack(self, hash_file, status, template_record):
        """Stages 4-5: run hashcat, stream progress, parse the potfile."""
        cfg = self.cfg
        tc = self.ctx.toolchain
        potfile = cfg["hashcat"]["potfile"]
        rules_ok = self._rules_ok()

        if self.ctx.dry_run:
            self.log.info("dry-run: skipping hashcat execution; sequence printed above")
            return status, None, {}, 0

        tc.require(("hashcat",))
        spec = build_hashcat_command(hash_file, cfg["wordlist"], cfg, tc, potfile, rules_ok)
        started = time.monotonic()
        speed_ref = {"hps": 0.0}
        last_pct = [-1.0]

        def on_line(raw):
            chunk = parse_hashcat_chunk(raw)
            if not chunk:
                return
            if chunk.get("speed_hps"):
                speed_ref["hps"] = chunk["speed_hps"]
            pct = chunk.get("pct")
            if pct is not None:
                if pct - last_pct[0] >= 2.0 or pct >= 100.0:
                    last_pct[0] = pct
                    self.log.info(
                        "hashcat ~%.1f%%  speed=%.0f keys/s  eta=%s",
                        pct, speed_ref["hps"], chunk.get("eta", "n/a"),
                    )

        res = tc.run(spec, on_line=on_line)
        elapsed_ms = int((time.monotonic() - started) * 1000)

        if res.timed_out:
            self.log.error("hashcat hit the %ss timeout; aborting this attempt", spec.timeout)
        elif not res.executed:
            return status, None, {}, elapsed_ms

        found = parse_potfile(potfile)
        if found:
            password = found[0][1]
            self.log.info("CRACKED: passphrase recovered from potfile")
            record = dict(template_record)
            record["status"] = STATUS_CRACKED
            record["passphrase"] = password
            record["keys_per_sec"] = speed_ref["hps"]
            record["time_to_crack_ms"] = elapsed_ms
            record["candidates_tested"] = None
            return STATUS_CRACKED, password, record, elapsed_ms

        record = dict(template_record)
        record["status"] = STATUS_NOT_CRACKED
        record["keys_per_sec"] = speed_ref["hps"]
        record["time_to_crack_ms"] = elapsed_ms
        return STATUS_NOT_CRACKED, None, record, elapsed_ms

    def _store(self, record):
        self.ctx.store.store(record)

    # capture pipeline (wpa / pmkid-from-capture) ----------------------------

    def crack_capture(self, cap, kind="wpa"):
        cfg = self.cfg
        tc = self.ctx.toolchain
        cap = str(cap)
        if not Path(cap).is_file():
            raise ConfigError(f"capture file not found: {cap}")

        if not self.ctx.dry_run:
            how = capture_authorization(cap, cfg)
            self.log.info("capture authorized by %s: %s", how, cap)
            self._precheck_wordlist()

        stem = Path(cap).stem
        out_hash = self._work_path(f"{stem}.hc22000")
        potfile = cfg["hashcat"]["potfile"]

        template = {
            "ts": utc_now(),
            "input": cap,
            "kind": kind,
            "bssid": None,
            "ssid": None,
            "mode": cfg["hashcat"]["mode"],
            "status": "",
            "passphrase": None,
            "keys_per_sec": None,
            "time_to_crack_ms": None,
            "candidates_tested": None,
            "notes": "",
        }

        if self.ctx.dry_run:
            rules_ok = Path(cfg["rules"]).is_file()
            print("--- planned command sequence (dry-run, nothing executed) ---")
            print_plan(plan_command_sequence(cap, cfg, tc, out_hash, potfile, rules_ok))
            if not Path(cfg["wordlist"]).is_file():
                self.log.warning("dry-run: wordlist %s not found (would fail in a real run)", cfg["wordlist"])
            template["status"] = STATUS_DRY_RUN
            self.log.info("dry-run: no commands executed for %s", cap)
            return template

        require_detector(tc)
        det = detect_capture(cap, self.ctx)
        if det.kind == "unknown":
            raise NoHandshake(no_handshake_message(cap))
        template["bssid"] = det.bssid
        template["ssid"] = det.ssid
        template["notes"] = f"detected={det.kind} pmkid={det.pmkid_count} handshake={det.handshake_count}"

        tc.require(("hcxpcapngtool",))
        self._ensure_workdir()
        convert_spec = build_convert_command(cap, out_hash, tc)
        res = tc.run(convert_spec)
        if not res.executed or res.timed_out or not out_hash.exists():
            raise OperationError(
                f"hcxpcapngtool did not produce {out_hash} for {cap} "
                f"(exit {res.returncode}). Corrupt or unreadable capture?"
            )
        self.log.info("converted %s -> %s (%s bytes)", cap, out_hash, out_hash.stat().st_size)

        status, password, record, _ = self._hashcat_crack(out_hash, STATUS_NOT_CRACKED, template)
        record["bssid"] = det.bssid
        record["ssid"] = det.ssid
        self._store(record)
        return record

    # hash-file / pmkid pipeline ---------------------------------------------

    def crack_hash_file(self, hash_file, kind="pmkid"):
        cfg = self.cfg
        hash_file = str(hash_file)
        if not Path(hash_file).is_file():
            raise ConfigError(f"hash file not found: {hash_file}")

        if not self.ctx.dry_run:
            self._precheck_wordlist()

        potfile = cfg["hashcat"]["potfile"]
        template = {
            "ts": utc_now(),
            "input": hash_file,
            "kind": kind,
            "bssid": None,
            "ssid": None,
            "mode": cfg["hashcat"]["mode"],
            "status": "",
            "passphrase": None,
            "keys_per_sec": None,
            "time_to_crack_ms": None,
            "candidates_tested": None,
            "notes": "input is a pre-converted hash file",
        }

        if self.ctx.dry_run:
            rules_ok = Path(cfg["rules"]).is_file()
            spec = build_hashcat_command(hash_file, cfg["wordlist"], cfg,
                                         self.ctx.toolchain, potfile, rules_ok)
            print("--- planned command sequence (dry-run, nothing executed) ---")
            print_plan([spec])
            template["status"] = STATUS_DRY_RUN
            return template

        status, password, record, _ = self._hashcat_crack(hash_file, STATUS_NOT_CRACKED, template)
        self._store(record)
        return record

    def crack(self, target, kind):
        if target.lower().endswith(labspec.CAPTURE_EXTS):
            return self.crack_capture(target, kind=kind)
        return self.crack_hash_file(target, kind=kind)

    # batch -------------------------------------------------------------------

    def batch(self, directory):
        directory = str(directory)
        root = Path(directory)
        if not root.is_dir():
            raise ConfigError(f"batch directory not found: {directory}")
        caps = sorted(
            p for p in root.iterdir()
            if p.is_file() and p.name.lower().endswith(labspec.CAPTURE_EXTS)
        )
        if not caps:
            raise ConfigError(
                f"no capture files (*.cap *.pcap *.pcapng) found under {directory}"
            )
        self._precheck_wordlist()
        attempts = 0
        seen_no_handshake = 0
        print(f"--- batch: {len(caps)} capture(s) from {directory} ---")
        for cap in caps:
            try:
                record = self.crack_capture(str(cap), kind="wpa")
                attempts += 1
                mark = "CRACKED" if record.get("status") == STATUS_CRACKED else (
                    "not-cracked" if record.get("status") == STATUS_NOT_CRACKED else "dry-run"
                )
                print(f"  {cap.name:40s} {mark:12s} {record.get('passphrase') or ''}")
            except NoHandshake as exc:
                seen_no_handshake += 1
                self.ctx.store.store({
                    "ts": utc_now(),
                    "input": str(cap),
                    "kind": "wpa",
                    "status": STATUS_NO_HANDSHAKE,
                    "notes": exc.message,
                })
                print(f"  {cap.name:40s} no-handshake   skipped")
            except OperationError as exc:
                self.log.warning("stage failed for %s: %s", cap, exc)
                print(f"  {cap.name:40s} failed        {exc}")
        if attempts == 0 and seen_no_handshake == len(caps) and seen_no_handshake:
            raise NoHandshake(
                f"none of the {len(caps)} captures in {directory} contained a "
                "WPA handshake/PMKID (exit 3)"
            )
        print(f"--- batch done: cracked-so-far logged to logs/results.db ---")
        return STATUS_CRACKED if attempts else STATUS_DRY_RUN