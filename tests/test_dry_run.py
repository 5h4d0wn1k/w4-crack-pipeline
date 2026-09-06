"""Dry-run contract tests: the exact command sequence is built AND nothing is
ever executed -- no subprocess calls, no DB writes, no files created."""

from unittest import mock
from firmware.config import deep_merge, BASE_CFG
from firmware.pipeline import (
    Context,
    Pipeline,
    plan_command_sequence,
    build_convert_command,
    build_hashcat_command,
)
from firmware.report import ResultStore
from firmware.toolchain import CommandSpec, Toolchain
import tempfile
import unittest
from pathlib import Path


def _cfg(base_dir):
    return deep_merge(BASE_CFG, {
        "wordlist": str(base_dir / "wordlist.txt"),
        "rules": str(base_dir / "does-not-exist" / "best64.rule"),
        "db": {"path": str(base_dir / "logs" / "results.db"),
               "jsonl": str(base_dir / "logs" / "results.jsonl")},
        "workdir": str(base_dir / "logs" / "work"),
    })


class ToolchainDryRunTests(unittest.TestCase):
    def test_dry_run_never_invokes_subprocess(self):
        tc = Toolchain({}, dry_run=True)
        with mock.patch("firmware.toolchain.subprocess.Popen",
                        side_effect=AssertionError("Popen must not run in dry-run")), \
             mock.patch("firmware.toolchain.subprocess.run",
                        side_effect=AssertionError("run must not run in dry-run")):
            res = tc.run(CommandSpec(("/bin/echo", "hello"), "say hello"))
        self.assertFalse(res.executed)
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout, "")

    def test_dry_run_accepts_binary_that_does_not_exist(self):
        tc = Toolchain({}, dry_run=True)
        res = tc.run(CommandSpec(("/no/such/binary", "-x"), "phantom"))
        self.assertFalse(res.executed)


class CommandSequenceTests(unittest.TestCase):
    def test_plan_has_full_pipeline_order(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            wl = base / "wordlist.txt"
            wl.write_text("winter2020\n", encoding="utf-8")
            cap = base / "lab-ap.cap"
            cap.write_text("not a real capture", encoding="utf-8")
            cfg = _cfg(base)
            tc = Toolchain(cfg, dry_run=True)
            out = base / "logs" / "work" / "lab-ap.hc22000"
            pot = base / "logs" / "crack.potfile"
            plan = plan_command_sequence(str(cap), cfg, tc, out, pot, rules_ok=False)
            self.assertEqual(len(plan), 4)
            self.assertIn("detect", plan[0].description.lower())
            self.assertIn("detect", plan[1].description.lower())
            self.assertIn("convert", plan[2].description.lower())
            self.assertIn("crack", plan[3].description.lower())
            self.assertEqual(plan[2].argv[0], "hcxpcapngtool")
            self.assertEqual(plan[2].argv[1], "-o")

    def test_hashcat_command_shape(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            cfg = _cfg(base)
            tc = Toolchain(cfg, dry_run=True)
            spec = build_hashcat_command("f.hc22000", "words.txt", cfg, tc,
                                         "logs/crack.potfile", rules_ok=True)
            argv = spec.argv
            self.assertEqual(argv[0], "hashcat")
            self.assertIn("-m", argv)
            self.assertEqual(argv[argv.index("-m") + 1], "22000")
            self.assertIn("-a", argv)
            self.assertEqual(argv[argv.index("-a") + 1], "0")
            self.assertIn("--potfile-path", argv)
            self.assertIn("--status", argv)
            self.assertIn("f.hc22000", argv)
            self.assertIn("words.txt", argv)
            self.assertEqual(argv[-2:], ("f.hc22000", "words.txt"))

    def test_convert_command_shape(self):
        tc = Toolchain({}, dry_run=True)
        spec = build_convert_command("in.cap", Path("out.hc22000"), tc)
        self.assertEqual(spec.argv[:2], ("hcxpcapngtool", "-o"))


class PipelineDryRunTests(unittest.TestCase):
    def test_crack_capture_dry_run_does_nothing_but_plan(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            cap = base / "lab-ap.cap"
            cap.write_text("not a real capture", encoding="utf-8")
            wl = base / "wordlist.txt"
            wl.write_text("winter2020\n", encoding="utf-8")
            cfg = _cfg(base)
            tc = Toolchain(cfg, dry_run=True)
            store = ResultStore(cfg, dry_run=True)
            ctx = Context(cfg=cfg, toolchain=tc, store=store, logger=mock.MagicMock())

            with mock.patch("firmware.toolchain.subprocess.Popen",
                            side_effect=AssertionError("no subprocess in dry-run")):
                record = Pipeline(ctx).crack_capture(str(cap), kind="wpa")

            self.assertEqual(record["status"], "DRY_RUN")
            self.assertEqual(record["input"], str(cap))
            self.assertFalse((base / "logs" / "results.db").exists())
            self.assertFalse((base / "logs" / "work").exists())

    def test_crack_hash_dry_run_returns_dry_run_record(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            hf = base / "my.hc22000"
            hf.write_text("WPA*01*\n", encoding="utf-8")
            wl = base / "wordlist.txt"
            wl.write_text("winter2020\n", encoding="utf-8")
            cfg = _cfg(base)
            store = ResultStore(cfg, dry_run=True)
            ctx = Context(cfg=cfg, toolchain=Toolchain(cfg, dry_run=True),
                          store=store, logger=mock.MagicMock())
            record = Pipeline(ctx).crack_hash_file(str(hf), kind="pmkid")
            self.assertEqual(record["status"], "DRY_RUN")


if __name__ == "__main__":
    unittest.main()