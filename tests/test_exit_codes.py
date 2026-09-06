"""Exit-code mapping contract (see firmware/errors.py)."""

from firmware import errors
from firmware.crack_pipeline import main
import tempfile
import unittest
from pathlib import Path

import yaml


class ExitCodeMappingTests(unittest.TestCase):
    def test_named_constants(self):
        self.assertEqual(errors.EXIT_OK, 0)
        self.assertEqual(errors.EXIT_CONFIG, 1)
        self.assertEqual(errors.EXIT_TOOL, 2)
        self.assertEqual(errors.EXIT_NO_HANDSHAKE, 3)

    def test_exception_to_code_mapping(self):
        self.assertEqual(errors.ConfigError("c").exit_code, 1)
        self.assertEqual(errors.OperationError("o").exit_code, 1)
        self.assertEqual(errors.ToolMissing("t").exit_code, 2)
        self.assertEqual(errors.NoHandshake("n").exit_code, 3)

    def test_all_pipeline_errors_have_a_clean_code(self):
        for cls in (errors.ConfigError, errors.OperationError,
                    errors.ToolMissing, errors.NoHandshake):
            self.assertIn(cls.exit_code, {0, 1, 2, 3})


class MainExitCodeTests(unittest.TestCase):
    def test_missing_config_is_exit_1(self):
        with tempfile.TemporaryDirectory() as d:
            code = main(["-c", str(Path(d) / "missing.yaml"), "selftest"])
        self.assertEqual(code, errors.EXIT_CONFIG)

    def test_missing_report_db_is_exit_1(self):
        with tempfile.TemporaryDirectory() as d:
            code = main(["--dry-run", "report", str(Path(d) / "none.db")])
        self.assertEqual(code, errors.EXIT_CONFIG)

    def test_selftest_offline_exits_0(self):
        with tempfile.TemporaryDirectory() as d:
            cfg_dir = Path(d)
            (cfg_dir / "crack.yaml").write_text(
                yaml.safe_dump(
                    {
                        "tools": {
                            "hcxdumptool": "nonexistent-hcxdumptool-xyz",
                            "hcxpcapngtool": "nonexistent-hcxpcapngtool-xyz",
                            "hashcat": "nonexistent-hashcat-xyz",
                            "aircrack": "nonexistent-aircrack-xyz",
                        },
                        "db": {"path": str(cfg_dir / "logs" / "r.db"),
                               "jsonl": str(cfg_dir / "logs" / "r.jsonl")},
                        "wordlist": str(cfg_dir / "no-wordlist.txt"),
                        "workdir": str(cfg_dir / "logs" / "work"),
                    }
                ),
                encoding="utf-8",
            )
            code = main(["-c", str(cfg_dir / "crack.yaml"),
                         "--log-file", str(cfg_dir / "logs" / "crack.log"),
                         "selftest"])
        self.assertEqual(code, errors.EXIT_OK)


if __name__ == "__main__":
    unittest.main()