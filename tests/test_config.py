from firmware.config import deep_merge, load_config, validate_config, BASE_CFG, check_wordlist
from firmware.errors import ConfigError, PipelineError
import tempfile
import unittest
from pathlib import Path

import yaml


def _base():
    return deep_merge(BASE_CFG, {})


class ConfigValidationTests(unittest.TestCase):
    def test_defaults_are_valid(self):
        self.assertEqual(validate_config(_base()), [])

    def test_bad_wordlist_type_reported(self):
        cfg = _base()
        cfg["wordlist"] = 123
        problems = validate_config(cfg)
        self.assertTrue(any("wordlist" in p for p in problems))
        cfg["wordlist"] = "rockyou.txt"
        cfg["tools"] = "not-a-mapping"
        self.assertTrue(any("tools" in p for p in validate_config(cfg)))

    def test_bad_hashcat_workload_reported(self):
        cfg = deep_merge(BASE_CFG, {"hashcat": {"workload": 9}})
        self.assertTrue(any("workload" in p for p in validate_config(cfg)))

    def test_load_config_raises_on_explicit_missing(self):
        with tempfile.TemporaryDirectory() as d:
            missing = Path(d) / "no.yaml"
            with self.assertRaises(ConfigError):
                load_config(str(missing))

    def test_load_config_from_yaml_resolves_paths(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            (base / "crack.yaml").write_text(
                yaml.safe_dump({"wordlist": "lists/my.txt", "hashcat": {"potfile": "logs/x.pot"}}),
                encoding="utf-8",
            )
            cfg = load_config(str(base / "crack.yaml"))
            self.assertTrue(str(cfg["wordlist"]).endswith("lists/my.txt"))
            self.assertTrue(Path(cfg["wordlist"]).is_absolute())
            self.assertTrue(Path(cfg["hashcat"]["potfile"]).is_absolute())

    def test_invalid_yaml_raises(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.yaml"
            bad.write_text("wordlist: [unclosed\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(str(bad))


class WordlistCheckTests(unittest.TestCase):
    def test_missing_wordlist_raises(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ConfigError) as cm:
                check_wordlist(str(Path(d) / "nope.txt"))
            self.assertIn("wordlist", cm.exception.message.lower())

    def test_empty_wordlist_raises(self):
        with tempfile.TemporaryDirectory() as d:
            wl = Path(d) / "empty.txt"
            wl.write_text("", encoding="utf-8")
            with self.assertRaises(ConfigError):
                check_wordlist(str(wl))

    def test_readable_wordlist_ok(self):
        with tempfile.TemporaryDirectory() as d:
            wl = Path(d) / "words.txt"
            wl.write_text("password\nwinter2020\n", encoding="utf-8")
            st = check_wordlist(str(wl))
            self.assertEqual(st["size_bytes"], wl.stat().st_size)
            self.assertIs(PipelineError, ConfigError.__mro__[1])


if __name__ == "__main__":
    unittest.main()