"""Result-database and report rendering tests."""

from firmware.config import deep_merge, BASE_CFG
from firmware.report import ResultStore, format_duration_ms, utc_now
import json
import tempfile
import unittest
from pathlib import Path


def _cfg(base_dir, dry=False):
    cfg = deep_merge(BASE_CFG, {
        "db": {"path": str(base_dir / "logs" / "results.db"),
               "jsonl": str(base_dir / "logs" / "results.jsonl")},
        "workdir": str(base_dir / "logs" / "work"),
    })
    return cfg


def _record(input_, kind="wpa", status="CRACKED", passphrase="winter2020", kps=155000.0, ttc=4200):
    return {
        "ts": utc_now(),
        "input": input_,
        "kind": kind,
        "bssid": "00:11:22:33:44:55",
        "ssid": "lab-ap",
        "mode": 22000,
        "status": status,
        "passphrase": passphrase,
        "keys_per_sec": kps,
        "time_to_crack_ms": ttc,
        "candidates_tested": None,
        "notes": "detected=handshake",
    }


class ResultStoreTests(unittest.TestCase):
    def test_store_and_query_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            store = ResultStore(_cfg(Path(d)), dry_run=False)
            rid = store.store(_record("lab-ap.cap"))
            self.assertIsInstance(rid, int)
            rows = store.all()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["status"], "CRACKED")
            self.assertEqual(rows[0]["passphrase"], "winter2020")
            self.assertEqual(rows[0]["id"], rid)
            self.assertEqual(rows[0]["bssid"], "00:11:22:33:44:55")

    def test_jsonl_sidecar_written(self):
        with tempfile.TemporaryDirectory() as d:
            store = ResultStore(_cfg(Path(d)), dry_run=False)
            store.store(_record("lab-ap.cap"))
            lines = (Path(d) / "logs" / "results.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            payload = json.loads(lines[0])
            self.assertEqual(payload["kind"], "wpa")
            self.assertIn("id", payload)

    def test_dry_run_store_is_noop(self):
        with tempfile.TemporaryDirectory() as d:
            store = ResultStore(_cfg(Path(d)), dry_run=True)
            self.assertIsNone(store.store(_record("lab-ap.cap")))
            self.assertEqual(store.all(), [])
            self.assertFalse((Path(d) / "logs" / "results.db").exists())

    def test_stats(self):
        with tempfile.TemporaryDirectory() as d:
            store = ResultStore(_cfg(Path(d)), dry_run=False)
            store.store(_record("a.cap", status="CRACKED", passphrase="one", ttc=1000, kps=10000))
            store.store(_record("b.cap", status="CRACKED", passphrase="two", ttc=3000, kps=20000))
            store.store(_record("c.cap", status="NOT_CRACKED", passphrase=None))
            rows = store.all()
            stats = store.stats(rows)
            self.assertEqual(stats["total"], 3)
            self.assertEqual(stats["cracked"], 2)
            self.assertEqual(stats["not_cracked"], 1)
            self.assertEqual(stats["avg_keys_per_sec"], 15000.0)
            self.assertEqual(stats["min_time_to_crack_ms"], 1000)
            self.assertEqual(stats["max_time_to_crack_ms"], 3000)
            self.assertEqual(sorted(stats["passphrases"]), ["one", "two"])


class ReportRenderingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.store = ResultStore(_cfg(self.d), dry_run=False)
        self.store.store(_record("lab-ap.cap", status="CRACKED", passphrase="winter2020", ttc=4200, kps=155000))
        self.store.store(_record("lab-iot.cap", status="NOT_CRACKED"))
        self.rows = self.store.all()
        self.stats = self.store.stats(self.rows)

    def tearDown(self):
        self.tmp.cleanup()

    def test_markdown_contains_summary_and_rows(self):
        md = self.store.render_markdown(self.rows, self.stats)
        self.assertIn("W4 Crack Pipeline", md)
        self.assertIn("| Attempts | 2 |", md)
        self.assertIn("| Cracked | 1 |", md)
        self.assertIn("`winter2020`", md)
        self.assertIn("lab-ap.cap", md)
        self.assertIn("own-lab", md)

    def test_json_roundtrip(self):
        js = self.store.render_json(self.rows, self.stats)
        payload = json.loads(js)
        self.assertEqual(payload["stats"]["cracked"], 1)
        self.assertEqual(len(payload["attempts"]), 2)

    def test_write_report_files(self):
        json_p = self.d / "logs" / "report.json"
        md_p = self.d / "logs" / "report.md"
        stats = self.store.write_report(self.rows, json_p, md_p)
        self.assertEqual(stats["cracked"], 1)
        self.assertTrue(json_p.exists())
        self.assertTrue(md_p.exists())
        payload = json.loads(json_p.read_text(encoding="utf-8"))
        self.assertEqual(payload["stats"]["cracked"], 1)


class DurationFormatTests(unittest.TestCase):
    def test_units(self):
        self.assertEqual(format_duration_ms(None), "n/a")
        self.assertEqual(format_duration_ms(500), "500 ms")
        self.assertEqual(format_duration_ms(4200), "4.2 s")
        self.assertEqual(format_duration_ms(90000), "1.5 min")
        self.assertEqual(format_duration_ms(7200000), "2.0 h")


if __name__ == "__main__":
    unittest.main()