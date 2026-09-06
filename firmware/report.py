"""Results persistence and reporting.

Pipeline outcomes land in two places:

  * SQLite database (config 'db.path', default logs/results.db) -- the source
    of truth for  crack report <db>  queries; and
  * a JSONL sidecar (config 'db.jsonl', default logs/results.jsonl) -- one JSON
    object per attempt for streaming/audit pipelines.

SQLite is stdlib (sqlite3); there is no ORM. In --dry-run every store call is a
no-op: amendments to the DB are themselves an "execution".
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_LOG = logging.getLogger("w4.report")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cracks (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                 TEXT NOT NULL,
    input              TEXT NOT NULL,
    kind               TEXT NOT NULL,
    bssid              TEXT,
    ssid               TEXT,
    mode               INTEGER,
    status             TEXT NOT NULL,
    passphrase         TEXT,
    keys_per_sec       REAL,
    time_to_crack_ms   INTEGER,
    candidates_tested  INTEGER,
    notes              TEXT
)
"""


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def format_duration_ms(ms):
    if ms is None:
        return "n/a"
    total = int(ms)
    if total < 1000:
        return f"{total} ms"
    seconds = total / 1000.0
    if seconds < 60:
        return f"{seconds:.1f} s"
    if seconds < 3600:
        return f"{seconds / 60:.1f} min"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} h"
    return f"{seconds / 86400:.1f} d"


class ResultStore:
    def __init__(self, cfg, dry_run=False, logger=None):
        self.db_path = Path(cfg["db"]["path"])
        self.jsonl_path = Path(cfg["db"]["jsonl"])
        self.dry_run = bool(dry_run)
        self.log = logger or _LOG
        self._conn = None  # lazily opened on first write

    def _connect(self):
        if self._conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.execute(_SCHEMA)
            self._conn.commit()
        return self._conn

    # -- write ---------------------------------------------------------------

    def store(self, record):
        """Persist one crack-attempt record; returns row id (or None in dry-run).

        Lazy: the SQLite file is only created/opened on the first real write,
        never by merely constructing the store or by a dry-run.
        """
        if self.dry_run:
            self.log.info("dry-run: would store record %s", json.dumps(record, sort_keys=True))
            return None
        conn = self._connect()
        row = (
            record.get("ts") or utc_now(),
            record.get("input") or "",
            record.get("kind") or "wpa",
            record.get("bssid"),
            record.get("ssid"),
            record.get("mode"),
            record.get("status") or "UNKNOWN",
            record.get("passphrase"),
            record.get("keys_per_sec"),
            record.get("time_to_crack_ms"),
            record.get("candidates_tested"),
            record.get("notes"),
        )
        cur = conn.execute(
            "INSERT INTO cracks "
            "(ts, input, kind, bssid, ssid, mode, status, passphrase,"
            " keys_per_sec, time_to_crack_ms, candidates_tested, notes)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            row,
        )
        conn.commit()
        row_id = cur.lastrowid
        record_out = dict(record)
        record_out["id"] = row_id
        record_out["ts"] = record_out.get("ts") or row[0]
        with self.jsonl_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record_out, sort_keys=True) + "\n")
        self.log.info("stored crack result id=%s status=%s", row_id, record.get("status"))
        return row_id

    # -- read ----------------------------------------------------------------

    def all(self):
        """All stored rows, newest first. Never creates the DB when missing."""
        if self.dry_run or not self.db_path.exists():
            return []
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, ts, input, kind, bssid, ssid, mode, status, passphrase,"
            " keys_per_sec, time_to_crack_ms, candidates_tested, notes"
            " FROM cracks ORDER BY id DESC"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def stats(self, rows):
        total = len(rows)
        cracked = sum(1 for r in rows if r.get("status") == "CRACKED")
        not_cracked = sum(1 for r in rows if r.get("status") == "NOT_CRACKED")
        no_handshake = sum(1 for r in rows if r.get("status") == "NO_HANDSHAKE")
        other = total - cracked - not_cracked - no_handshake
        kps = [r.get("keys_per_sec") or 0 for r in rows if r.get("status") == "CRACKED"]
        ttc = [r.get("time_to_crack_ms") for r in rows if r.get("status") == "CRACKED"]
        return {
            "total": total,
            "cracked": cracked,
            "not_cracked": not_cracked,
            "no_handshake": no_handshake,
            "other": other,
            "avg_keys_per_sec": (sum(kps) / len(kps)) if kps else 0.0,
            "min_time_to_crack_ms": min(ttc) if ttc else None,
            "max_time_to_crack_ms": max(ttc) if ttc else None,
            "passphrases": [r.get("passphrase") for r in rows if r.get("passphrase")],
        }

    # -- rendering -----------------------------------------------------------

    def render_markdown(self, rows, stats):
        lines = ["# W4 Crack Pipeline — Results Report", ""]
        lines.append(f"_Generated {utc_now()} UTC_")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("| --- | --- |")
        lines.append(f"| Attempts | {stats['total']} |")
        lines.append(f"| Cracked | {stats['cracked']} |")
        lines.append(f"| Not cracked | {stats['not_cracked']} |")
        lines.append(f"| No handshake/PMKID | {stats['no_handshake']} |")
        lines.append(f"| Avg keys/s (cracked) | {stats['avg_keys_per_sec']:.0f} |")
        lines.append(
            "| Time-to-crack range | "
            f"{format_duration_ms(stats['min_time_to_crack_ms'])} – "
            f"{format_duration_ms(stats['max_time_to_crack_ms'])} |"
        )
        if stats["passphrases"]:
            shown = ", ".join(f"`{p}`" for p in stats["passphrases"])
            lines.append(f"| Recovered passphrases | {shown} |")
        lines.append("")
        lines.append("## Attempts")
        lines.append("")
        lines.append("| # | Time (UTC) | Input | Kind | Status | Key (ms) | Keys/s | Notes |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for r in rows:
            bssid = r.get("bssid") or "?"
            ssid = r.get("ssid") or "?"
            passphrase = r.get("passphrase") or ""
            notes = f"{ssid} ({bssid})"
            if passphrase:
                notes += f" → `{passphrase}`"
            lines.append(
                f"| {r.get('id')} | {r.get('ts')} | `{r.get('input')}` | {r.get('kind')} | "
                f"{r.get('status')} | {format_duration_ms(r.get('time_to_crack_ms'))} | "
                f"{r.get('keys_per_sec') or 0:.0f} | {notes} |"
            )
        lines.append("")
        lines.append("_All captures processed by this pipeline are own-lab traffic._")
        lines.append("")
        return "\n".join(lines)

    def render_json(self, rows, stats):
        return json.dumps(
            {"generated_utc": utc_now(), "stats": stats, "attempts": rows},
            indent=2,
            sort_keys=True,
        )

    def write_report(self, rows, json_path, md_path):
        stats = self.stats(rows)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(self.render_json(rows, stats) + "\n", encoding="utf-8")
        md_path.write_text(self.render_markdown(rows, stats) + "\n", encoding="utf-8")
        return stats