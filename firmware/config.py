"""Configuration loading, validation, and wordlist/reliability checks.

Backing store is a YAML file (config/crack.yaml by default, overridable with
--config or the W4_CRACK_CONFIG environment variable). Relative artifact paths
(logs/, workdir, DB, potfile, wordlist, rules) resolve against the launch
directory (run the CLI from the repo root).
"""

import logging
import os
from pathlib import Path

import yaml

from . import labspec
from .errors import ConfigError

DEFAULT_CONFIG_PATH = "config/crack.yaml"

BASE_CFG = {
    "tools": {
        "hcxdumptool": "hcxdumptool",
        "hcxpcapngtool": "hcxpcapngtool",
        "hashcat": "hashcat",
        "aircrack": "aircrack-ng",
    },
    "wordlist": labspec.DEFAULT_WORDLIST,
    "rules": labspec.DEFAULT_RULES,
    "hashcat": {
        "mode": labspec.HASHCAT_MODE_WPA,
        "workload": 3,
        "devices": "",
        "status_timer": 5,
        "potfile": "logs/crack.potfile",
        "extra": [],
    },
    "capture": {
        "allowed_owner": None,  # extra uid/username accepted as owner (None = current user)
        "marker": labspec.LAB_MARKER,  # filename token that marks a capture as own-lab
    },
    "db": {"path": "logs/results.db", "jsonl": "logs/results.jsonl"},
    "workdir": "logs/work",
    "network": {
        "documentation_range": labspec.DOC_NETWORK_RANGE,
        "example_ssids": list(labspec.DOC_SSIDS),
        "example_macs": list(labspec.DOC_MAC_ADDRESSES),
    },
}

_LOG = logging.getLogger("w4.config")


def deep_merge(base, overlay):
    """Recursively merge overlay onto a copy of base. Lists/strings/scalars overwrite."""
    out = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _resolve_rel(base_dir, path):
    if path is None:
        return None
    p = Path(str(path))
    return str(p) if p.is_absolute() else str(base_dir / p)


def resolve_paths(cfg, base_dir=None):
    """Resolve relative artifact paths against the launch directory (CWD).

    Run the CLI from the repo root so logs/, logs/work/ and the results DB land
    in the repository (all gitignored). Absolute paths pass through unchanged.
    """
    base = Path.cwd()
    cfg["wordlist"] = _resolve_rel(base, cfg.get("wordlist"))
    cfg["rules"] = _resolve_rel(base, cfg.get("rules"))
    if cfg.get("hashcat") and cfg["hashcat"].get("potfile"):
        cfg["hashcat"]["potfile"] = _resolve_rel(base, cfg["hashcat"]["potfile"])
    if cfg.get("db"):
        if cfg["db"].get("path"):
            cfg["db"]["path"] = _resolve_rel(base, cfg["db"]["path"])
        if cfg["db"].get("jsonl"):
            cfg["db"]["jsonl"] = _resolve_rel(base, cfg["db"]["jsonl"])
    if cfg.get("workdir"):
        cfg["workdir"] = _resolve_rel(base, cfg["workdir"])
    return cfg


def validate_config(cfg):
    """Return a list of human-readable problems (empty means valid)."""
    problems = []
    tools = cfg.get("tools")
    if not isinstance(tools, dict) or not tools:
        problems.append("config 'tools' must be a non-empty mapping of tool-name -> path")
    else:
        for key in ("hcxpcapngtool", "hashcat", "aircrack", "hcxdumptool"):
            if not isinstance(tools.get(key), str) or not tools[key]:
                problems.append(f"config 'tools.{key}' must be a non-empty string")

    for field in ("wordlist", "rules"):
        if not isinstance(cfg.get(field), str) or not cfg[field]:
            problems.append(f"config '{field}' must be a non-empty string")

    hc = cfg.get("hashcat")
    if not isinstance(hc, dict):
        problems.append("config 'hashcat' must be a mapping")
    else:
        if not isinstance(hc.get("mode"), int):
            problems.append("config 'hashcat.mode' must be an integer (22000 for WPA PMKID+EAPOL)")
        if not isinstance(hc.get("workload"), int) or not 1 <= hc["workload"] <= 4:
            problems.append("config 'hashcat.workload' must be an integer between 1 and 4")
        if hc.get("devices") is not None and not isinstance(hc["devices"], (str, int)):
            problems.append("config 'hashcat.devices' must be empty, an int, or a string")
        if not isinstance(hc.get("extra", []), list):
            problems.append("config 'hashcat.extra' must be a list of extra hashcat flags")

    cap = cfg.get("capture")
    if not isinstance(cap, dict):
        problems.append("config 'capture' must be a mapping")
    else:
        if cap.get("allowed_owner") is not None and not isinstance(
            cap["allowed_owner"], (str, int)
        ):
            problems.append("config 'capture.allowed_owner' must be a username, uid, or null")
        marker = cap.get("marker")
        if not isinstance(marker, str) or not marker:
            problems.append("config 'capture.marker' must be a non-empty string")

    db = cfg.get("db")
    if not isinstance(db, dict) or not db.get("path"):
        problems.append("config 'db.path' must be a non-empty string")
    if cfg.get("workdir") is None:
        problems.append("config 'workdir' must be a string")

    net = cfg.get("network")
    if not isinstance(net, dict):
        problems.append("config 'network' must be a mapping of documentation placeholders")
    return problems


def load_config(path=None):
    """Load, validate, and path-resolve configuration. Raises ConfigError on problems."""
    explicit = bool(path or os.environ.get("W4_CRACK_CONFIG"))
    config_path = path or os.environ.get("W4_CRACK_CONFIG") or DEFAULT_CONFIG_PATH
    cfg_path = Path(config_path)

    overlay = {}
    if cfg_path.exists():
        with cfg_path.open("r", encoding="utf-8") as fh:
            try:
                overlay = yaml.safe_load(fh) or {}
            except yaml.YAMLError as exc:
                raise ConfigError(f"invalid YAML in {cfg_path}: {exc}")
    elif explicit:
        raise ConfigError(
            f"configuration file not found: {cfg_path} "
            "(use --config to point at an existing YAML file)"
        )
    else:
        _LOG.warning("default config %s not found; using built-in defaults", cfg_path)

    if not isinstance(overlay, dict):
        raise ConfigError(f"configuration root in {cfg_path} must be a mapping")

    cfg = deep_merge(BASE_CFG, overlay)
    problems = validate_config(cfg)
    if problems:
        raise ConfigError("configuration problems:\n  - " + "\n  - ".join(problems))

    resolve_paths(cfg)
    _LOG.info("config loaded from %s", cfg_path if cfg_path.exists() else "(built-in defaults)")
    return cfg


def check_wordlist(path):
    """Validation stage 3: the wordlist must exist, be readable, and be non-empty."""
    p = Path(str(path))
    if not p.exists():
        raise ConfigError(
            f"wordlist not found: {p}. Install one (e.g. 'rockyou.txt') or point the "
            "pipeline at yours with  --wordlist <path>  or  config/crack.yaml 'wordlist:'."
        )
    if not p.is_file():
        raise ConfigError(f"wordlist path is not a regular file: {p}")
    if not os.access(p, os.R_OK):
        raise ConfigError(f"wordlist is not readable: {p} (check permissions)")
    size = p.stat().st_size
    if size == 0:
        raise ConfigError(f"wordlist is empty: {p}")
    return {"path": str(p), "size_bytes": size}


def check_rules(path):
    """The best64 rules file is optional -- warn and continue if absent."""
    p = Path(str(path))
    ok = p.is_file() and os.access(p, os.R_OK)
    if not ok:
        _LOG.warning(
            "best64 rules file not found at %s (continuing without -r). Point "
            "config 'rules:' at hashcat's best64.rule to enable rule cracking.",
            p,
        )
    return None if ok else None, ok