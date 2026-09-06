"""External binary detection + safe subprocess invocation.

Every external tool (hcxdumptool / hcxpcapngtool / aircrack-ng / hashcat) is
run through Toolchain.run(), which:

  * refuses to run a binary that was not previously resolved as present,
  * honors --dry-run by only PRINTING the command and returning a synthetic
    result that records executed=False (never touches the OS / subprocess), and
  * streams stdout line-by-line so hashcat progress is visible/logged live.
"""

import logging
import os
import shlex
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .errors import ToolMissing

_MAX_CAPTURE_BYTES = 2_000_000  # cap retained stdout; keep last chunk if exceeded
_TAIL_CAPTURE_BYTES = 500_000


@dataclass(frozen=True)
class CommandSpec:
    """A single executable invocation planned by the pipeline."""

    argv: Tuple[str, ...]
    description: str
    timeout: int = 3600
    expected_ok: bool = True

    def shell_join(self):
        return shlex.join(self.argv)


@dataclass
class RunResult:
    argv: Tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    elapsed: float
    executed: bool
    timed_out: bool = False

    def succeeded(self):
        return self.returncode == 0


@dataclass(frozen=True)
class ToolStatus:
    key: str
    configured: str
    path: Optional[str] = None

    @property
    def present(self):
        return self.path is not None


class Toolchain:
    """Resolves configured tool paths and executes commands safely."""

    def __init__(self, cfg, dry_run=False, logger=None):
        self.cfg = cfg
        self.dry_run = bool(dry_run)
        self.log = logger or logging.getLogger("w4.toolchain")
        self._cache: Dict[str, ToolStatus] = {}

    # -- resolution ---------------------------------------------------------

    def _resolve(self, configured):
        if not configured:
            return None
        if "/" in configured or configured.startswith("."):
            return (
                configured
                if os.path.isfile(configured) and os.access(configured, os.X_OK)
                else None
            )
        return shutil.which(configured)

    def status(self, key):
        if key not in self._cache:
            configured = self.cfg.get("tools", {}).get(key, key)
            self._cache[key] = ToolStatus(key, configured, self._resolve(configured))
        return self._cache[key]

    def present(self, key):
        return self.status(key).present

    def exe(self, key):
        """Executable name to place in a command: resolved path, else configured name."""
        st = self.status(key)
        return st.path if st.path else st.configured

    def require(self, keys):
        """Raise ToolMissing (exit 2) listing every absent binary among keys."""
        missing = [self.status(k) for k in keys if not self.status(k).present]
        if missing:
            names = "".join(
                f"    - {s.configured} (configured as 'tools.{s.key}')\n" for s in missing
            )
            raise ToolMissing(
                "required external tool(s) not installed:\n"
                + names
                + "Install them or fix their paths in config/crack.yaml "
                "(see README -> Toolchain Requirements). "
                "Run  crack selftest  to re-check."
            )
        return {k: self.status(k) for k in keys}

    def require_any(self, keys):
        """Like require() but satisfies when at least ONE of the keys is present.

        Used for fallback detectors (hcxpcapngtool OR aircrack-ng).
        """
        present = [k for k in keys if self.status(k).present]
        if present:
            return {k: self.status(k) for k in present}
        names = "".join(
            f"    - {self.status(k).configured} (configured as 'tools.{k}')\n" for k in keys
        )
        raise ToolMissing(
            "required external tool(s) not installed (need at least one of):\n"
            + names
            + "Install one or fix paths in config/crack.yaml "
            "(see README -> Toolchain Requirements)."
        )

    # -- execution ----------------------------------------------------------

    def _read_stream(self, fp, sink, buf):
        for raw in fp:
            if raw:
                buf.append(raw)
                if len(buf) > _MAX_CAPTURE_BYTES:
                    del buf[:-_TAIL_CAPTURE_BYTES]
                if sink:
                    try:
                        sink(raw)
                    except Exception:  # progress callbacks must never kill the run
                        self.log.exception("progress callback failed")

    def run(self, spec: CommandSpec, on_line=None) -> RunResult:
        argv = spec.argv
        shown = spec.shell_join()

        if self.dry_run:
            self.log.info("DRY-RUN (not executed): %s", shown)
            print(f"$ {shown}")
            return RunResult(argv, 0, "", "", 0.0, executed=False)

        self._verify_executable(argv[0])
        self.log.info("running: %s", shown)
        start = time.monotonic()
        stdout_buf: List[str] = []
        stderr_buf: List[str] = []
        proc = None
        try:
            proc = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            threads = [
                threading.Thread(target=self._read_stream, args=(proc.stdout, None, stdout_buf)),
                threading.Thread(target=self._read_stream, args=(proc.stderr, on_line, stderr_buf)),
            ]
            for t in threads:
                t.start()

            def join_all():
                for t in threads:
                    t.join()

            worker = threading.Thread(target=join_all)
            worker.start()
            worker.join(timeout=spec.timeout)
            timed_out = worker.is_alive()
            if timed_out:
                proc.kill()
                worker.join()
            retcode = proc.wait()
        except FileNotFoundError as exc:
            raise ToolMissing(
                f"external tool not found while invoking: {exc.filename}"
            ) from exc
        except OSError as exc:
            raise ToolMissing(f"failed to execute {executable}: {exc}") from exc

        elapsed = time.monotonic() - start
        stdout = "".join(stdout_buf)
        stderr = "".join(stderr_buf)
        if timed_out:
            self.log.error("timeout after %ss: %s", spec.timeout, shown)
        elif retcode != 0 and spec.expected_ok:
            self.log.warning(
                "exit %s (%ss): %s", retcode, round(elapsed, 2), shown
            )
        return RunResult(argv, retcode, stdout, stderr, elapsed, executed=True, timed_out=timed_out)

    def _verify_executable(self, executable):
        """Raise ToolMissing when the binary is not resolvable right before invoking."""
        if os.path.dirname(executable):
            if not os.path.exists(executable):
                raise ToolMissing(
                    f"external tool not found: {executable} "
                    "(was it removed after tool detection?)"
                )
        elif not shutil.which(executable):
            raise ToolMissing(f"external tool not found on PATH: {executable}")