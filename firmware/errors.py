"""Exit-code contract and pipeline exception types.

Clean exit-code mapping (single source of truth, imported by the CLI and by
tests/test_exit_codes.py):

    0  OK            pipeline ran cleanly (incl. "no password recovered" runs;
                     the crack outcome is a data field, not an exit code)
    1  CONFIG/ARG    bad usage, missing/unreadable wordlist, unauthorized
                     capture, failed tool run
    2  TOOL          an external binary required for the job is not installed
    3  NO_HANDSHAKE  capture contains no WPA handshake / PMKID to crack
"""

EXIT_OK = 0
EXIT_CONFIG = 1
EXIT_TOOL = 2
EXIT_NO_HANDSHAKE = 3


class PipelineError(Exception):
    """Base for all recoverable pipeline failures (mapped to exit codes)."""

    exit_code = EXIT_CONFIG

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class ConfigError(PipelineError):
    """Configuration, argument, or input-sanity failure -> exit 1."""

    exit_code = EXIT_CONFIG


class OperationError(PipelineError):
    """An external stage failed while running -> exit 1."""

    exit_code = EXIT_CONFIG


class ToolMissing(PipelineError):
    """A required external binary is absent -> exit 2."""

    exit_code = EXIT_TOOL


class NoHandshake(PipelineError):
    """Nothing to crack in the capture -> exit 3."""

    exit_code = EXIT_NO_HANDSHAKE