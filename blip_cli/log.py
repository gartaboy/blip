"""Small stderr logger with a consistent, script-friendly format."""

from __future__ import annotations

import sys


class Logger:
    def __init__(self, *, verbose: int = 0, quiet: bool = False):
        self.verbose = int(verbose)
        self.quiet = bool(quiet)

    def _write(self, level: str, message: str) -> None:
        print(f"[{level}] {message}", file=sys.stderr, flush=True)

    def debug(self, message: str) -> None:
        if self.verbose >= 1:
            self._write("debug", message)

    def info(self, message: str) -> None:
        if not self.quiet:
            self._write("info", message)

    def warn(self, message: str) -> None:
        if not self.quiet:
            self._write("warn", message)

    def error(self, message: str) -> None:
        self._write("error", message)
