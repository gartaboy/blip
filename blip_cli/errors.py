"""Error types with stable CLI exit codes."""

from __future__ import annotations

from typing import Optional


class BlipCliError(Exception):
    """Base class for expected failures."""

    exit_code = 1

    def __init__(self, message: str, hint: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.hint = hint


class UsageError(BlipCliError):
    """Invalid user input or invalid configuration."""

    exit_code = 2


class InputError(UsageError):
    """Message input could not be read or is invalid."""


class NetworkError(BlipCliError):
    """Connection, timeout, or local socket failure."""

    exit_code = 1


class ProtocolError(BlipCliError):
    """A peer sent malformed or unauthenticated data."""

    exit_code = 1


class OutputError(BlipCliError):
    """The result file could not be written."""

    exit_code = 1
