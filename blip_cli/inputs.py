"""Message input resolution: raw text, file, URL, or stdin."""

from __future__ import annotations

import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .errors import InputError, NetworkError, UsageError

DEFAULT_MAX_INPUT_BYTES = 1024 * 1024
USER_AGENT = "blip-cli/1.0 (+https://github.com/krwg/blip)"


@dataclass(frozen=True)
class MessageInput:
    text: str
    kind: str
    origin: str
    size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "origin": self.origin,
            "sizeBytes": self.size_bytes,
            "text": self.text,
        }


def _decode(data: bytes, *, charset: Optional[str], origin: str) -> str:
    encoding = (charset or "utf-8").strip() or "utf-8"
    try:
        return data.decode(encoding)
    except (LookupError, UnicodeDecodeError) as exc:
        raise InputError(
            f"cannot decode {origin} as {encoding}: {exc}",
            hint="Use a UTF-8 encoded text source.",
        ) from exc


def _clean(text: str, origin: str) -> str:
    text = text.lstrip("\ufeff").rstrip("\r\n")
    if not text.strip():
        raise InputError(f"{origin} is empty")
    return text


def _read_stream(stream, max_bytes: int, origin: str) -> bytes:
    data = stream.read(max_bytes + 1)
    if isinstance(data, str):
        data = data.encode("utf-8")
    if len(data) > max_bytes:
        raise InputError(
            f"{origin} is larger than {max_bytes} bytes",
            hint="Raise --max-input-bytes if this is intentional.",
        )
    return data


def _read_file(path_text: str, max_bytes: int) -> MessageInput:
    if path_text == "-":
        data = _read_stream(sys.stdin.buffer, max_bytes, "stdin")
        return MessageInput(
            text=_clean(_decode(data, charset="utf-8-sig", origin="stdin"), "stdin"),
            kind="stdin",
            origin="<stdin>",
            size_bytes=len(data),
        )
    path = Path(path_text).expanduser()
    try:
        with path.open("rb") as handle:
            data = _read_stream(handle, max_bytes, str(path))
    except FileNotFoundError as exc:
        raise InputError(f"input file not found: {path}") from exc
    except IsADirectoryError as exc:
        raise InputError(f"input path is a directory: {path}") from exc
    except OSError as exc:
        raise InputError(f"cannot read input file {path}: {exc}") from exc
    return MessageInput(
        text=_clean(_decode(data, charset="utf-8-sig", origin=str(path)), str(path)),
        kind="file",
        origin=str(path),
        size_bytes=len(data),
    )


def _read_stdin(max_bytes: int) -> MessageInput:
    data = _read_stream(sys.stdin.buffer, max_bytes, "stdin")
    return MessageInput(
        text=_clean(_decode(data, charset="utf-8-sig", origin="stdin"), "stdin"),
        kind="stdin",
        origin="<stdin>",
        size_bytes=len(data),
    )


def _read_url(url: str, max_bytes: int, timeout: float) -> MessageInput:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise InputError(
            f"unsupported URL scheme {parsed.scheme!r}",
            hint="Only http:// and https:// URLs are supported.",
        )
    if not parsed.netloc:
        raise InputError(f"invalid URL: {url}")
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/plain, */*;q=0.5"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            length = response.headers.get("Content-Length")
            if length is not None:
                try:
                    if int(length) > max_bytes:
                        raise InputError(
                            f"URL content is larger than {max_bytes} bytes",
                            hint="Raise --max-input-bytes if this is intentional.",
                        )
                except ValueError:
                    pass
            data = _read_stream(response, max_bytes, url)
            charset = response.headers.get_content_charset() or "utf-8"
    except InputError:
        raise
    except urllib.error.HTTPError as exc:
        raise NetworkError(f"HTTP {exc.code} while fetching {url}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise NetworkError(f"cannot fetch {url}: {exc.reason}") from exc
    except (socket.timeout, TimeoutError) as exc:
        raise NetworkError(f"timed out fetching {url} after {timeout:g}s") from exc
    except OSError as exc:
        raise NetworkError(f"cannot fetch {url}: {exc}") from exc
    return MessageInput(
        text=_clean(_decode(data, charset=charset, origin=url), url),
        kind="url",
        origin=url,
        size_bytes=len(data),
    )


def load_message(
    *,
    text: Optional[str] = None,
    file_path: Optional[str] = None,
    url: Optional[str] = None,
    use_stdin: bool = False,
    max_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    url_timeout: float = 10.0,
) -> MessageInput:
    supplied = [
        text is not None,
        file_path is not None,
        url is not None,
        bool(use_stdin),
    ]
    if sum(supplied) != 1:
        raise UsageError(
            "provide exactly one message source: --text, --file, --url, or --stdin"
        )
    if max_bytes <= 0:
        raise UsageError("--max-input-bytes must be positive")
    if text is not None:
        raw = text.encode("utf-8")
        if len(raw) > max_bytes:
            raise InputError(f"--text is larger than {max_bytes} bytes")
        return MessageInput(
            text=_clean(text, "--text"),
            kind="text",
            origin="--text",
            size_bytes=len(raw),
        )
    if file_path is not None:
        return _read_file(file_path, max_bytes)
    if url is not None:
        return _read_url(url, max_bytes, url_timeout)
    return _read_stdin(max_bytes)
