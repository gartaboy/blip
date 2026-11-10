"""Result file writers and human-readable CLI output."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Iterable, Optional

from .errors import OutputError
from .protocol import Peer


def _prepare_path(path: str) -> Path:
    target = Path(path).expanduser()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OutputError(f"cannot create output directory {target.parent}: {exc}") from exc
    return target


def write_json(path: str, value: Any) -> Path:
    target = _prepare_path(path)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise OutputError(f"cannot write output file {target}: {exc}") from exc
    return target


class EventWriter:
    """Thread-safe append-only JSONL writer."""

    def __init__(self, path: Optional[str], *, append: bool = True):
        self.path = str(_prepare_path(path)) if path else None
        self.append = append
        self._lock = threading.Lock()
        self._handle = None
        if self.path:
            mode = "a" if append else "w"
            try:
                self._handle = open(  # noqa: SIM115 - lifetime matches the listener
                    self.path, mode, encoding="utf-8", newline="\n"
                )
            except OSError as exc:
                raise OutputError(f"cannot open output file {self.path}: {exc}") from exc

    def write(self, event: dict[str, Any]) -> None:
        if self._handle is None:
            return
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            try:
                self._handle.write(line + "\n")
                self._handle.flush()
            except OSError as exc:
                raise OutputError(f"cannot append to {self.path}: {exc}") from exc

    def close(self) -> None:
        if self._handle is None:
            return
        with self._lock:
            try:
                self._handle.close()
            except OSError:
                pass
            self._handle = None

    def __enter__(self) -> "EventWriter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def _shorten(value: str, width: int) -> str:
    return value if len(value) <= width else value[: max(0, width - 1)] + "…"


def format_peers(peers: Iterable[Peer]) -> str:
    peer_list = list(peers)
    if not peer_list:
        return "No peers discovered."
    rows = [("ID", "NAME", "PRESENCE", "ADDRESS", "PROTO", "STATUS")]
    for peer in peer_list:
        address = f"{peer.ip}:{peer.tcp_port}"
        rows.append(
            (
                str(peer.blip_id),
                _shorten(peer.display_name, 24),
                peer.presence + (f" / {peer.presence_text}" if peer.presence_text else ""),
                address,
                str(peer.mesh_proto),
                "verified" if peer.verified else "unverified",
            )
        )
    widths = [max(len(row[index]) for row in rows) for index in range(len(rows[0]))]
    lines = []
    for row in rows:
        line = "  ".join(
            cell.ljust(widths[index]) for index, cell in enumerate(row)
        ).rstrip()
        lines.append(line)
    return "\n".join(lines)


def format_event(event: dict[str, Any]) -> str:
    received = event.get("receivedAtHuman", "")
    sender = event.get("from", "?")
    text = str(event.get("text", "")).replace("\n", "\\n")
    suffix = f" [{received}]" if received else ""
    return f"#{sender}: {text}{suffix}"
