"""Command-line interface for the BLIP LAN core.

Run ``python cli.py --help`` or inspect README.md for examples.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from . import __version__
from .crypto import (
    Identity,
    default_identity_path,
    load_identity,
    new_identity,
    save_identity,
    validate_blip_id,
)
from .errors import BlipCliError, NetworkError, UsageError
from .inputs import DEFAULT_MAX_INPUT_BYTES, load_message
from .log import Logger
from .net import (
    Discovery,
    TcpInboxServer,
    ping_peer,
    send_announce_once,
    send_message_to_peer,
)
from .output import EventWriter, format_event, format_peers, write_json
from .protocol import (
    DEFAULT_TCP_PORT,
    DEFAULT_UDP_PORT,
    validate_peer_id,
    validate_port,
)

_PRESENCE_CHOICES = ("online", "away", "busy")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _non_negative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def _add_common(parser: argparse.ArgumentParser, *, suppress: bool) -> None:
    def default(value: Any) -> Any:
        return argparse.SUPPRESS if suppress else value

    parser.add_argument(
        "--identity",
        metavar="PATH",
        default=default(None),
        help="identity JSON path (default: platform config dir)",
    )
    parser.add_argument(
        "--id", type=int, default=default(None), metavar="1-64", help="BLIP ID to use"
    )
    parser.add_argument(
        "--name", default=default(None), metavar="NAME", help="display name on the mesh"
    )
    parser.add_argument(
        "--presence",
        choices=_PRESENCE_CHOICES,
        default=default(None),
        help="presence announced to peers (default: online)",
    )
    parser.add_argument(
        "--presence-text",
        default=default(None),
        metavar="TEXT",
        help="short custom status text (max 48 chars)",
    )
    parser.add_argument(
        "--udp-port",
        type=int,
        default=default(DEFAULT_UDP_PORT),
        metavar="PORT",
        help=f"UDP discovery port (default: {DEFAULT_UDP_PORT})",
    )
    parser.add_argument(
        "--tcp-port",
        type=int,
        default=default(DEFAULT_TCP_PORT),
        metavar="PORT",
        help=f"announced/listening TCP port (default: {DEFAULT_TCP_PORT})",
    )
    parser.add_argument(
        "--ip",
        default=default(None),
        metavar="ADDR",
        help="IPv4 address to announce (default: auto-detect)",
    )
    parser.add_argument(
        "--broadcast",
        action="append",
        default=default([]),
        metavar="ADDR",
        help="extra broadcast/unicast discovery target (repeatable)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=default(0),
        help="verbose diagnostics on stderr (repeat for more)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=default(False),
        help="suppress informational stderr output",
    )


def _add_message_input(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--text", metavar="TEXT", help="raw message text")
    group.add_argument("--file", metavar="PATH", help="read message from a file ('-' = stdin)")
    group.add_argument("--url", metavar="URL", help="fetch message over http(s)")
    group.add_argument("--stdin", action="store_true", help="read message from stdin")
    parser.add_argument(
        "--max-input-bytes",
        type=int,
        default=DEFAULT_MAX_INPUT_BYTES,
        metavar="N",
        help=f"maximum input size (default: {DEFAULT_MAX_INPUT_BYTES})",
    )
    parser.add_argument(
        "--url-timeout",
        type=_positive_float,
        default=10.0,
        metavar="SEC",
        help="HTTP timeout for --url (default: 10)",
    )


def _add_target(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--peer-ip",
        metavar="HOST",
        default=None,
        help="connect directly to HOST instead of discovering the peer",
    )
    parser.add_argument(
        "--peer-port",
        type=int,
        metavar="PORT",
        default=None,
        help="override the peer's TCP port",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blip",
        description=(
            "Dependency-free BLIP LAN utility: discover peers, exchange messages, "
            "and run a JSONL inbox over UDP 42069 / TCP 42070."
        ),
        epilog=(
            "Common flags may be placed before or after the subcommand.\n"
            "Examples:\n"
            "  python cli.py --id 7 --name alice discover --timeout 8\n"
            "  python cli.py send --peer 7 --text \"hello\"\n"
            "  python cli.py send --peer 7 --file message.txt --output receipt.json\n"
            "  python cli.py listen --output inbox.jsonl\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common(parser, suppress=False)
    parser.add_argument(
        "--version", action="version", version=f"blip-cli {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    identity_parser = subparsers.add_parser(
        "identity", help="show or create the local identity"
    )
    _add_common(identity_parser, suppress=True)
    identity_parser.add_argument(
        "--rotate", action="store_true", help="replace the Ed25519 key, keep the ID"
    )
    identity_parser.add_argument(
        "--json", action="store_true", help="print machine-readable JSON"
    )

    discover_parser = subparsers.add_parser(
        "discover", help="announce and list BLIP peers on the LAN"
    )
    _add_common(discover_parser, suppress=True)
    discover_parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=6.0,
        metavar="SEC",
        help="how long to listen for announces (default: 6)",
    )
    discover_parser.add_argument(
        "--output", metavar="PATH", default=None, help="write peer list as JSON"
    )
    discover_parser.add_argument(
        "--json", action="store_true", help="print machine-readable JSON"
    )

    send_parser = subparsers.add_parser(
        "send", help="send one text message to a peer"
    )
    _add_common(send_parser, suppress=True)
    send_parser.add_argument(
        "--peer", type=int, required=True, metavar="1-64", help="target BLIP ID"
    )
    _add_target(send_parser)
    _add_message_input(send_parser)
    send_parser.add_argument(
        "--output", metavar="PATH", default=None, help="write send receipt as JSON"
    )
    send_parser.add_argument(
        "--discover-timeout",
        type=_positive_float,
        default=5.0,
        metavar="SEC",
        help="peer discovery window when --peer-ip is omitted (default: 5)",
    )
    send_parser.add_argument(
        "--connect-timeout",
        type=_positive_float,
        default=5.0,
        metavar="SEC",
        help="TCP connect timeout (default: 5)",
    )
    send_parser.add_argument(
        "--handshake-timeout",
        type=_positive_float,
        default=3.0,
        metavar="SEC",
        help="legacy handshake wait (default: 3)",
    )
    send_parser.add_argument(
        "--wait-reply",
        type=_non_negative_float,
        default=0.0,
        metavar="SEC",
        help="wait up to SEC for one reply frame (default: 0)",
    )
    send_parser.add_argument(
        "--no-handshake",
        action="store_true",
        help="skip mesh-handshake and send a plaintext frame directly",
    )
    send_parser.add_argument(
        "--no-announce",
        action="store_true",
        help="do not send a best-effort announce when --peer-ip is used",
    )
    send_parser.add_argument(
        "--json", action="store_true", help="print machine-readable JSON"
    )

    listen_parser = subparsers.add_parser(
        "listen", help="run a TCP inbox and write messages as JSONL"
    )
    _add_common(listen_parser, suppress=True)
    listen_parser.add_argument(
        "--timeout",
        type=_non_negative_float,
        default=0.0,
        metavar="SEC",
        help="stop after SEC seconds (default: 0 = run forever)",
    )
    listen_parser.add_argument(
        "--once", action="store_true", help="exit after the first message"
    )
    listen_parser.add_argument(
        "--output", metavar="PATH", default=None, help="append events to a JSONL file"
    )
    listen_parser.add_argument(
        "--all-events",
        action="store_true",
        help="also emit typing/receipt/call frames and handshakes",
    )
    listen_parser.add_argument(
        "--no-announce", action="store_true", help="do not announce on UDP"
    )
    listen_parser.add_argument(
        "--json", action="store_true", help="print each event as JSON"
    )

    ping_parser = subparsers.add_parser(
        "ping", help="measure TCP round-trip time to a peer"
    )
    _add_common(ping_parser, suppress=True)
    ping_parser.add_argument(
        "--peer", type=int, required=True, metavar="1-64", help="target BLIP ID"
    )
    _add_target(ping_parser)
    ping_parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=3.0,
        metavar="SEC",
        help="pong timeout (default: 3)",
    )
    ping_parser.add_argument(
        "--discover-timeout",
        type=_positive_float,
        default=5.0,
        metavar="SEC",
        help="peer discovery window when --peer-ip is omitted (default: 5)",
    )
    ping_parser.add_argument(
        "--json", action="store_true", help="print machine-readable JSON"
    )

    return parser


# ---------------------------------------------------------------------------
# Shared command helpers
# ---------------------------------------------------------------------------


def _normalize_args(args: argparse.Namespace) -> argparse.Namespace:
    args.udp_port = validate_port(
        getattr(args, "udp_port", DEFAULT_UDP_PORT), "--udp-port"
    )
    args.tcp_port = validate_port(
        getattr(args, "tcp_port", DEFAULT_TCP_PORT), "--tcp-port"
    )
    args.verbose = int(getattr(args, "verbose", 0) or 0)
    args.quiet = bool(getattr(args, "quiet", False))
    args.presence = getattr(args, "presence", None) or "online"
    args.presence_text = getattr(args, "presence_text", None) or ""
    args.broadcast = list(getattr(args, "broadcast", None) or [])
    args.identity = getattr(args, "identity", None)
    args.id = getattr(args, "id", None)
    args.name = getattr(args, "name", None)
    args.ip = getattr(args, "ip", None)
    if args.id is not None:
        try:
            validate_blip_id(args.id)
        except ValueError as exc:
            raise UsageError(str(exc)) from exc
    if getattr(args, "peer", None) is not None:
        args.peer = validate_peer_id(args.peer)
    if getattr(args, "peer_port", None) is not None:
        args.peer_port = validate_port(args.peer_port, "--peer-port")
    return args


def _identity_path(args: argparse.Namespace) -> Path:
    return Path(args.identity).expanduser() if args.identity else default_identity_path()


def _load_identity(args: argparse.Namespace, *, rotate: bool = False) -> Identity:
    path = _identity_path(args)
    try:
        existing = load_identity(path)
    except ValueError as exc:
        raise UsageError(
            str(exc),
            hint="Delete the file or pass --rotate to regenerate the key.",
        ) from exc
    except OSError as exc:
        raise UsageError(f"cannot read identity {path}: {exc}") from exc

    requested_id = args.id
    requested_name = args.name
    if existing is None:
        identity = new_identity(
            requested_id if requested_id is not None else 64,
            requested_name or socket.gethostname() or "blip-cli",
        )
    else:
        identity = existing
        if requested_id is not None:
            identity = identity.with_changes(blip_id=requested_id)
        if requested_name is not None:
            identity = identity.with_changes(display_name=requested_name)
        if rotate:
            identity = Identity(
                identity.blip_id, identity.display_name, os.urandom(32)
            )
    try:
        if existing is None or identity != existing or rotate:
            save_identity(path, identity)
    except OSError as exc:
        raise UsageError(f"cannot write identity {path}: {exc}") from exc
    return identity


def _self_payload(identity: Identity, args: argparse.Namespace) -> dict[str, Any]:
    return {
        "blipId": identity.blip_id,
        "displayName": identity.display_name,
        "publicKey": identity.public_key_b64,
        "udpPort": args.udp_port,
        "tcpPort": args.tcp_port,
        "presence": args.presence,
    }


def _emit_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2), flush=True)


def _resolve_target(
    args: argparse.Namespace,
    *,
    identity: Identity,
    logger: Logger,
    tcp_port_default: int = DEFAULT_TCP_PORT,
) -> tuple[str, int]:
    if getattr(args, "peer_ip", None):
        host = args.peer_ip
        port = args.peer_port or tcp_port_default
        logger.debug(f"direct target: {host}:{port}")
        return host, port

    discovery = Discovery(
        identity,
        udp_port=args.udp_port,
        tcp_port=args.tcp_port,
        primary_ip=args.ip,
        targets=args.broadcast,
        presence=args.presence,
        presence_text=args.presence_text,
        logger=logger,
        receive=True,
    )
    try:
        discovery.start()
        logger.info(
            f"discovering #{args.peer} for up to {args.discover_timeout:g}s..."
        )
        peer = discovery.wait_for_peer(args.peer, args.discover_timeout)
        if peer is None:
            raise NetworkError(
                f"peer #{args.peer} was not discovered",
                hint="Pass --peer-ip HOST to connect directly, or check the LAN/VPN.",
            )
        port = args.peer_port or peer.tcp_port
        logger.info(
            f"peer #{peer.blip_id} {peer.display_name} at {peer.ip}:{port}"
        )
        return peer.ip, port
    finally:
        discovery.stop()


def _iso_timestamp(ms: Any) -> str:
    try:
        return datetime.fromtimestamp(int(ms) / 1000.0).astimezone().isoformat(
            timespec="seconds"
        )
    except (TypeError, ValueError, OSError):
        return ""


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_identity(args: argparse.Namespace, logger: Logger) -> int:
    identity = _load_identity(args, rotate=bool(getattr(args, "rotate", False)))
    path = _identity_path(args)
    payload = {
        "ok": True,
        "path": str(path),
        "blipId": identity.blip_id,
        "displayName": identity.display_name,
        "publicKey": identity.public_key_b64,
        "rotated": bool(getattr(args, "rotate", False)),
    }
    if getattr(args, "json", False):
        _emit_json(payload)
    else:
        print(f"identity: {path}")
        print(f"blip id:  {identity.blip_id}")
        print(f"name:     {identity.display_name}")
        print(f"pubkey:   {identity.public_key_b64}")
        if getattr(args, "rotate", False):
            print("key:      rotated")
    return 0


def cmd_discover(args: argparse.Namespace, logger: Logger) -> int:
    identity = _load_identity(args)
    discovery = Discovery(
        identity,
        udp_port=args.udp_port,
        tcp_port=args.tcp_port,
        primary_ip=args.ip,
        targets=args.broadcast,
        presence=args.presence,
        presence_text=args.presence_text,
        logger=logger,
        receive=True,
    )
    try:
        discovery.start()
        logger.info(
            f"listening for announces as #{identity.blip_id} for {args.timeout:g}s..."
        )
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
        peers = discovery.peers()
        payload = {
            "ok": True,
            "self": _self_payload(identity, args),
            "count": len(peers),
            "peers": [peer.to_dict() for peer in peers],
        }
    finally:
        discovery.stop()

    if args.output:
        target = write_json(args.output, payload)
        logger.info(f"peer list written to {target}")
    if args.json:
        _emit_json(payload)
    else:
        print(format_peers(peers))
        if not peers:
            logger.info(
                "No peers answered. Check the LAN/VPN and firewall UDP 42069."
            )
    return 0


def cmd_send(args: argparse.Namespace, logger: Logger) -> int:
    identity = _load_identity(args)
    message = load_message(
        text=args.text,
        file_path=args.file,
        url=args.url,
        use_stdin=bool(args.stdin),
        max_bytes=args.max_input_bytes,
        url_timeout=args.url_timeout,
    )
    logger.debug(
        f"message source={message.kind} bytes={message.size_bytes} "
        f"origin={message.origin}"
    )

    host, port = _resolve_target(
        args, identity=identity, logger=logger, tcp_port_default=args.tcp_port
    )
    if args.peer_ip and not args.no_announce:
        sent = send_announce_once(
            identity,
            udp_port=args.udp_port,
            tcp_port=args.tcp_port,
            primary_ip=args.ip,
            targets=args.broadcast,
            presence=args.presence,
            presence_text=args.presence_text,
            logger=logger,
        )
        logger.debug(f"best-effort announce sent ({sent} datagrams)")

    result = send_message_to_peer(
        identity,
        args.peer,
        host,
        port,
        message.text,
        handshake=not args.no_handshake,
        connect_timeout=args.connect_timeout,
        handshake_timeout=args.handshake_timeout,
        wait_reply=args.wait_reply,
        logger=logger,
    )
    payload = {
        "ok": True,
        **result.to_dict(),
        "input": {
            "kind": message.kind,
            "origin": message.origin,
            "sizeBytes": message.size_bytes,
        },
    }
    if args.output:
        target = write_json(args.output, payload)
        logger.info(f"receipt written to {target}")
    if args.json:
        _emit_json(payload)
    else:
        print(
            f"sent to #{result.peer_id} at {result.host}:{result.port} "
            f"({result.bytes_sent} bytes, message {result.message_id}, "
            f"handshake={'yes' if result.handshaked else 'no'})"
        )
        if args.wait_reply:
            if result.reply is None:
                print("no reply received before timeout")
            else:
                print("reply: " + json.dumps(result.reply, ensure_ascii=False))
    return 0


def cmd_listen(args: argparse.Namespace, logger: Logger) -> int:
    identity = _load_identity(args)
    stop = threading.Event()
    message_count = 0
    writer = EventWriter(args.output, append=True)
    server: Optional[TcpInboxServer] = None
    discovery: Optional[Discovery] = None

    def on_frame(frame: dict[str, Any], metadata: dict[str, Any]) -> None:
        nonlocal message_count
        frame_type = frame.get("type")
        if frame_type == "message":
            message_count += 1
            event = {
                "event": "message",
                "from": frame.get("from"),
                "to": frame.get("to"),
                "text": str(frame.get("text") or ""),
                "messageId": frame.get("id"),
                "timestamp": frame.get("timestamp"),
                "receivedAt": metadata.get("receivedAt"),
                "receivedAtHuman": _iso_timestamp(metadata.get("receivedAt")),
                "remoteIp": metadata.get("remoteIp"),
                "remotePort": metadata.get("remotePort"),
                "authenticated": metadata.get("authenticated"),
                "peerId": metadata.get("peerId"),
                "frame": frame,
            }
            writer.write(event)
            if args.json:
                print(json.dumps(event, ensure_ascii=False), flush=True)
            else:
                print(format_event(event), flush=True)
            if args.once:
                stop.set()
            return
        if args.all_events:
            event = {
                "event": "frame",
                "type": frame_type,
                "from": frame.get("from"),
                "to": frame.get("to"),
                "receivedAt": metadata.get("receivedAt"),
                "receivedAtHuman": _iso_timestamp(metadata.get("receivedAt")),
                "remoteIp": metadata.get("remoteIp"),
                "remotePort": metadata.get("remotePort"),
                "authenticated": metadata.get("authenticated"),
                "frame": frame,
            }
            writer.write(event)
            if args.json:
                print(json.dumps(event, ensure_ascii=False), flush=True)
            logger.debug(f"frame {frame_type} from {metadata.get('remoteIp')}")

    try:
        server = TcpInboxServer(
            identity,
            port=args.tcp_port,
            on_frame=on_frame,
            logger=logger,
        )
        server.start()
        if not args.no_announce:
            discovery = Discovery(
                identity,
                udp_port=args.udp_port,
                tcp_port=server.bound_port,
                primary_ip=args.ip,
                targets=args.broadcast,
                presence=args.presence,
                presence_text=args.presence_text,
                logger=logger,
                receive=True,
            )
            discovery.start()
        logger.info(
            f"inbox ready as #{identity.blip_id} on TCP {server.bound_port}"
            + ("" if args.no_announce else f", announcing on UDP {args.udp_port}")
        )
        deadline = None if args.timeout <= 0 else time.monotonic() + args.timeout
        while not stop.is_set():
            if deadline is not None and time.monotonic() >= deadline:
                break
            stop.wait(0.2)
        if message_count == 0 and deadline is not None:
            logger.info("listener timeout reached with no messages")
        else:
            logger.info(f"listener stopped after {message_count} message(s)")
    finally:
        if discovery is not None:
            discovery.stop()
        if server is not None:
            server.stop()
        writer.close()
    return 0


def cmd_ping(args: argparse.Namespace, logger: Logger) -> int:
    identity = _load_identity(args)
    host, port = _resolve_target(
        args, identity=identity, logger=logger, tcp_port_default=args.tcp_port
    )
    latency = ping_peer(host, port, timeout=args.timeout, logger=logger)
    payload = {
        "ok": True,
        "peerId": args.peer,
        "host": host,
        "port": port,
        "latencyMs": round(latency, 2),
    }
    if args.json:
        _emit_json(payload)
    else:
        print(f"pong from #{args.peer} at {host}:{port} in {latency:.1f} ms")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logger = Logger(
        verbose=int(getattr(args, "verbose", 0) or 0),
        quiet=bool(getattr(args, "quiet", False)),
    )
    try:
        _normalize_args(args)
    except BlipCliError as exc:
        logger.error(exc.message)
        if exc.hint:
            logger.error(f"hint: {exc.hint}")
        return exc.exit_code

    handlers = {
        "identity": cmd_identity,
        "discover": cmd_discover,
        "send": cmd_send,
        "listen": cmd_listen,
        "ping": cmd_ping,
    }
    handler = handlers[args.command]
    try:
        return handler(args, logger)
    except BlipCliError as exc:
        logger.error(exc.message)
        if exc.hint:
            logger.error(f"hint: {exc.hint}")
        if args.verbose and exc.__cause__ is not None:
            logger.debug(f"cause: {exc.__cause__}")
        return exc.exit_code
    except KeyboardInterrupt:
        logger.warn("interrupted")
        return 1
    except Exception as exc:  # unexpected programming/runtime failure
        logger.error(f"unexpected failure: {exc}")
        if args.verbose:
            traceback.print_exc()
        return 1
