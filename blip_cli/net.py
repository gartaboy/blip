"""LAN discovery and TCP transport for the BLIP CLI core."""

from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional

from .crypto import Identity
from .errors import NetworkError, ProtocolError
from .log import Logger
from .protocol import (
    DEFAULT_TCP_PORT,
    DEFAULT_UDP_PORT,
    DISCOVERY_BROADCAST_PORTS,
    LineReader,
    Peer,
    build_announce,
    build_handshake,
    build_handshake_ack,
    build_message,
    encode_frame,
    now_ms,
    peer_from_announce,
    verify_handshake,
)

_SOCKET_REUSE = getattr(socket, "SO_REUSEPORT", None)


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------


def _add_unique(values: list[str], candidate: Any) -> None:
    if not candidate or not isinstance(candidate, str):
        return
    candidate = candidate.strip()
    if not candidate or candidate == "0.0.0.0":
        return
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return
    if candidate not in values:
        values.append(candidate)


def detect_local_ipv4() -> list[str]:
    """Best-effort list of local IPv4 addresses without third-party modules."""

    found: list[str] = []
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        _add_unique(found, probe.getsockname()[0])
    except OSError:
        pass
    finally:
        probe.close()

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            _add_unique(found, info[4][0])
    except OSError:
        pass

    non_loopback = [ip for ip in found if not ipaddress.ip_address(ip).is_loopback]
    if non_loopback:
        return non_loopback + [
            ip for ip in found if ipaddress.ip_address(ip).is_loopback
        ]
    return found or ["127.0.0.1"]


def choose_primary_ip(preferred: Optional[str] = None) -> str:
    if preferred:
        try:
            address = ipaddress.ip_address(preferred)
        except ValueError as exc:
            raise NetworkError(
                f"--ip must be an IPv4/IPv6 literal, got {preferred!r}",
                hint="Use --peer-ip for hostnames when sending.",
            ) from exc
        if address.version != 4:
            raise NetworkError("--ip must be an IPv4 address")
        return preferred
    for candidate in detect_local_ipv4():
        if not ipaddress.ip_address(candidate).is_loopback:
            return candidate
    return "127.0.0.1"


def announce_ips(primary: str) -> list[str]:
    values: list[str] = []
    _add_unique(values, primary)
    for candidate in detect_local_ipv4():
        if ipaddress.ip_address(candidate).is_loopback and primary != candidate:
            continue
        _add_unique(values, candidate)
    return values or [primary]


def broadcast_targets(primary: str, extra: Iterable[str] = ()) -> list[str]:
    targets: list[str] = []

    def add(value: str) -> None:
        value = value.strip()
        if value and value not in targets:
            targets.append(value)

    add("255.255.255.255")
    for source in (primary, *detect_local_ipv4()):
        try:
            address = ipaddress.ip_address(source)
        except ValueError:
            continue
        if address.version != 4 or address.is_loopback:
            continue
        try:
            network = ipaddress.ip_network(f"{source}/24", strict=False)
        except ValueError:
            continue
        add(str(network.broadcast_address))
    for value in extra:
        add(value)
    return targets


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


class Discovery:
    """Send signed announces and collect peers from UDP broadcasts."""

    def __init__(
        self,
        identity: Identity,
        *,
        udp_port: int = DEFAULT_UDP_PORT,
        tcp_port: int = DEFAULT_TCP_PORT,
        primary_ip: Optional[str] = None,
        targets: Optional[Iterable[str]] = None,
        presence: str = "online",
        presence_text: str = "",
        logger: Optional[Logger] = None,
        receive: bool = True,
    ):
        self.identity = identity
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.primary_ip = choose_primary_ip(primary_ip)
        self.local_ips = announce_ips(self.primary_ip)
        self.targets = broadcast_targets(self.primary_ip, targets or ())
        self.presence = presence
        self.presence_text = presence_text
        self.logger = logger or Logger(quiet=True)
        self.receive = receive
        self._peers: dict[int, Peer] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._socket: Optional[socket.socket] = None
        self._threads: list[threading.Thread] = []

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._socket is not None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if _SOCKET_REUSE is not None:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, _SOCKET_REUSE, 1)
                except OSError:
                    pass
            sock.bind(("0.0.0.0", self.udp_port if self.receive else 0))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(0.4)
        except OSError as exc:
            sock.close()
            raise NetworkError(
                f"cannot bind UDP {self.udp_port}: {exc}",
                hint="Close BLIP or choose another --udp-port.",
            ) from exc
        self._socket = sock
        self.logger.debug(
            f"UDP {'listening' if self.receive else 'announcing'} on "
            f"0.0.0.0:{sock.getsockname()[1]} as #{self.identity.blip_id} "
            f"({self.primary_ip})"
        )
        self._threads = [
            threading.Thread(
                target=self._announce_loop, name="blip-announce", daemon=True
            )
        ]
        if self.receive:
            self._threads.append(
                threading.Thread(
                    target=self._receive_loop, name="blip-discovery", daemon=True
                )
            )
        for thread in self._threads:
            thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        for thread in self._threads:
            thread.join(timeout=1.5)
        self._threads.clear()

    def __enter__(self) -> "Discovery":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    # -- announcing --------------------------------------------------------

    def _announce_packet(self) -> bytes:
        packet = build_announce(
            self.identity,
            ip=self.primary_ip,
            ips=self.local_ips,
            udp_port=self.udp_port,
            tcp_port=self.tcp_port,
            presence=self.presence,
            presence_text=self.presence_text,
        )
        return json.dumps(packet, separators=(",", ":")).encode("utf-8")

    def announce_once(self) -> int:
        sock = self._socket
        if sock is None:
            return 0
        payload = self._announce_packet()
        ports = []
        for port in (self.udp_port, *DISCOVERY_BROADCAST_PORTS):
            if port not in ports:
                ports.append(port)
        sent = 0
        for target in self.targets:
            for port in ports:
                try:
                    sock.sendto(payload, (target, port))
                    sent += 1
                except OSError as exc:
                    self.logger.debug(f"announce to {target}:{port} failed: {exc}")
        self.logger.debug(
            f"announce #{self.identity.blip_id} sent to {len(self.targets)} target(s)"
        )
        return sent

    def _announce_loop(self) -> None:
        self.announce_once()
        # BLIP's initial burst helps Wi-Fi/Ethernet peers see each other.
        for interval in (0.7, 1.1, 1.7):
            if self._stop.wait(interval):
                return
            self.announce_once()
        while not self._stop.wait(5.0):
            self.announce_once()

    # -- receiving ---------------------------------------------------------

    def _receive_loop(self) -> None:
        assert self._socket is not None
        sock = self._socket
        while not self._stop.is_set():
            try:
                data, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                packet = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.logger.debug(f"ignored non-JSON UDP packet from {address[0]}")
                continue
            if not isinstance(packet, dict) or packet.get("type") != "announce":
                continue
            try:
                peer = peer_from_announce(packet, address[0])
            except ProtocolError as exc:
                self.logger.debug(
                    f"ignored announce from {address[0]}: {exc.message}"
                )
                continue
            if peer.blip_id == self.identity.blip_id and address[0] in self.local_ips:
                continue
            with self._lock:
                previous = self._peers.get(peer.blip_id)
                self._peers[peer.blip_id] = peer
            if previous is None:
                self.logger.debug(
                    f"peer #{peer.blip_id} {peer.display_name} at "
                    f"{peer.ip}:{peer.tcp_port} ({peer.presence})"
                )
            elif (
                previous.display_name != peer.display_name
                or previous.presence != peer.presence
                or previous.ip != peer.ip
                or previous.tcp_port != peer.tcp_port
            ):
                self.logger.debug(
                    f"peer #{peer.blip_id} updated: {peer.presence}, "
                    f"{peer.ip}:{peer.tcp_port}"
                )

    def peers(self) -> list[Peer]:
        with self._lock:
            return sorted(self._peers.values(), key=lambda peer: peer.blip_id)

    def get_peer(self, peer_id: int) -> Optional[Peer]:
        with self._lock:
            return self._peers.get(int(peer_id))

    def wait_for_peer(self, peer_id: int, timeout: float) -> Optional[Peer]:
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            peer = self.get_peer(peer_id)
            if peer is not None or time.monotonic() >= deadline:
                return peer
            time.sleep(0.1)


def send_announce_once(
    identity: Identity,
    *,
    udp_port: int = DEFAULT_UDP_PORT,
    tcp_port: int = DEFAULT_TCP_PORT,
    primary_ip: Optional[str] = None,
    targets: Optional[Iterable[str]] = None,
    presence: str = "online",
    presence_text: str = "",
    logger: Optional[Logger] = None,
) -> int:
    """Fire one announce without binding the discovery port.

    Used by ``send --peer-ip`` so the receiver's discovery can learn about us
    even when we do not need to receive replies.
    """

    log = logger or Logger(quiet=True)
    ip = choose_primary_ip(primary_ip)
    packet = build_announce(
        identity,
        ip=ip,
        ips=announce_ips(ip),
        udp_port=udp_port,
        tcp_port=tcp_port,
        presence=presence,
        presence_text=presence_text,
    )
    payload = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("0.0.0.0", 0))
        targets_list = broadcast_targets(ip, targets or ())
        ports = []
        for port in (udp_port, *DISCOVERY_BROADCAST_PORTS):
            if port not in ports:
                ports.append(port)
        for target in targets_list:
            for port in ports:
                try:
                    sock.sendto(payload, (target, port))
                    sent += 1
                except OSError as exc:
                    log.debug(f"announce to {target}:{port} failed: {exc}")
    finally:
        sock.close()
    return sent


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------


class SocketLineReader:
    """Read newline-delimited JSON from one blocking socket."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self._reader = LineReader()
        self._queue: deque[dict[str, Any]] = deque()

    def read(self, timeout: float) -> Optional[dict[str, Any]]:
        """Return a frame, or ``None`` when the timeout expires."""

        if self._queue:
            return self._queue.popleft()
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                self.sock.settimeout(remaining)
                chunk = self.sock.recv(65536)
            except socket.timeout:
                return None
            except OSError as exc:
                raise NetworkError(f"socket read failed: {exc}") from exc
            if not chunk:
                raise NetworkError("peer closed the connection")
            for frame in self._reader.feed(chunk):
                self._queue.append(frame)
            if self._queue:
                return self._queue.popleft()


def _open_tcp(host: str, port: int, timeout: float) -> socket.socket:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except socket.timeout as exc:
        raise NetworkError(
            f"connection to {host}:{port} timed out after {timeout:g}s"
        ) from exc
    except OSError as exc:
        raise NetworkError(f"cannot connect to {host}:{port}: {exc}") from exc
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(timeout)
    except OSError:
        pass
    return sock


def _send_packet(sock: socket.socket, packet: dict[str, Any]) -> int:
    try:
        data = encode_frame(packet)
        sock.sendall(data)
        return len(data)
    except (OSError, ValueError) as exc:
        raise NetworkError(f"failed to send frame: {exc}") from exc


@dataclass(frozen=True)
class SendResult:
    peer_id: int
    host: str
    port: int
    message_id: str
    timestamp: int
    bytes_sent: int
    handshaked: bool
    reply: Optional[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": True,
            "peerId": self.peer_id,
            "host": self.host,
            "port": self.port,
            "messageId": self.message_id,
            "timestamp": self.timestamp,
            "bytesSent": self.bytes_sent,
            "handshaked": self.handshaked,
            "reply": self.reply,
        }


def _perform_handshake(
    sock: socket.socket,
    reader: SocketLineReader,
    identity: Identity,
    peer_id: int,
    timeout: float,
    logger: Logger,
) -> bool:
    _send_packet(sock, build_handshake(identity))
    ack = reader.read(timeout)
    if ack is None:
        logger.debug("handshake timed out; falling back to plaintext")
        return False
    try:
        info = verify_handshake(ack, expected_from=peer_id)
    except ProtocolError as exc:
        logger.warn(f"handshake failed: {exc.message}; using plaintext")
        return False
    logger.debug(
        f"handshake with #{info.from_id} ok (proto {info.mesh_proto}, "
        f"encrypted={info.encrypted_capable})"
    )
    return True


def send_message_to_peer(
    identity: Identity,
    peer_id: int,
    host: str,
    port: int,
    text: str,
    *,
    handshake: bool = True,
    connect_timeout: float = 5.0,
    handshake_timeout: float = 3.0,
    wait_reply: float = 0.0,
    logger: Optional[Logger] = None,
) -> SendResult:
    log = logger or Logger(quiet=True)
    used_handshake = False
    sock = _open_tcp(host, port, connect_timeout)
    reader = SocketLineReader(sock)
    try:
        if handshake:
            used_handshake = _perform_handshake(
                sock, reader, identity, peer_id, handshake_timeout, log
            )
            if not used_handshake and log.verbose:
                log.debug("sending as legacy plaintext session")
        timestamp = now_ms()
        message = build_message(identity, peer_id, text, timestamp_ms=timestamp)
        sent = _send_packet(sock, message)
        reply = None
        if wait_reply > 0:
            try:
                reply = reader.read(wait_reply)
            except NetworkError as exc:
                log.debug(f"no reply: {exc.message}")
        return SendResult(
            peer_id=peer_id,
            host=host,
            port=port,
            message_id=str(message["id"]),
            timestamp=timestamp,
            bytes_sent=sent,
            handshaked=used_handshake,
            reply=reply,
        )
    finally:
        try:
            sock.close()
        except OSError:
            pass


def ping_peer(
    host: str,
    port: int,
    *,
    timeout: float = 3.0,
    logger: Optional[Logger] = None,
) -> float:
    log = logger or Logger(quiet=True)
    started = time.monotonic()
    sock = _open_tcp(host, port, timeout)
    reader = SocketLineReader(sock)
    try:
        _send_packet(sock, {"type": "ping"})
        frame = reader.read(timeout)
        if frame is None:
            raise NetworkError(f"no pong from {host}:{port} within {timeout:g}s")
        if frame.get("type") != "pong":
            raise NetworkError(
                f"unexpected reply from {host}:{port}: {frame.get('type')!r}"
            )
        elapsed = (time.monotonic() - started) * 1000.0
        log.debug(f"pong from {host}:{port} in {elapsed:.1f} ms")
        return elapsed
    finally:
        try:
            sock.close()
        except OSError:
            pass


class TcpInboxServer:
    """Minimal BLIP-compatible TCP listener.

    It answers pings, completes the legacy v1 handshake, and forwards every
    other frame to the callback.  Messages are accepted from unauthenticated
    sockets too, mirroring BLIP's legacy compatibility mode.
    """

    def __init__(
        self,
        identity: Identity,
        *,
        port: int = DEFAULT_TCP_PORT,
        on_frame: Optional[
            Callable[[dict[str, Any], dict[str, Any]], None]
        ] = None,
        logger: Optional[Logger] = None,
    ):
        self.identity = identity
        self.port = port
        self.on_frame = on_frame
        self.logger = logger or Logger(quiet=True)
        self._stop = threading.Event()
        self._socket: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._clients: set[socket.socket] = set()
        self._clients_lock = threading.Lock()
        self.bound_port = port

    def start(self) -> None:
        if self._socket is not None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.port))
            sock.listen(16)
            sock.settimeout(0.4)
        except OSError as exc:
            sock.close()
            raise NetworkError(
                f"cannot bind TCP {self.port}: {exc}",
                hint="Close BLIP or choose another --tcp-port.",
            ) from exc
        self._socket = sock
        self.bound_port = int(sock.getsockname()[1])
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="blip-tcp-accept", daemon=True
        )
        self._accept_thread.start()
        self.logger.debug(f"TCP listening on 0.0.0.0:{self.bound_port}")

    def stop(self) -> None:
        self._stop.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        with self._clients_lock:
            clients = list(self._clients)
            self._clients.clear()
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=1.5)
            self._accept_thread = None

    def __enter__(self) -> "TcpInboxServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def _accept_loop(self) -> None:
        assert self._socket is not None
        while not self._stop.is_set():
            try:
                client, address = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                client.settimeout(0.5)
                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            with self._clients_lock:
                self._clients.add(client)
            self.logger.debug(f"inbound TCP from {address[0]}:{address[1]}")
            threading.Thread(
                target=self._client_loop,
                args=(client, address),
                name=f"blip-tcp-{address[0]}",
                daemon=True,
            ).start()

    def _client_loop(self, client: socket.socket, address) -> None:
        reader = LineReader()
        session = {"peer_id": None, "authenticated": False}
        try:
            while not self._stop.is_set():
                try:
                    chunk = client.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                try:
                    frames = reader.feed(chunk)
                except ProtocolError as exc:
                    self.logger.warn(
                        f"dropping {address[0]}:{address[1]}: {exc.message}"
                    )
                    break
                for frame in frames:
                    if not self._handle_frame(client, frame, session, address):
                        return
        finally:
            with self._clients_lock:
                self._clients.discard(client)
            try:
                client.close()
            except OSError:
                pass

    def _handle_frame(
        self,
        client: socket.socket,
        frame: dict[str, Any],
        session: dict[str, Any],
        address,
    ) -> bool:
        frame_type = frame.get("type")
        if frame_type == "ping":
            try:
                client.sendall(encode_frame({"type": "pong"}))
            except OSError:
                return False
            return True

        if frame_type == "mesh-handshake":
            try:
                info = verify_handshake(frame)
            except ProtocolError as exc:
                self.logger.warn(f"bad handshake from {address[0]}: {exc.message}")
                return True
            session["peer_id"] = info.from_id
            session["authenticated"] = True
            ack = build_handshake_ack(
                self.identity, peer_pubkey=info.mesh_pubkey
            )
            try:
                client.sendall(encode_frame(ack))
            except OSError:
                return False
            self.logger.debug(f"legacy handshake from #{info.from_id}")
            return True

        if frame_type == "mesh-handshake-ack":
            return True

        metadata = {
            "remoteIp": address[0],
            "remotePort": address[1],
            "peerId": session["peer_id"],
            "authenticated": bool(session["authenticated"]),
            "receivedAt": now_ms(),
        }
        if self.on_frame is not None:
            try:
                self.on_frame(frame, metadata)
            except Exception as exc:  # callback errors must not kill the listener
                self.logger.error(f"frame handler failed: {exc}")
        return True
