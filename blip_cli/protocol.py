"""BLIP wire protocol: signed announces, v1 handshake, JSON-line messages.

The wire format is compatible with BLIP 3.x's legacy/plaintext mode:

* discovery: UDP broadcast with a JSON ``announce`` signed by Ed25519;
* transport: TCP, one JSON object per ``\\n``-terminated line;
* authentication: optional legacy v1 ``mesh-handshake`` (no ECDH cipher).

Encrypted (meshProto 2) sessions from newer clients are deliberately not
implemented.  By advertising ``meshProto: 1`` the CLI asks peers to use the
legacy handshake and plaintext frames, which BLIP accepts when
"Allow older BLIP versions" is enabled (the default).
"""

from __future__ import annotations

import json
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .crypto import (
    Identity,
    b64d,
    b64e,
    public_key_from_spki_b64,
    verify,
)
from .errors import ProtocolError, UsageError

BLIP_ID_MIN = 1
BLIP_ID_MAX = 64
DEFAULT_UDP_PORT = 42069
DEFAULT_TCP_PORT = 42070
DISCOVERY_BROADCAST_PORTS = (42069, 42071, 42073, 42075)
MAX_LINE_BYTES = 4 * 1024 * 1024
ANNOUNCE_FRESHNESS_MS = 5 * 60 * 1000
MESH_PROTO_LEGACY = 1

_PRESENCE_VALUES = {"online", "away", "busy"}


def now_ms() -> int:
    return int(time.time() * 1000)


def is_valid_blip_id(value: Any) -> bool:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return False
    return BLIP_ID_MIN <= number <= BLIP_ID_MAX and str(value).strip() == str(number)


def sanitize_text(value: Any, limit: int = 48) -> str:
    """Match BLIP's control-character scrub and remove our delimiter."""

    if value is None:
        return ""
    text = str(value)
    text = "".join(
        char for char in text if not (ord(char) < 0x20 or ord(char) == 0x7F)
    )
    return text.replace("|", "/").strip()[:limit]


def normalize_presence(value: Any) -> str:
    text = str(value or "online").strip().lower()
    return text if text in _PRESENCE_VALUES else "online"


@dataclass(frozen=True)
class Peer:
    blip_id: int
    display_name: str
    presence: str
    presence_text: str
    ip: str
    ips: tuple[str, ...]
    udp_port: int
    tcp_port: int
    mesh_proto: int
    mesh_pubkey: str
    last_seen_ms: int
    source_ip: str
    verified: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "blipId": self.blip_id,
            "displayName": self.display_name,
            "presence": self.presence,
            "presenceText": self.presence_text,
            "ip": self.ip,
            "ips": list(self.ips),
            "udpPort": self.udp_port,
            "tcpPort": self.tcp_port,
            "meshProto": self.mesh_proto,
            "meshLegacy": self.mesh_proto < 2,
            "meshPubkey": self.mesh_pubkey,
            "lastSeen": self.last_seen_ms,
            "sourceIp": self.source_ip,
            "verified": self.verified,
        }


def announce_canonical(fields: dict[str, Any]) -> str:
    return (
        "blip-announce-v1"
        f"|{fields['blipId']}"
        f"|{fields['displayName']}"
        f"|{fields['presence']}"
        f"|{fields['presenceText']}"
        f"|{fields['ip']}"
        f"|{fields['udpPort']}"
        f"|{fields['tcpPort']}"
        f"|{fields['meshAnnounceTs']}"
        f"|{fields['meshPubkey']}"
    )


def build_announce(
    identity: Identity,
    *,
    ip: str,
    ips: Iterable[str],
    udp_port: int,
    tcp_port: int,
    presence: str = "online",
    presence_text: str = "",
    timestamp_ms: Optional[int] = None,
) -> dict[str, Any]:
    """Build a signed announce packet accepted by ``shouldAcceptAnnounce``."""

    presence = normalize_presence(presence)
    presence_text = sanitize_text(presence_text)
    display_name = sanitize_text(identity.display_name, limit=64) or "blip-cli"
    timestamp = now_ms() if timestamp_ms is None else int(timestamp_ms)
    mesh_pubkey = identity.public_key_b64
    canonical = announce_canonical(
        {
            "blipId": identity.blip_id,
            "displayName": display_name,
            "presence": presence,
            "presenceText": presence_text,
            "ip": ip,
            "udpPort": udp_port,
            "tcpPort": tcp_port,
            "meshAnnounceTs": timestamp,
            "meshPubkey": mesh_pubkey,
        }
    )
    signature = b64e(identity.sign(canonical.encode("utf-8")))
    unique_ips = []
    for candidate in (ip, *ips):
        if candidate and candidate not in unique_ips:
            unique_ips.append(candidate)
    return {
        "type": "announce",
        "blipId": identity.blip_id,
        "displayName": display_name,
        "presence": presence,
        "presenceText": presence_text,
        "ip": ip,
        "ips": unique_ips,
        "udpPort": udp_port,
        "tcpPort": tcp_port,
        "meshProto": MESH_PROTO_LEGACY,
        "meshPubkey": mesh_pubkey,
        "meshAnnounceTs": timestamp,
        "meshAnnounceSig": signature,
    }


def verify_announce_details(
    data: Any, *, now: Optional[int] = None
) -> tuple[bool, str]:
    if not isinstance(data, dict) or data.get("type") != "announce":
        return False, "not_an_announce"
    try:
        blip_id = int(data.get("blipId"))
        udp_port = int(data.get("udpPort"))
        tcp_port = int(data.get("tcpPort"))
        timestamp = int(data.get("meshAnnounceTs"))
        mesh_proto = int(data.get("meshProto"))
    except (TypeError, ValueError):
        return False, "bad_numeric_fields"
    if not BLIP_ID_MIN <= blip_id <= BLIP_ID_MAX:
        return False, "bad_blip_id"
    if not (1 <= udp_port <= 65535 and 1 <= tcp_port <= 65535):
        return False, "bad_port"
    if mesh_proto < 1 or mesh_proto > 2:
        return False, "bad_mesh_proto"
    current = now_ms() if now is None else int(now)
    if abs(current - timestamp) > ANNOUNCE_FRESHNESS_MS:
        return False, "stale_announce"

    mesh_pubkey = str(data.get("meshPubkey") or "")
    signature = str(data.get("meshAnnounceSig") or "")
    if not mesh_pubkey or not signature:
        return False, "missing_signature"
    try:
        raw_public = public_key_from_spki_b64(mesh_pubkey)
        raw_signature = b64d(signature)
    except ValueError:
        return False, "bad_key_or_signature"

    canonical = announce_canonical(
        {
            "blipId": blip_id,
            "displayName": str(data.get("displayName") or ""),
            "presence": str(data.get("presence") or "online"),
            "presenceText": str(data.get("presenceText") or ""),
            "ip": str(data.get("ip") or ""),
            "udpPort": udp_port,
            "tcpPort": tcp_port,
            "meshAnnounceTs": timestamp,
            "meshPubkey": mesh_pubkey,
        }
    )
    if not verify(raw_public, canonical.encode("utf-8"), raw_signature):
        return False, "bad_signature"
    return True, "ok"


def verify_announce(data: Any, *, now: Optional[int] = None) -> bool:
    return verify_announce_details(data, now=now)[0]


def peer_from_announce(data: dict[str, Any], source_ip: str) -> Peer:
    """Convert a verified announce to a dialable peer record."""

    ok, reason = verify_announce_details(data)
    if not ok:
        raise ProtocolError(f"invalid announce: {reason}")

    blip_id = int(data["blipId"])
    announced_ip = str(data.get("ip") or "").strip()
    primary_ip = announced_ip or source_ip
    all_ips: list[str] = []
    for candidate in (primary_ip, source_ip, *list(data.get("ips") or [])):
        if candidate and isinstance(candidate, str) and candidate not in all_ips:
            all_ips.append(candidate)
    return Peer(
        blip_id=blip_id,
        display_name=str(data.get("displayName") or f"BLIP-{blip_id}"),
        presence=normalize_presence(data.get("presence")),
        presence_text=sanitize_text(data.get("presenceText")),
        ip=primary_ip,
        ips=tuple(all_ips),
        udp_port=int(data.get("udpPort") or DEFAULT_UDP_PORT),
        tcp_port=int(data.get("tcpPort") or DEFAULT_TCP_PORT),
        mesh_proto=int(data.get("meshProto") or MESH_PROTO_LEGACY),
        mesh_pubkey=str(data.get("meshPubkey") or ""),
        last_seen_ms=now_ms(),
        source_ip=source_ip,
    )


def handshake_canonical(
    from_id: int,
    timestamp: int,
    nonce: str,
    mesh_pubkey: str,
    ecdh_pubkey: str = "",
) -> str:
    if ecdh_pubkey:
        return (
            f"blip-handshake-v2|{from_id}|{timestamp}|{nonce}"
            f"|{mesh_pubkey}|{ecdh_pubkey}"
        )
    return f"blip-handshake-v1|{from_id}|{timestamp}|{nonce}|{mesh_pubkey}"


def build_handshake(
    identity: Identity, *, timestamp_ms: Optional[int] = None
) -> dict[str, Any]:
    timestamp = now_ms() if timestamp_ms is None else int(timestamp_ms)
    nonce = f"{timestamp}-{secrets.token_hex(4)}"
    mesh_pubkey = identity.public_key_b64
    canonical = handshake_canonical(identity.blip_id, timestamp, nonce, mesh_pubkey)
    signature = b64e(identity.sign(canonical.encode("utf-8")))
    return {
        "type": "mesh-handshake",
        "meshProto": MESH_PROTO_LEGACY,
        "from": identity.blip_id,
        "ts": timestamp,
        "nonce": nonce,
        "meshPubkey": mesh_pubkey,
        "sig": signature,
    }


def build_handshake_ack(
    identity: Identity,
    *,
    peer_pubkey: str = "",
    timestamp_ms: Optional[int] = None,
) -> dict[str, Any]:
    timestamp = now_ms() if timestamp_ms is None else int(timestamp_ms)
    nonce = f"{timestamp}-{secrets.token_hex(4)}"
    mesh_pubkey = identity.public_key_b64
    canonical = handshake_canonical(identity.blip_id, timestamp, nonce, mesh_pubkey)
    signature = b64e(identity.sign(canonical.encode("utf-8")))
    packet = {
        "type": "mesh-handshake-ack",
        "meshProto": MESH_PROTO_LEGACY,
        "from": identity.blip_id,
        "ts": timestamp,
        "nonce": nonce,
        "meshPubkey": mesh_pubkey,
        "sig": signature,
    }
    if peer_pubkey:
        packet["peerPubkey"] = peer_pubkey
    return packet


@dataclass(frozen=True)
class HandshakeInfo:
    from_id: int
    mesh_pubkey: str
    mesh_proto: int
    nonce: str
    timestamp: int
    encrypted_capable: bool


def verify_handshake(
    packet: Any, *, expected_from: Optional[int] = None
) -> HandshakeInfo:
    if not isinstance(packet, dict):
        raise ProtocolError("handshake is not an object")
    if packet.get("type") not in {"mesh-handshake", "mesh-handshake-ack"}:
        raise ProtocolError("not a handshake packet")
    try:
        from_id = int(packet.get("from"))
        timestamp = int(packet.get("ts"))
        mesh_proto = int(packet.get("meshProto") or 1)
    except (TypeError, ValueError) as exc:
        raise ProtocolError("handshake has bad numeric fields") from exc
    if not BLIP_ID_MIN <= from_id <= BLIP_ID_MAX:
        raise ProtocolError("handshake has invalid BLIP ID")
    if expected_from is not None and from_id != int(expected_from):
        raise ProtocolError(
            f"handshake from #{from_id}, expected #{int(expected_from)}"
        )
    mesh_pubkey = str(packet.get("meshPubkey") or "")
    nonce = str(packet.get("nonce") or "")
    signature = str(packet.get("sig") or "")
    ecdh_pubkey = str(packet.get("ecdhPubkey") or "")
    if not mesh_pubkey or not nonce or not signature:
        raise ProtocolError("handshake is missing signature fields")
    try:
        raw_public = public_key_from_spki_b64(mesh_pubkey)
        raw_signature = b64d(signature)
    except ValueError as exc:
        raise ProtocolError("handshake has an invalid public key/signature") from exc
    canonical = handshake_canonical(
        from_id,
        timestamp,
        nonce,
        mesh_pubkey,
        ecdh_pubkey if mesh_proto >= 2 else "",
    )
    if not verify(raw_public, canonical.encode("utf-8"), raw_signature):
        raise ProtocolError("handshake signature verification failed")
    return HandshakeInfo(
        from_id=from_id,
        mesh_pubkey=mesh_pubkey,
        mesh_proto=mesh_proto,
        nonce=nonce,
        timestamp=timestamp,
        encrypted_capable=mesh_proto >= 2 and bool(ecdh_pubkey),
    )


def new_message_id() -> str:
    return uuid.uuid4().hex


def build_message(
    identity: Identity,
    peer_id: int,
    text: str,
    *,
    message_id: Optional[str] = None,
    timestamp_ms: Optional[int] = None,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    message = {
        "type": "message",
        "from": identity.blip_id,
        "to": int(peer_id),
        "text": text,
        "id": message_id or new_message_id(),
        "timestamp": now_ms() if timestamp_ms is None else int(timestamp_ms),
    }
    if extra:
        for key, value in extra.items():
            if key not in message and value is not None:
                message[key] = value
    return message


def encode_frame(packet: dict[str, Any]) -> bytes:
    if not isinstance(packet, dict):
        raise ValueError("frame must be a JSON object")
    try:
        payload = json.dumps(
            packet, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"frame is not JSON serializable: {exc}") from exc
    if len(payload) > MAX_LINE_BYTES:
        raise ValueError("frame exceeds the 4 MiB BLIP limit")
    return payload + b"\n"


@dataclass
class LineReader:
    """Incremental newline-delimited JSON reader with BLIP's size limit."""

    max_bytes: int = MAX_LINE_BYTES
    _buffer: bytearray = field(default_factory=bytearray)

    def feed(self, chunk: bytes) -> list[dict[str, Any]]:
        if not chunk:
            return []
        self._buffer.extend(chunk)
        if len(self._buffer) > self.max_bytes:
            self._buffer.clear()
            raise ProtocolError("incoming TCP line exceeds 4 MiB")
        frames: list[dict[str, Any]] = []
        while True:
            index = self._buffer.find(b"\n")
            if index < 0:
                break
            raw = bytes(self._buffer[:index])
            del self._buffer[: index + 1]
            if not raw.strip():
                continue
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ProtocolError("incoming frame is not valid UTF-8") from exc
            try:
                packet = json.loads(decoded)
            except json.JSONDecodeError as exc:
                raise ProtocolError(f"incoming frame is not valid JSON: {exc}") from exc
            if not isinstance(packet, dict):
                raise ProtocolError("incoming frame is not a JSON object")
            frames.append(packet)
        return frames

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)


def validate_peer_id(value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise UsageError("peer ID must be an integer from 1 to 64") from exc
    if not BLIP_ID_MIN <= number <= BLIP_ID_MAX:
        raise UsageError("peer ID must be an integer from 1 to 64")
    return number


def validate_port(value: Any, label: str = "port") -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise UsageError(f"{label} must be an integer from 1 to 65535") from exc
    if not 1 <= number <= 65535:
        raise UsageError(f"{label} must be an integer from 1 to 65535")
    return number
