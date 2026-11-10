"""Ed25519 signatures and BLIP-compatible key encoding.

BLIP announces are signed with Ed25519 and advertise the public key as a
base64-encoded SPKI DER structure.  This module keeps the CLI dependency-free
by implementing RFC 8032 signatures in pure Python.  It is used only for
identity/authentication metadata, not for encrypting payloads.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Optional

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)

_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")

# Extended twisted-Edwards coordinates: (X, Y, Z, T).
_ZERO = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> int:
    y2 = y * y % _P
    x2 = (y2 - 1) * pow(_D * y2 + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        raise ValueError("invalid Ed25519 point")
    if (x & 1) != sign:
        x = _P - x
    return x


_BY = 4 * pow(5, _P - 2, _P) % _P
_BASE = (_recover_x(_BY, 0), _BY, 1, _recover_x(_BY, 0) * _BY % _P)


def _point_add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d = 2 * z1 * z2 % _P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_double(p: tuple[int, int, int, int]):
    x1, y1, z1, _ = p
    a = x1 * x1 % _P
    b = y1 * y1 % _P
    c = 2 * z1 * z1 % _P
    d = -a
    e = (x1 + y1) * (x1 + y1) - a - b
    g = d + b
    f = g - c
    h = d - b
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalarmult(point: tuple[int, int, int, int], scalar: int):
    result = _ZERO
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_double(addend)
        scalar >>= 1
    return result


def _encode_point(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    z_inv = pow(z, _P - 2, _P)
    x = x * z_inv % _P
    y = y * z_inv % _P
    value = y | ((x & 1) << 255)
    return value.to_bytes(32, "little")


def _decode_point(raw: bytes) -> tuple[int, int, int, int]:
    if len(raw) != 32:
        raise ValueError("invalid Ed25519 point length")
    value = int.from_bytes(raw, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= _P:
        raise ValueError("non-canonical Ed25519 point")
    x = _recover_x(y, sign)
    return (x, y, 1, x * y % _P)


def _clamp(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def public_key_from_seed(seed: bytes) -> bytes:
    """Return the raw 32-byte Ed25519 public key for a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    scalar, _ = _clamp(seed)
    return _encode_point(_scalarmult(_BASE, scalar))


def sign(seed: bytes, message: bytes) -> bytes:
    """Create a 64-byte RFC 8032 signature."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    scalar, prefix = _clamp(seed)
    public = _encode_point(_scalarmult(_BASE, scalar))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    encoded_r = _encode_point(_scalarmult(_BASE, r))
    k = int.from_bytes(
        hashlib.sha512(encoded_r + public + message).digest(), "little"
    ) % _L
    s = (r + k * scalar) % _L
    return encoded_r + s.to_bytes(32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature without raising for malformed input."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        r_encoded = signature[:32]
        s = int.from_bytes(signature[32:], "little")
        if s >= _L:
            return False
        a_point = _decode_point(public_key)
        r_point = _decode_point(r_encoded)
        k = int.from_bytes(
            hashlib.sha512(r_encoded + public_key + message).digest(), "little"
        ) % _L
        left = _scalarmult(_BASE, s)
        right = _point_add(r_point, _scalarmult(a_point, k))
        return _encode_point(left) == _encode_point(right)
    except (ValueError, OverflowError):
        return False


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid base64") from exc


def public_spki_from_seed(seed: bytes) -> bytes:
    return _SPKI_PREFIX + public_key_from_seed(seed)


def public_key_from_spki_b64(value: str) -> bytes:
    der = b64d(value)
    if len(der) != len(_SPKI_PREFIX) + 32 or not der.startswith(_SPKI_PREFIX):
        raise ValueError("not an Ed25519 SPKI public key")
    return der[len(_SPKI_PREFIX) :]


def public_spki_b64_from_seed(seed: bytes) -> str:
    return b64e(public_spki_from_seed(seed))


def private_pkcs8_from_seed(seed: bytes) -> bytes:
    return _PKCS8_PREFIX + seed


def default_identity_path() -> Path:
    override = os.environ.get("BLIP_CLI_IDENTITY")
    if override:
        return Path(override).expanduser()
    if os.name == "nt" and os.environ.get("APPDATA"):
        base = Path(os.environ["APPDATA"])
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "blip-cli" / "identity.json"


@dataclass(frozen=True)
class Identity:
    blip_id: int
    display_name: str
    seed: bytes

    @property
    def public_key(self) -> bytes:
        return public_key_from_seed(self.seed)

    @property
    def public_key_b64(self) -> str:
        return b64e(public_spki_from_seed(self.seed))

    def sign(self, message: bytes) -> bytes:
        return sign(self.seed, message)

    def with_changes(self, *, blip_id: Optional[int] = None, display_name: Optional[str] = None):
        return replace(
            self,
            blip_id=self.blip_id if blip_id is None else blip_id,
            display_name=self.display_name if display_name is None else display_name,
        )


def validate_blip_id(value: int) -> int:
    if not isinstance(value, int) or not 1 <= value <= 64:
        raise ValueError("BLIP ID must be an integer between 1 and 64")
    return value


def new_identity(blip_id: int, display_name: str) -> Identity:
    return Identity(
        blip_id=validate_blip_id(int(blip_id)),
        display_name=display_name,
        seed=os.urandom(32),
    )


def save_identity(path: Path, identity: Identity) -> None:
    import json

    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "blipId": identity.blip_id,
        "displayName": identity.display_name,
        "seed": b64e(identity.seed),
        "publicKey": identity.public_key_b64,
    }
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def load_identity(path: Path) -> Optional[Identity]:
    import json

    path = Path(path).expanduser()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        raw_seed = b64d(str(data["seed"]))
        identity = Identity(
            blip_id=validate_blip_id(int(data["blipId"])),
            display_name=str(data.get("displayName", "blip-cli")),
            seed=raw_seed,
        )
        stored_public = data.get("publicKey")
        if stored_public and stored_public != identity.public_key_b64:
            raise ValueError("stored public key does not match seed")
        return identity
    except (KeyError, TypeError, ValueError, OSError) as exc:
        raise ValueError(f"invalid identity file {path}: {exc}") from exc


def load_or_create_identity(
    path: Path,
    *,
    blip_id: int = 64,
    display_name: str = "blip-cli",
    rotate: bool = False,
) -> Identity:
    existing = load_identity(path)
    if existing is None:
        identity = new_identity(blip_id, display_name)
        save_identity(path, identity)
        return identity
    if rotate:
        identity = Identity(existing.blip_id, existing.display_name, os.urandom(32))
        save_identity(path, identity)
        return identity
    updated = existing.with_changes(blip_id=blip_id, display_name=display_name)
    if updated != existing:
        save_identity(path, updated)
    return updated
