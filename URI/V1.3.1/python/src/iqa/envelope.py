"""iqa.envelope -- AE-128, the fixed 128-byte attestation envelope (companion draft v0.3).

Authority boundaries
    Layout .......... ae128-draft-v0.3 sec. 2 (sole authority; this module
                      implements it byte for byte)
    Canonical rule .. draft sec. 3 (HMAC over the full frame, attestation zeroed)
    Verification .... draft sec. 4 (fail-closed, constant-time compare)
    Standing codes .. AICENT-009 sec. 11.1.1 closed set (ghost/probation/
                      radiant/genesis -> 0x00/0x01/0x02/0x03)

Relationship to the RTTP pulse frame
    The pulse frame (PulseHeader128, SPEC/RTTP-FRAME-EXT-v1.2.6) is the
    QUESTION carrier (rttp side, magic "RTTP", ROUTE_SHARD at 0x36). AE-128
    is the ANSWER carrier (iqa side, magic "IQAE"). The two formats do not
    parse each other and MUST NOT be conflated. The intent_shard at offset 16
    is the same 16-octet derivation the pulse frame carries at 0x36 -- one
    subject, one derived address, two carriers. That overlap is by design and
    is NOT a compatibility claim.

Design rules inherited from the codec discipline:
    * Malformed input is REJECTED, never normalised.
    * A check that cannot be performed is a failure, never a pass.
    * Zero dependencies: standard library only (hashlib, hmac, struct, time).
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import time

#: Frame size in octets -- fixed; a receiver MUST reject any other length.
SIZE = 128

#: Magic at offset 0: 'IQAE' (IQA Envelope) -- scheme-anchored, mirroring the
#: pulse frame's "RTTP" magic pattern. Four printable ASCII bytes.
MAGIC = b"IQAE"

#: The only frame version this module knows. Unknown versions fail closed.
VERSION = 1

#: The only algorithm byte defined in version 1. 0x00 is invalid; others TBD.
ALGORITHM_HMAC_SHA256 = 0x01

# Fixed offsets (zero-based) -- the whole point of the format.
OFF_MAGIC = 0          # 4  magic
OFF_VERSION = 4        # 1  version
OFF_ALGORITHM = 5      # 1  algorithm
OFF_FLAGS = 6          # 2  u16 BE, unassigned in version 1 (send 0x0000)
OFF_LEASE = 8          # 8  u64 BE Unix seconds -- verdict valid until
OFF_SHARD = 16         # 16 ROUTE_SHARD of the subject (I-D sec. 4.4)
OFF_ATTESTATION = 32   # 32 HMAC-SHA256, full frame with this field zeroed
OFF_ORGAN = 64         # 8  US-ASCII organ tag, right-padded with 0x00
OFF_NONCE = 72         # 8  u64 BE, unique per verdict issued
OFF_STANDING = 80      # 1  closed-set standing code (added in draft v0.3)
OFF_RESERVED = 81      # 15 MUST be all zeros
OFF_EXTENSION = 96     # 32 MUST be all zeros in version 1

#: Standing closed set per AICENT-009 sec. 11.1.1 -- wire codes and names.
STANDING_CODES = {"ghost": 0x00, "probation": 0x01, "radiant": 0x02,
                  "genesis": 0x03}
#: The reverse map: wire code -> lowercase name.
STANDING_NAMES = {code: name for name, code in STANDING_CODES.items()}

_ORGAN_LEN = 8
_SHARD_LEN = 16
_ATTESTATION_LEN = 32
_PRINTABLE = frozenset(range(0x20, 0x7F))


class EnvelopeError(ValueError):
    """The only error type raised by this module."""


def _fail(reason: str) -> "EnvelopeError":
    return EnvelopeError("AE-128: " + reason)


def derive_intent_shard(canonical_authority: str) -> bytes:
    """ROUTE_SHARD = SHA-256(ASCII(canonical_authority))[0:16] (I-D sec. 4.4).

    This is the same derivation the rttp side performs for its pulse frame
    (the 16 octets at offset 0x36). It is a pure computation: no registry, no
    resolver, no network. NOTE: this is NOT ``iqa_uri.derive_route`` -- that
    is the 4-octet IQA_ROUTE address fingerprint. The two numbers are about
    different things and MUST NOT be conflated.
    """
    if not canonical_authority:
        raise _fail("derive_intent_shard: authority is empty")
    try:
        return hashlib.sha256(canonical_authority.encode("ascii")).digest()[:_SHARD_LEN]
    except UnicodeEncodeError:
        raise _fail("derive_intent_shard: authority must be US-ASCII")


def intent_shard_hex(canonical_authority: str) -> str:
    """The same 16 octets, as 32 lowercase hex characters."""
    return derive_intent_shard(canonical_authority).hex()


def _resolve_standing(standing) -> int:
    """Accept a wire code or a lowercase name; anything else fails closed."""
    if isinstance(standing, int):
        if standing in STANDING_NAMES:
            return standing
        raise _fail(f"standing 0x{standing:02x} is outside the closed set")
    if isinstance(standing, str):
        if standing in STANDING_CODES:
            return STANDING_CODES[standing]
        raise _fail(f"standing {standing!r} is outside the closed set")
    raise _fail(f"standing must be a code or a name, got {type(standing).__name__}")


def _resolve_shard(intent_shard) -> bytes:
    if isinstance(intent_shard, (bytes, bytearray)):
        shard = bytes(intent_shard)
    elif isinstance(intent_shard, str):
        try:
            shard = bytes.fromhex(intent_shard)
        except ValueError:
            raise _fail("intent_shard hex is not valid hex")
    else:
        raise _fail(f"intent_shard must be bytes or hex, got {type(intent_shard).__name__}")
    if len(shard) != _SHARD_LEN:
        raise _fail(f"intent_shard must be exactly {_SHARD_LEN} octets, got {len(shard)}")
    return shard


def _resolve_organ_tag(organ) -> bytes:
    if isinstance(organ, str):
        try:
            organ = organ.encode("ascii")
        except UnicodeEncodeError:
            raise _fail("organ tag must be US-ASCII")
    else:
        organ = bytes(organ)
    if not 1 <= len(organ) <= _ORGAN_LEN:
        raise _fail(f"organ tag must be 1..{_ORGAN_LEN} octets, got {len(organ)}")
    if any(b not in _PRINTABLE for b in organ):
        raise _fail("organ tag must be printable US-ASCII")
    return organ.ljust(_ORGAN_LEN, b"\x00")


def _resolve_u64(value, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise _fail(f"{label} must be an integer")
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise _fail(f"{label} {value} does not fit in an unsigned 64-bit integer")
    return value


def encode(*, key, intent_shard, organ, standing, lease_expiry, nonce,
           flags: int = 0) -> bytes:
    """Build one AE-128 frame (draft sec. 2 + sec. 3).

    The attestation is HMAC-SHA256 over the ENTIRE frame with the attestation
    field itself zeroed -- so organ tag, nonce, lease and standing are all
    authenticated: a rewrite of any of them cannot survive verification.
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
        raise _fail("key must be non-empty bytes (organ key material)")
    if flags != 0:
        raise _fail(f"flags must be 0x0000 in version 1 (unassigned), got 0x{flags:04x}")

    shard = _resolve_shard(intent_shard)
    tag = _resolve_organ_tag(organ)
    code = _resolve_standing(standing)
    lease = _resolve_u64(lease_expiry, "lease_expiry")
    nonce = _resolve_u64(nonce, "nonce")

    frame = bytearray(SIZE)
    frame[OFF_MAGIC:OFF_MAGIC + 4] = MAGIC
    frame[OFF_VERSION] = VERSION
    frame[OFF_ALGORITHM] = ALGORITHM_HMAC_SHA256
    struct.pack_into(">H", frame, OFF_FLAGS, flags)
    struct.pack_into(">Q", frame, OFF_LEASE, lease)
    frame[OFF_SHARD:OFF_SHARD + _SHARD_LEN] = shard
    frame[OFF_ORGAN:OFF_ORGAN + _ORGAN_LEN] = tag
    struct.pack_into(">Q", frame, OFF_NONCE, nonce)
    frame[OFF_STANDING] = code
    # attestation (32..63), reserved (81..95) and extension (96..127) stay zero

    mac = hmac.new(bytes(key), bytes(frame), hashlib.sha256).digest()
    frame[OFF_ATTESTATION:OFF_ATTESTATION + _ATTESTATION_LEN] = mac
    return bytes(frame)


def parse(data) -> dict:
    """Structural decode -- fail closed on every rule of draft sec. 2/sec. 4.

    Returns a dict with the frame's fields. Raises :class:`EnvelopeError` on
    any violation; malformed input is never normalised into a partial result.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise _fail(f"frame must be bytes, got {type(data).__name__}")
    frame = bytes(data)
    if len(frame) != SIZE:
        raise _fail(f"frame must be exactly {SIZE} octets, got {len(frame)}")
    if frame[OFF_MAGIC:OFF_MAGIC + 4] != MAGIC:
        raise _fail(f"bad magic {frame[OFF_MAGIC:OFF_MAGIC + 4]!r} (expected 'IQAE')")
    if frame[OFF_VERSION] != VERSION:
        raise _fail(f"unknown version 0x{frame[OFF_VERSION]:02x}")
    if frame[OFF_ALGORITHM] != ALGORITHM_HMAC_SHA256:
        raise _fail(f"unknown algorithm 0x{frame[OFF_ALGORITHM]:02x}")
    flags = struct.unpack_from(">H", frame, OFF_FLAGS)[0]
    if flags != 0:
        raise _fail(f"flags must be 0x0000 in version 1 (unassigned), got 0x{flags:04x}")

    tag = frame[OFF_ORGAN:OFF_ORGAN + _ORGAN_LEN]
    stripped = tag.rstrip(b"\x00")
    if not stripped or any(b not in _PRINTABLE for b in stripped):
        raise _fail("organ tag must be printable US-ASCII (right-padded with 0x00)")

    code = frame[OFF_STANDING]
    if code not in STANDING_NAMES:
        raise _fail(f"standing 0x{code:02x} is outside the closed set")

    if any(frame[OFF_RESERVED:OFF_EXTENSION]):
        raise _fail("reserved field (81..95) MUST be all zeros")
    if any(frame[OFF_EXTENSION:SIZE]):
        raise _fail("extension field (96..127) MUST be all zeros in version 1")

    return {
        "version": frame[OFF_VERSION],
        "algorithm": frame[OFF_ALGORITHM],
        "flags": flags,
        "lease_expiry": struct.unpack_from(">Q", frame, OFF_LEASE)[0],
        "intent_shard": frame[OFF_SHARD:OFF_SHARD + _SHARD_LEN],
        "attestation": frame[OFF_ATTESTATION:OFF_ATTESTATION + _ATTESTATION_LEN],
        "organ": stripped.decode("ascii"),
        "nonce": struct.unpack_from(">Q", frame, OFF_NONCE)[0],
        "standing": code,
        "standing_name": STANDING_NAMES[code],
    }


def verify(data, key, *, now=None, check_lease: bool = True):
    """Verify one AE-128 frame (draft sec. 4). Constant-time HMAC compare.

    Returns ``(ok, reason, frame)``: on success ``frame`` is the parsed dict;
    on failure it is ``None`` and ``reason`` says which rule rejected it.
    A failure is a RESULT, never an exception -- the caller decides.
    """
    try:
        frame = parse(data)
    except EnvelopeError as exc:
        return False, str(exc), None
    if check_lease:
        if now is None:
            now = time.time()
        if not isinstance(now, (int, float)):
            return False, f"now must be a number, got {type(now).__name__}", None
        if frame["lease_expiry"] < now:
            return False, (f"verdict expired (lease_expiry {frame['lease_expiry']}"
                           f" < now {int(now)})"), None
    raw = bytes(data)
    scratch = bytearray(raw)
    scratch[OFF_ATTESTATION:OFF_ATTESTATION + _ATTESTATION_LEN] = b"\x00" * _ATTESTATION_LEN
    expected = hmac.new(bytes(key), bytes(scratch), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, frame["attestation"]):
        return False, "attestation does not verify (HMAC mismatch)", None
    return True, "ok", frame


# ---------------------------------------------------------------------------
# The published vector (companion draft v0.3 sec. 6) -- every parameter is
# documented there, so any implementation MUST reproduce the frame byte for
# byte from the parameters alone. Generated by ae128-vector-1.py, not typed.

#: The merged I-D's own example authority (sec. 4.4).
VECTOR_1_AUTHORITY = "f3b2a1c4.pillar.example"
#: 32-byte US-ASCII test organ key (label retained from v0.1 for diff
#: continuity; it is a label, not a name dependency -- draft sec. 6).
VECTOR_1_KEY = b"PLSF-TEST-ORG-KEY-00012345678901"
#: 2027-01-01T00:00:00Z.
VECTOR_1_LEASE = 1798761600
VECTOR_1_STANDING = "radiant"
VECTOR_1_ORGAN = "ORG-TEST"
VECTOR_1_NONCE = 1
#: The full 128-octet frame, as lowercase hex.
VECTOR_1_FRAME_HEX = (
    "4951414501010000" "000000006b36ec80"
    "557c8154d3780cb78cc5fa1bd72b331c"
    "4bd14b6ae7b00904986294a326a0f0255847184ff2c9185539d4863efb84596a"
    "4f52472d544553540000000000000001"
    "02" + "00" * 47
)


def vector_1_frame() -> bytes:
    """The published vector as bytes -- encode() of the documented parameters."""
    return encode(key=VECTOR_1_KEY,
                  intent_shard=derive_intent_shard(VECTOR_1_AUTHORITY),
                  organ=VECTOR_1_ORGAN,
                  standing=VECTOR_1_STANDING,
                  lease_expiry=VECTOR_1_LEASE,
                  nonce=VECTOR_1_NONCE)
