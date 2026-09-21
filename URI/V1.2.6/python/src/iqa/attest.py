"""
attest — the sovereign **attestation envelope** (Ed25519, self-certifying)

Why this module exists
----------------------
An ``iqa://`` URI is a *claim about standing* (RFC-009 §10.4: "parsing is not
attestation"). To act on the claim, a verifier needs evidence. The evidence
travels as an **envelope**: a signed object that cites the subject URI and
carries the standing an Organ rendered.

Layout: identical to the RTTP sovereign seal
(``SPEC/RTTP-SEAL-ENVELOPE-v1.2.6.md`` §3) with two changes fixed by
``SPEC/IQA-URI-ATTEST-v1.2.6.md`` §5:

    1. **Domain separation.** The signing-input prefix is ``b"iqa-attest-v1\\n"``
       — a signature made for one scheme can never be replayed as the other.
    2. **Payload semantics.** ``{"subject_uri", "organ", "standing"}``, with
       ``standing`` a closed set (``ghost`` / ``probation`` / ``radiant`` /
       ``genesis``, RFC-009-C §3).

Identity: ``AID = SHA-256(public key)`` — self-certifying, recomputed by the
verifier from the in-band key. No registry, no issuer, no directory. Lose the
key, lose the identity; there is no operator who can restore it.

``ts`` and ``nonce`` are **inside** the signature: rewriting them must require
breaking Ed25519, not just editing JSON. Freshness window: 120 seconds for any
envelope arriving over a network; archival validation only may disable it.

Installing
----------
    pip install iqa[ed25519]

Without the extra, importing this module succeeds but every call raises
``AttestError`` with that instruction — it never degrades to an unsigned path.
"""

from __future__ import annotations

import hashlib
import json
import os
import time

from . import iqa_uri
from .iqa_uri import IqaUriError

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    HAVE_ED25519 = True
    _IMPORT_ERROR = None
except ImportError as _exc:  # pragma: no cover - depends on the environment
    HAVE_ED25519 = False
    _IMPORT_ERROR = _exc

ALG = "ed25519"
ENVELOPE_VERSION = 1

#: Maximum accepted |now - ts|, in seconds.
MAX_CLOCK_SKEW = 120

#: Nonce length in bytes (hex-encoded on the wire).
NONCE_BYTES = 8

AID_BYTES = 32
PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64
SEED_BYTES = 32

#: SPEC/IQA-URI-ATTEST-v1.2.6 §5.2 — domain separation from the RTTP seal.
CANONICAL_PREFIX = b"iqa-attest-v1\n"

#: Closed set of standings an Organ may render (RFC-009-C §3).
STANDINGS = iqa_uri.STANDINGS

INSTALL_HINT = "pip install iqa-org[ed25519]"


class AttestError(Exception):
    """The envelope is unavailable, unparsable or malformed."""


def _require_backend() -> None:
    if not HAVE_ED25519:
        raise AttestError(
            f"Ed25519 backend unavailable - install it with '{INSTALL_HINT}' "
            f"(import error: {_IMPORT_ERROR})")


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def aid_from_public_key(public_key: bytes) -> bytes:
    """AID = SHA-256(public_key), 32 bytes — self-certifying by construction."""
    if not isinstance(public_key, (bytes, bytearray)):
        raise AttestError("public_key must be bytes")
    if len(public_key) != PUBLIC_KEY_BYTES:
        raise AttestError(f"public_key must be {PUBLIC_KEY_BYTES} bytes")
    return hashlib.sha256(bytes(public_key)).digest()


def generate_keypair(seed: bytes = None) -> dict:
    """Generate an Ed25519 key pair and its AID.

    :param seed: 32-byte seed. **For reproducible test vectors only**; omit in
                 production and let the OS entropy source decide.
    """
    _require_backend()
    if seed is None:
        private_key = Ed25519PrivateKey.generate()
    else:
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != SEED_BYTES:
            raise AttestError(f"seed must be {SEED_BYTES} bytes")
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(seed))

    raw_seed = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    aid_bytes = aid_from_public_key(public_key)

    return {
        "private_key": private_key,          # signing use — never share
        "seed": raw_seed,                    # 32B seed — never share
        "public_key": public_key,            # 32B
        "aid": aid_bytes,                    # 32B = sha256(public_key)
        "seed_hex": raw_seed.hex(),
        "public_hex": public_key.hex(),
        "aid_hex": aid_bytes.hex(),
    }


def public_bundle(keypair: dict) -> dict:
    """The safely publishable part (identity + public key), no private material."""
    return {"alg": ALG, "aid": keypair["aid_hex"], "pub": keypair["public_hex"]}


# ---------------------------------------------------------------------------
# Canonical signing input
# ---------------------------------------------------------------------------

def _hex_lower(value, what: str, nbytes: int) -> str:
    if not isinstance(value, str):
        raise AttestError(f"{what} must be a hex string")
    if value != value.lower():
        raise AttestError(f"{what} must be lowercase hex (RFC-009 §10.3 discipline)")
    if len(value) != nbytes * 2:
        raise AttestError(f"{what} must be {nbytes} bytes ({nbytes * 2} hex chars)")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise AttestError(f"{what} is not valid hex: {exc}") from exc
    return value


def json_canonical(obj) -> bytes:
    """Deterministic JSON encoding (UTF-8, sorted keys, no insignificant whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def signing_input(alg: str, aid_hex: str, pub_hex: str, ts: int, nonce: str,
                  payload: dict) -> bytes:
    """The signed byte sequence. Every envelope field except ``sig`` enters it.

    ``ts`` / ``nonce`` MUST be inside the signature — beside it, rewriting the
    replay window would not touch Ed25519 at all.
    """
    return CANONICAL_PREFIX + json_canonical({
        "alg": alg,
        "aid": aid_hex,
        "pub": pub_hex,
        "ts": ts,
        "nonce": nonce,
        "payload": payload,
    })


# ---------------------------------------------------------------------------
# Attestation claims
# ---------------------------------------------------------------------------

def build_claim(subject_uri: str, organ: str, standing: str) -> dict:
    """Build and validate an attestation payload (closed sets enforced).

    The subject URI must parse; ``organ`` and ``standing`` must be members of
    their closed sets. A claim that violates the grammar is not built — it is
    rejected, so an envelope can never carry a subject URI the codec itself
    would reject.
    """
    parsed = iqa_uri.parse(subject_uri)  # raises IqaUriError on any violation
    if organ not in iqa_uri.ORGANS:
        raise AttestError(f"organ {organ!r} is outside the closed set {list(iqa_uri.ORGANS)}")
    if standing not in STANDINGS:
        raise AttestError(f"standing {standing!r} is outside the closed set {list(STANDINGS)}")
    if organ != parsed["organ"]:
        raise AttestError("organ does not match the subject URI's organ")
    return {
        "subject_uri": parsed["canonical_uri"],
        "organ": organ,
        "standing": standing,
    }


# ---------------------------------------------------------------------------
# Seal / verify
# ---------------------------------------------------------------------------

def seal(payload: dict, keypair: dict, ts: int = None, nonce: str = None) -> dict:
    """Seal a payload into a self-certifying envelope with your own key.

    :param ts:    unix seconds. Omitted = now. **Pass it only to produce
                  reproducible vectors** — in production it pins the replay window.
    :param nonce: ``NONCE_BYTES`` bytes as lowercase hex. Omitted = OS entropy.
    """
    _require_backend()
    if not isinstance(payload, dict):
        raise AttestError("payload must be a dict")
    if not isinstance(keypair, dict) or "private_key" not in keypair:
        raise AttestError("keypair must come from generate_keypair()")

    if ts is None:
        ts = int(time.time())
    if not isinstance(ts, int) or isinstance(ts, bool):
        raise AttestError("ts must be an integer (unix seconds)")

    if nonce is None:
        nonce = os.urandom(NONCE_BYTES).hex()
    _hex_lower(nonce, "nonce", NONCE_BYTES)

    aid_hex = keypair["aid_hex"]
    pub_hex = keypair["public_hex"]
    signature = keypair["private_key"].sign(
        signing_input(ALG, aid_hex, pub_hex, ts, nonce, payload))

    return {
        "v": ENVELOPE_VERSION,
        "alg": ALG,
        "aid": aid_hex,
        "pub": pub_hex,
        "ts": ts,
        "nonce": nonce,
        "sig": signature.hex(),
        "payload": payload,
    }


def verify_envelope(envelope: dict, now: int = None,
                    max_skew: int = MAX_CLOCK_SKEW,
                    check_freshness: bool = True) -> tuple:
    """Verify an envelope. Returns ``(ok: bool, reason: str, aid_hex | None)``.

    Any failed step returns False — **a check that cannot be performed is a
    failure, never a pass.**

    :param check_freshness: default True. False is **only** for archived
        envelopes (audit records, test vectors). On live network input it must
        stay True — turn it off and replay attacks become trivial.
    """
    try:
        _require_backend()

        if not isinstance(envelope, dict):
            return False, "envelope must be a dict", None
        if envelope.get("v") != ENVELOPE_VERSION:
            return False, f"unsupported envelope version: {envelope.get('v')!r}", None
        if envelope.get("alg") != ALG:
            return False, f"unsupported algorithm: {envelope.get('alg')!r}", None

        aid_hex = _hex_lower(envelope.get("aid"), "aid", AID_BYTES)
        pub_hex = _hex_lower(envelope.get("pub"), "pub", PUBLIC_KEY_BYTES)
        sig_hex = _hex_lower(envelope.get("sig"), "sig", SIGNATURE_BYTES)
        nonce = _hex_lower(envelope.get("nonce"), "nonce", NONCE_BYTES)

        ts = envelope.get("ts")
        if not isinstance(ts, int) or isinstance(ts, bool):
            return False, "ts must be an integer (unix seconds)", None

        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            return False, "payload must be an object", None

        if check_freshness:
            reference = int(time.time()) if now is None else now
            drift = abs(reference - ts)
            if drift > max_skew:
                return False, (f"timestamp skew too large ({drift}s > {max_skew}s)"
                               " - replay?"), None

        public_key = bytes.fromhex(pub_hex)

        # --- self-certification: identity is derived, not claimed ---
        if aid_from_public_key(public_key).hex() != aid_hex:
            return False, "AID does not match public key (self-certification failed)", None

        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(sig_hex),
            signing_input(ALG, aid_hex, pub_hex, ts, nonce, payload),
        )
        return True, "sealed", aid_hex

    except InvalidSignature:
        return False, "bad seal (signature does not verify)", None
    except AttestError as exc:
        return False, str(exc), None
    except (ValueError, TypeError, KeyError) as exc:
        return False, f"malformed envelope: {exc}", None


def verify_attestation(envelope: dict, expected_subject_uri: str = None,
                       now: int = None, check_freshness: bool = True) -> tuple:
    """Verify an envelope **and** its claim payload (closed sets, URI grammar).

    The signature proves who said it; the claim checks make sure what they said
    is at least well-formed. Neither proves the standing is true — trusting an
    attestation is a different act from verifying one.
    """
    ok, reason, _aid = verify_envelope(envelope, now=now,
                                       check_freshness=check_freshness)
    if not ok:
        return False, reason
    payload = envelope["payload"]
    try:
        claim = build_claim(payload.get("subject_uri"), payload.get("organ"),
                            payload.get("standing"))
    except (AttestError, IqaUriError) as exc:
        return False, f"claim payload malformed: {exc}", None
    if expected_subject_uri is not None:
        if claim["subject_uri"] != iqa_uri.parse(expected_subject_uri)["canonical_uri"]:
            return False, "subject URI mismatch (cited a different subject?)", None
    return True, "sealed", None


def unseal(envelope: dict, now: int = None, check_freshness: bool = True) -> dict:
    """Return the payload if the envelope verifies; raise AttestError otherwise."""
    ok, reason, _aid = verify_envelope(envelope, now=now,
                                       check_freshness=check_freshness)
    if not ok:
        raise AttestError(reason)
    return envelope["payload"]
