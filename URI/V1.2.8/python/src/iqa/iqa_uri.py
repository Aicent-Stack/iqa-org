"""iqa:// URI codec -- validate, canonicalise, derive (RFC-009 sec. 10/sec. 11).

Authority boundaries
    Grammar ......... RFC-009 sec. 10.2 ABNF (sole authority; this module implements it)
    Closed sets ..... sec. 10.1 ("Closed set" stated for both organ and action)
    Case discipline . sec. 10.3 (lowercase US-ASCII only) + sec. 12 #8 (fail closed)
    Deref safety .... sec. 11.3 (action safety classes)
    Route derivation  SPEC/IQA-URI-ATTEST-v1.2.6.md sec. 3 (IQA_ROUTE)

Design rules inherited from the RTTP codec discipline:
    * Malformed input is REJECTED, never normalised.
    * A check that cannot be performed is a failure, never a pass.
    * Zero dependencies: standard library only.
"""

from __future__ import annotations

import hashlib

SCHEME = "iqa"

#: RFC-009 sec. 10.1 -- organ is a CLOSED set (RFC-009-A/-B/-C).
ORGANS = ("forge", "tss", "gateway")

#: RFC-009 sec. 10.1 -- action is a CLOSED set (differs from `rttp`, whose verb set
#: is open; here anything outside the four verbs is rejected).
ACTIONS = ("verify", "audit", "attest", "revoke")

#: RFC-009 sec. 11.3 -- safety classes. Omitted action = standing read (SAFE);
#: `verify` compares, writes nothing (SAFE). The other three are state
#: transitions or potentially harmful measurements (NOT SAFE).
SAFE_ACTIONS = frozenset({None, "verify"})
UNSAFE_ACTIONS = frozenset({"audit", "attest", "revoke"})

#: Standing values an Organ may render (RFC-009-C sec. 3) -- closed set, lowercase.
STANDINGS = ("ghost", "probation", "radiant", "genesis")

#: RFC-009 sec. 10.2 -- hash-subject lengths: routing short form / 128-bit / 256-bit.
HASH_LENGTHS = (8, 32, 64)

_LOWHEX = frozenset("0123456789abcdef")
_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
#: sec. 10.3: a string containing any of these is NOT a valid iqa URI. Enforced
#: implicitly by the allowed-charset scan; listed here for documentation.
_FORBIDDEN_CHARS = "@:?#[]"

_ALLOWED = _LOWHEX | _NAME_CHARS | frozenset("./")


class IqaUriError(ValueError):
    """The only error type raised by this module."""


def _fail(uri: str, reason: str) -> "IqaUriError":
    return IqaUriError(f"{uri!r}: {reason}")


def is_valid_action(value: str) -> bool:
    """sec. 10.2 action test -- True only for the closed four-verb set."""
    return value in ACTIONS


def derive_route(authority: str) -> bytes:
    """IQA_ROUTE = SHA-256(ASCII(canonical_authority))[0:4].

    Pure computation, DNS-free (RFC-009 sec. 12 #9). Mirrors the RTTP ROUTE_SHARD
    rule (SHA-256(authority)[0:16]) so the two schemes of the same addressing
    family derive the same way. NOTE: this is the *address* fingerprint -- it is
    NOT the subject hash, which is a routing hint for the *AID*. The two numbers
    are about different things and MUST NOT be conflated.
    """
    if not authority:
        raise IqaUriError("derive_route: authority is empty")
    return hashlib.sha256(authority.encode("ascii")).digest()[:4]


def derive_route_hex(authority: str) -> str:
    """The same four bytes, as 8 lowercase hex characters."""
    return derive_route(authority).hex()


def parse(uri: str) -> dict:
    """Validate, canonicalise and derive. Raises IqaUriError on any violation.

    Returned fields are snake_case ON PURPOSE so the Python and JavaScript
    implementations compare field for field against the published vectors.
    """
    if not isinstance(uri, str):
        raise _fail(uri, "input must be a string")

    # Scheme -- exact lowercase prefix. IQA://, iqas://, https:// ... all fail here.
    prefix = SCHEME + "://"
    if not uri.startswith(prefix):
        raise _fail(uri, f"scheme must be exactly {prefix!r} - no other scheme, "
                         "no case variant, no fallback (RFC-009 sec. 10.3, sec. 12 #8)")
    rest = uri[len(prefix):]

    # Charset gate: lowercase US-ASCII only (sec. 10.3). This single scan rejects
    # uppercase anywhere (scheme, subject, organ, action), userinfo '@', port
    # ':', query '?', fragment '#', whitespace and every other foreign byte.
    for ch in rest:
        if ch not in _ALLOWED:
            if ch in _FORBIDDEN_CHARS:
                raise _fail(uri, f"{ch!r} is not defined by the scheme (RFC-009 sec. 10.3)")
            if ch.isspace():
                raise _fail(uri, "whitespace is not allowed (RFC-009 sec. 10.3 lowercase US-ASCII only)")
            raise _fail(uri, f"character {ch!r} is outside the allowed set "
                             "(lowercase US-ASCII, digits, '-', '.', '/')")

    # Path: at most one '/', and the action behind it must be non-empty.
    if "/" in rest:
        authority, _, action = rest.partition("/")
        if action == "":
            raise _fail(uri, "trailing '/' with empty action - action is a "
                             "closed-set verb, not omissible by empty string (sec. 10.2)")
        if "/" in action:
            raise _fail(uri, "second path segment - path is a single '/<action>' (sec. 10.2)")
    else:
        authority, action = rest, None

    # Authority: exactly three segments.
    segments = authority.split(".")
    if len(segments) != 3:
        raise _fail(uri, f"authority has {len(segments)} segment(s), "
                         "must be <subject>.<organ>.<root> (RFC-009 sec. 10.2)")
    subject, organ, root = segments
    if subject == "" or root == "":
        raise _fail(uri, "authority segments must be non-empty (RFC-009 sec. 10.2)")

    # Subject: hash form (8/32/64 lowercase hex) or name form (RFC-009 sec. 10.2).
    # Ordered choice per the ABNF: all-lowerhex input is tried as hash-subject
    # first; a lowercase-hex string of another length is therefore a NAME
    # subject, exactly as the grammar says. Documented, not "fixed".
    if all(c in _LOWHEX for c in subject):
        if len(subject) in HASH_LENGTHS:
            subject_is_hash = True
            subject_hex = subject
        else:
            subject_is_hash = False
            subject_hex = None
    else:
        subject_is_hash = False
        subject_hex = None

    # Organ -- CLOSED set, case-sensitive (sec. 10.1). 'Forge', 'forgery', '' all fail.
    if organ not in ORGANS:
        raise _fail(uri, f"organ {organ!r} is outside the closed set "
                         f"{list(ORGANS)} (RFC-009 sec. 10.1/sec. 10.3)")

    # Action -- CLOSED set (sec. 10.1). This is the deliberate difference from rttp.
    if action is not None and action not in ACTIONS:
        raise _fail(uri, f"action {action!r} is outside the closed set "
                         f"{list(ACTIONS)} (RFC-009 sec. 10.1)")

    canonical_uri = SCHEME + "://" + authority + ("/" + action if action else "")

    return {
        "scheme": SCHEME,
        "subject": subject,
        "subject_is_hash": subject_is_hash,
        "subject_hex": subject_hex,
        "organ": organ,
        "root": root,
        "authority": authority,
        "action": action,
        "action_omitted": action is None,
        "action_safe": action in SAFE_ACTIONS,          # sec. 11.3
        "canonical_uri": canonical_uri,
        "route_hex": derive_route_hex(authority),       # SPEC sec. 3
    }
