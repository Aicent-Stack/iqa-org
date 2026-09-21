#!/usr/bin/env python3
"""
iqa self-test -- replay the published conformance vectors against *this* build.

Why a package ships a self-test
-------------------------------
A specification is only worth what an independent implementation can reproduce
from it. This module is the smallest possible statement of that: install the
package, run one command, and either the published vectors reproduce bit for bit
or they do not. No trust in the author is required -- which is the whole point.

    $ python -m iqa.selftest

Sections
--------
1. **Conformance** -- the published vectors: ``iqa://`` parsing, the two closed
   sets, fail-closed rejections, sec. 11.3 action safety classes, ``IQA_ROUTE``
   derivation, and the deterministic attestation envelope.
2. **Envelope rules** -- version, algorithm, hex shape, field types, freshness,
   self-certification and the claim closed sets. None of that needs a
   cryptographic primitive, so a zero-dependency install runs every check here.
3. **Attestation envelope** -- round-trip, determinism, claim acceptance and the
   tamper matrix. Run with the installed Ed25519 backend when there is one;
   otherwise with an injected test signer, and the output says which. The test
   signer is not Ed25519: it is there to show which fields the signed bytes
   cover.
4. **Ed25519 backend** -- RFC 8032 sec. 7.1 test vectors, so the signature backend
   is shown to be *standard* Ed25519 rather than a lookalike. These, plus the
   published envelope vector's own signature, are the only checks a
   zero-dependency install skips.
5. **Zero dependencies** -- a static scan proving the core modules import nothing
   outside the standard library, plus a runtime guard that counts any attempt to
   open an outbound connection while the self-test runs.

Exit status is 0 only if every check passed. Checks that require the optional
Ed25519 backend are **skipped** rather than failed when it is not installed,
and the summary names how many were skipped -- a green summary always says what
it did not verify. ``--quiet`` prints the summary line only.
"""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import os
import socket
import sys

from . import attest, iqa_uri

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS_FILE = os.path.join(HERE, "vectors", "iqa-conformance-v1.2.6.json")

# RFC 8032 sec. 7.1 -- TEST 1 (empty message) and TEST 2 (one-byte message 0x72).
# Reproduced here so a failure points at the signature backend, not at our code.
RFC8032_VECTORS = [
    {
        "name": "TEST 1 (empty message)",
        "seed": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "pub": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "msg": "",
        "sig": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
               "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    {
        "name": "TEST 2 (one-byte message 0x72)",
        "seed": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "pub": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "msg": "72",
        "sig": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
               "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
]

#: Fixed inputs for the reproducible envelope vector (SPEC sec. 5.4).
ENVELOPE_SEED = bytes.fromhex(
    "e722fed924c7f76b157faab674ea97bb7c3075f55ad7d3c6319418e22b86d611")
ENVELOPE_TS = 1760000000
ENVELOPE_NONCE = "0011223344556677"
ENVELOPE_PAYLOAD = {
    "subject_uri": "iqa://3f9a1b2c.gateway.iqa",
    "organ": "gateway",
    "standing": "radiant",
}


class _NetworkGuard:
    """Count outbound connection attempts made while this run is in progress.

    A static import scan shows that nothing was *imported*; this shows that
    nothing was *used*. Replacing socket.socket is enough to cover every
    higher-level client, because they all end up constructing one.
    """

    def __init__(self):
        self.calls = 0
        self._real = socket.socket
        guard = self

        class _Blocked(guard._real):
            def connect(self, *args, **kwargs):
                guard.calls += 1
                raise AssertionError("outbound network access attempted")

            def connect_ex(self, *args, **kwargs):
                guard.calls += 1
                raise AssertionError("outbound network access attempted")

        self._blocked = _Blocked

    def install(self):
        socket.socket = self._blocked

    def restore(self):
        socket.socket = self._real


class TestSignerBackend:
    """Hash-based stand-in for a signature backend. NOT Ed25519.

    It exists so the envelope flow can be exercised at all in a zero-dependency
    install, and so the tamper matrix keeps its meaning there: if the signed
    input did not cover ``payload``, ``ts``, ``nonce``, ``aid`` or ``pub``,
    tampering with those fields would stop being detected.

    Forgery with this signer is trivial, which is acceptable because it is only
    ever used by this self-test - never by ``attest`` on a real envelope. The
    real primitive is proven by the RFC 8032 vectors in section 4.
    """

    name = "test-hash-signer (NOT Ed25519)"

    def available(self) -> bool:
        return True

    def from_seed(self, seed: bytes):
        return bytes(seed)

    def generate(self):
        return bytes(32)

    def private_bytes(self, private_key) -> bytes:
        return bytes(private_key)

    def public_bytes(self, private_key) -> bytes:
        return bytes(private_key)

    def sign(self, private_key, message: bytes) -> bytes:
        digest = hashlib.sha256(b"iqa-selftest-signer"
                                + bytes(private_key) + message).digest()
        return digest + digest

    def verify(self, public_key: bytes, signature: bytes, message: bytes) -> bool:
        return signature == self.sign(public_key, message)


def _select_backend():
    """Ed25519 when it is installed, otherwise the injected test signer."""
    if attest.HAVE_ED25519:
        return attest.NATIVE_BACKEND, "Ed25519 (cryptography)"
    return TestSignerBackend(), "injected test signer -- NOT Ed25519"


class Runner:
    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self.passed = 0
        self.failed = []
        self.skipped = 0

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        if ok:
            self.passed += 1
        else:
            self.failed.append((name, detail))
        if not self.quiet:
            mark = "ok  " if ok else "FAIL"
            line = f"  [{mark}] {name}"
            if detail and not ok:
                line += f"\n         {detail}"
            print(line)
        return ok

    def skip(self, name: str, detail: str = "") -> None:
        """A check that cannot run in this environment -- reported, never hidden.

        Skipping is not passing: the backend-dependent checks are counted
        separately and named in the summary, so an install without the
        ``[ed25519]`` extra shows what it did not verify rather than showing
        green.
        """
        self.skipped += 1
        if not self.quiet:
            line = f"  [skip] {name}"
            if detail:
                line += f" ({detail})"
            print(line)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

def run_conformance(r: Runner) -> None:
    if not os.path.exists(VECTORS_FILE):
        r.check("vectors file present", False, f"missing: {VECTORS_FILE}")
        return
    with open(VECTORS_FILE, "r", encoding="utf-8") as fh:
        expected = json.load(fh)

    if not r.quiet:
        print(f"\n[1] Conformance -- {os.path.basename(VECTORS_FILE)}")

    for case in expected["positive_uris"]:
        try:
            p = iqa_uri.parse(case["uri"])
        except iqa_uri.IqaUriError as exc:
            r.check(f"parse {case['uri']}", False, str(exc))
            continue
        bad = [k for k in ("canonical_uri", "subject_is_hash", "organ", "root",
                           "authority", "action", "action_omitted", "action_safe",
                           "route_hex") if p[k] != case[k]]
        r.check(f"parse {case['uri']}", not bad,
                "; ".join(f"{k}: {case[k]!r} != {p[k]!r}" for k in bad) if bad else "")

    for case in expected["negative_uris"]:
        try:
            iqa_uri.parse(case["uri"])
            r.check(f"reject {case['uri']}", False, "expected REJECT but parsed")
        except iqa_uri.IqaUriError:
            r.check(f"reject {case['uri']}", True)
        except Exception as exc:  # noqa: BLE001
            r.check(f"reject {case['uri']}", False, f"wrong error type: {exc!r}")

    for row in expected["action_safety"]:
        action = row["action"]
        uri = ("iqa://3f9a1b2c.gateway.iqa" if action is None
               else f"iqa://3f9a1b2c.gateway.iqa/{action}")
        got = iqa_uri.parse(uri)["action_safe"]
        r.check(f"action_safe {action or '(omitted)'} == {row['safe']}", got == row["safe"])

    env = expected["attest_envelope_vector"]
    raw = attest.signing_input(env["alg"], env["aid"], env["pub"], env["ts"],
                               env["nonce"], env["payload"])
    r.check("envelope signing input reproduces byte for byte",
            raw.hex() == env["signing_input_hex"])
    r.check("envelope aid == SHA-256(pub)",
            attest.aid_from_public_key(bytes.fromhex(env["pub"])).hex() == env["aid"])
    if attest.HAVE_ED25519:
        ok, reason, _ = attest.verify_envelope(dict(env), now=env["ts"],
                                               check_freshness=False)
        r.check("envelope vector verifies", ok, reason)
    else:
        r.skip("envelope vector verifies", "Ed25519 backend not installed")


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

def run_rfc8032(r: Runner) -> None:
    if not r.quiet:
        print("\n[4] Ed25519 backend -- RFC 8032 section 7.1"
              " (the only checks a zero-dependency install skips)")
    if not attest.HAVE_ED25519:
        for vec in RFC8032_VECTORS:
            r.skip(vec["name"], f"{attest.INSTALL_HINT} not installed")
        return
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    for vec in RFC8032_VECTORS:
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(vec["pub"])).verify(
                bytes.fromhex(vec["sig"]), bytes.fromhex(vec["msg"]))
            r.check(vec["name"], True)
        except InvalidSignature:
            r.check(vec["name"], False, "signature does not verify")


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

def run_envelope_rules(r: Runner) -> None:
    """Envelope and claim rules that need no cryptographic primitive.

    Version, algorithm, hex shape, field types, freshness, self-certification and
    the claim closed sets are all decided without Ed25519, so a zero-dependency
    install runs every check in this group. Only the signature itself is left to
    the flow group.
    """
    if not r.quiet:
        print("\n[2] Envelope rules -- no primitive required")

    kp = attest.generate_keypair(ENVELOPE_SEED, backend=TestSignerBackend())
    env = attest.seal(ENVELOPE_PAYLOAD, kp, ts=ENVELOPE_TS, nonce=ENVELOPE_NONCE)

    def mut(**changes) -> dict:
        out = copy.deepcopy(env)
        out.update(changes)
        return out

    def drop(field: str) -> dict:
        return {k: v for k, v in env.items() if k != field}

    def upper_hex(value: str) -> str:
        head = "A" if value[:1] != "A" else "B"
        return head + value[1:]

    r.check("AID = SHA-256(public key)",
            attest.aid_from_public_key(kp["public_key"]).hex() == kp["aid_hex"],
            "identity is not derivable from the public key")
    r.check("well-formed envelope passes the rule layer",
            attest.check_envelope(env, now=ENVELOPE_TS)[0],
            "a well-formed envelope was rejected by the rule layer")

    cases = [
        ("envelope version bumped", mut(v=2)),
        ("unknown algorithm", mut(alg="ed448")),
        ("uppercase hex in pub", mut(pub=upper_hex(env["pub"]))),
        ("AID is not 32 bytes", mut(aid=env["aid"][:-2])),
        ("signature is not 64 bytes", mut(sig=env["sig"][:-2])),
        ("nonce is not 8 bytes", mut(nonce=env["nonce"] + "00")),
        ("nonce removed", drop("nonce")),
        ("ts is not an integer", mut(ts=str(ENVELOPE_TS))),
        ("ts removed", drop("ts")),
        ("payload is not an object", mut(payload="not-an-object")),
        ("payload removed", drop("payload")),
        ("AID does not match the public key", mut(aid="00" * 32)),
        ("public key swapped, AID kept", mut(pub="11" * 32)),
        ("envelope outside the freshness window", mut(ts=ENVELOPE_TS + 3600)),
    ]
    for label, tampered in cases:
        ok, reason = attest.check_envelope(tampered, now=ENVELOPE_TS)
        r.check(f"rule reject: {label}", not ok,
                f"the rule layer accepted it ({reason!r})")

    try:
        attest.build_claim("iqa://3f9a1b2c.gateway.iqa", "not-an-organ", "radiant")
        r.check("claim rejects an organ outside the closed set", False,
                "'not-an-organ' was accepted")
    except (attest.AttestError, iqa_uri.IqaUriError):
        r.check("claim rejects an organ outside the closed set", True)
    try:
        attest.build_claim("rttp://3f9a1b2c.gateway.iqa", "gateway", "radiant")
        r.check("claim rejects a subject URI outside the iqa scheme", False,
                "an rttp:// subject was accepted")
    except (attest.AttestError, iqa_uri.IqaUriError):
        r.check("claim rejects a subject URI outside the iqa scheme", True)


def run_envelope(r: Runner) -> None:
    backend, label = _select_backend()

    if not r.quiet:
        print(f"\n[3] Attestation envelope -- round-trip, self-certification,"
              f" tamper matrix -- {label}")

    kp = attest.generate_keypair(ENVELOPE_SEED, backend=backend)
    env = attest.seal(ENVELOPE_PAYLOAD, kp, ts=ENVELOPE_TS, nonce=ENVELOPE_NONCE)

    # Determinism: same seed/ts/nonce must reproduce the envelope byte for byte.
    with open(VECTORS_FILE, "r", encoding="utf-8") as fh:
        expected = json.load(fh)["attest_envelope_vector"]
    if attest.HAVE_ED25519:
        r.check("deterministic envelope matches the published vector",
                env["sig"] == expected["sig"] and env["aid"] == expected["aid"],
                "signature or AID differs from SPEC sec. 5.4")
    else:
        twin = attest.seal(ENVELOPE_PAYLOAD, kp, ts=ENVELOPE_TS,
                           nonce=ENVELOPE_NONCE)
        r.check("deterministic envelope reproduces byte for byte",
                twin == env and env["aid"] == kp["aid_hex"],
                "two seals of the same inputs differ")

    ok, reason, aid = attest.verify_envelope(env, now=ENVELOPE_TS,
                                             backend=backend)
    r.check("round-trip verifies", ok and aid == kp["aid_hex"], reason)

    ok, reason, _ = attest.verify_attestation(env, now=ENVELOPE_TS,
                                              backend=backend)
    r.check("attestation claim verifies", ok, reason)

    bad_claim = attest.build_claim("iqa://3f9a1b2c.gateway.iqa", "gateway", "ascendant") \
        if False else None
    try:
        attest.build_claim("iqa://3f9a1b2c.gateway.iqa", "gateway", "ascendant")
        r.check("claim rejects a standing outside the closed set", False,
                "'ascendant' was accepted")
    except attest.AttestError:
        r.check("claim rejects a standing outside the closed set", True)
    try:
        attest.build_claim("iqa://3f9a1b2c.forge.iqa", "gateway", "radiant")
        r.check("claim rejects an organ/URI mismatch", False, "accepted")
    except (attest.AttestError, iqa_uri.IqaUriError):
        r.check("claim rejects an organ/URI mismatch", True)

    ok, reason, _ = attest.verify_envelope(env, now=ENVELOPE_TS + 121,
                                           backend=backend)
    r.check("stale envelope rejected (121s > 120s window)", not ok, reason)
    ok, reason, _ = attest.verify_envelope(env, now=ENVELOPE_TS + 121,
                                           check_freshness=False,
                                           backend=backend)
    r.check("archival mode accepts a stale envelope", ok, reason)

    def tampered(mutate) -> dict:
        e = copy.deepcopy(env)
        mutate(e)
        return e

    other = attest.generate_keypair(backend=backend)
    other_env = attest.seal({"x": 1}, other, ts=ENVELOPE_TS, nonce=ENVELOPE_NONCE)

    def expect_reject(name: str, e: dict) -> None:
        ok, reason, _ = attest.verify_envelope(e, now=ENVELOPE_TS,
                                               check_freshness=False,
                                               backend=backend)
        r.check(f"tamper: {name}", not ok, f"accepted?! ({reason})")

    expect_reject("payload altered",
                  tampered(lambda e: e["payload"].__setitem__("standing", "genesis")))
    expect_reject("aid swapped for another identity",
                  tampered(lambda e: e.__setitem__("aid", other["aid_hex"])))
    expect_reject("pub swapped while aid kept",
                  tampered(lambda e: e.__setitem__("pub", other["public_hex"])))
    expect_reject("signature from a different key",
                  tampered(lambda e: e.__setitem__("sig", other_env["sig"])))
    expect_reject("signature truncated",
                  tampered(lambda e: e.__setitem__("sig", e["sig"][:124])))
    expect_reject("one signature bit flipped",
                  tampered(lambda e: e.__setitem__("sig",
                            ("0" if e["sig"][10] == "1" else "1").join(
                                [e["sig"][:10], e["sig"][11:]]))))
    expect_reject("hex in uppercase",
                  tampered(lambda e: e.__setitem__("nonce", "ABCDEF0011223345")))
    expect_reject("alg unknown",
                  tampered(lambda e: e.__setitem__("alg", "ed448")))
    expect_reject("v bumped",
                  tampered(lambda e: e.__setitem__("v", 2)))
    expect_reject("payload removed",
                  tampered(lambda e: e.pop("payload")))
    expect_reject("ts altered, still inside the window",
                  tampered(lambda e: e.__setitem__("ts", e["ts"] + 30)))
    expect_reject("ts removed",
                  tampered(lambda e: e.pop("ts")))
    expect_reject("nonce altered",
                  tampered(lambda e: e.__setitem__("nonce", "0011223344556678")))
    expect_reject("nonce removed",
                  tampered(lambda e: e.pop("nonce")))


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

STDLIB_OK = {
    "__future__", "ast", "copy", "hashlib", "json", "os", "sys", "time",
}

def run_zero_dep(r: Runner, guard: "_NetworkGuard" = None) -> None:
    if not r.quiet:
        print("\n[5] Zero dependencies -- static scan + runtime guard")
    core = [os.path.join(HERE, "iqa_uri.py"), os.path.join(HERE, "__init__.py")]
    for path in core:
        with open(path, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
        bad = sorted(roots - STDLIB_OK - {"iqa"})
        r.check(f"{os.path.basename(path)} imports stdlib only", not bad,
                f"non-stdlib: {bad}")

    if guard is not None:
        r.check("no outbound connection attempted while this run was in progress",
                guard.calls == 0,
                f"{guard.calls} connection attempt(s) were made")


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="iqa self-test")
    ap.add_argument("--quiet", action="store_true", help="summary line only")
    args = ap.parse_args()

    guard = _NetworkGuard()
    guard.install()
    try:
        r = Runner(quiet=args.quiet)
        run_conformance(r)
        run_envelope_rules(r)
        run_envelope(r)
        run_rfc8032(r)
        run_zero_dep(r, guard)
    finally:
        guard.restore()

    total = r.passed + len(r.failed)
    if r.failed:
        print(f"\n[FAIL] {len(r.failed)} of {total} checks failed")
        for name, detail in r.failed:
            print(f"   - {name}" + (f": {detail}" if detail else ""))
        return 1
    skipped_note = f" ({r.skipped} skipped)" if r.skipped else ""
    print(f"\n[PASS] all {r.passed} checks passed{skipped_note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
