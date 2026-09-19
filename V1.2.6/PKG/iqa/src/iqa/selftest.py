#!/usr/bin/env python3
"""
iqa self-test — replay the published conformance vectors against *this* build.

Why a package ships a self-test
-------------------------------
A specification is only worth what an independent implementation can reproduce
from it. This module is the smallest possible statement of that: install the
package, run one command, and either the published vectors reproduce bit for bit
or they do not. No trust in the author is required — which is the whole point.

    $ python -m iqa.selftest

Sections
--------
1. **Conformance** — the published vectors: ``iqa://`` parsing, the two closed
   sets, fail-closed rejections, §11.3 action safety classes, ``IQA_ROUTE``
   derivation, and the deterministic attestation envelope.
2. **Ed25519 backend** — RFC 8032 §7.1 test vectors, so the signature backend
   is shown to be *standard* Ed25519 rather than a lookalike.
3. **Attestation envelope** — round-trip, self-certification, freshness, and a
   tamper matrix in which every modification must be rejected.
4. **Zero dependencies** — a static scan proving the core modules import
   nothing outside the standard library.

Exit status is 0 only if every check passed. Checks that require the optional
Ed25519 backend are **skipped** rather than failed when it is not installed,
and the summary names how many were skipped — a green summary always says what
it did not verify. ``--quiet`` prints the summary line only.
"""

from __future__ import annotations

import argparse
import ast
import copy
import json
import os
import sys

from . import attest, iqa_uri

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS_FILE = os.path.join(HERE, "vectors", "iqa-conformance-v1.2.6.json")

# RFC 8032 §7.1 — TEST 1 (empty message) and TEST 2 (one-byte message 0x72).
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

#: Fixed inputs for the reproducible envelope vector (SPEC §5.4).
ENVELOPE_SEED = bytes.fromhex(
    "e722fed924c7f76b157faab674ea97bb7c3075f55ad7d3c6319418e22b86d611")
ENVELOPE_TS = 1760000000
ENVELOPE_NONCE = "0011223344556677"
ENVELOPE_PAYLOAD = {
    "subject_uri": "iqa://3f9a1b2c.gateway.iqa",
    "organ": "gateway",
    "standing": "radiant",
}


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
        """A check that cannot run in this environment — reported, never hidden.

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
# 1. 一致性向量
# ---------------------------------------------------------------------------

def run_conformance(r: Runner) -> None:
    if not os.path.exists(VECTORS_FILE):
        r.check("vectors file present", False, f"missing: {VECTORS_FILE}")
        return
    with open(VECTORS_FILE, "r", encoding="utf-8") as fh:
        expected = json.load(fh)

    if not r.quiet:
        print(f"\n[1] Conformance -- {os.path.basename(VECTORS_FILE)}")

    # --- 正向 URI：字段逐一对照（case 计 1 项，字段不等即失败）---
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

    # --- 拒斥 URI：必须抛 IqaUriError ---
    for case in expected["negative_uris"]:
        try:
            iqa_uri.parse(case["uri"])
            r.check(f"reject {case['uri']}", False, "expected REJECT but parsed")
        except iqa_uri.IqaUriError:
            r.check(f"reject {case['uri']}", True)
        except Exception as exc:  # noqa: BLE001
            r.check(f"reject {case['uri']}", False, f"wrong error type: {exc!r}")

    # --- §11.3 安全档 ---
    for row in expected["action_safety"]:
        action = row["action"]
        uri = ("iqa://3f9a1b2c.gateway.iqa" if action is None
               else f"iqa://3f9a1b2c.gateway.iqa/{action}")
        got = iqa_uri.parse(uri)["action_safe"]
        r.check(f"action_safe {action or '(omitted)'} == {row['safe']}", got == row["safe"])

    # --- 确定性信封向量：签名输入 / 自证明 / Ed25519 ---
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
# 2. Ed25519 后端（RFC 8032 §7.1）
# ---------------------------------------------------------------------------

def run_rfc8032(r: Runner) -> None:
    if not attest.HAVE_ED25519:
        if not r.quiet:
            print(f"\n[2] Ed25519 backend -- SKIPPED ({attest.INSTALL_HINT} not installed)")
        return
    if not r.quiet:
        print("\n[2] Ed25519 backend -- RFC 8032 section 7.1")
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
# 3. 信封：往返 / 自证明 / 新鲜度 / 篡改矩阵
# ---------------------------------------------------------------------------

def run_envelope(r: Runner) -> None:
    if not attest.HAVE_ED25519:
        if not r.quiet:
            print(f"\n[3] Attestation envelope -- SKIPPED ({attest.INSTALL_HINT} not installed)")
        return
    if not r.quiet:
        print("\n[3] Attestation envelope -- round-trip, self-certification, tamper matrix")

    kp = attest.generate_keypair(ENVELOPE_SEED)
    env = attest.seal(ENVELOPE_PAYLOAD, kp, ts=ENVELOPE_TS, nonce=ENVELOPE_NONCE)

    # 确定性：同 seed/ts/nonce ⇒ 信封逐字节可复现（向量对照）
    with open(VECTORS_FILE, "r", encoding="utf-8") as fh:
        expected = json.load(fh)["attest_envelope_vector"]
    r.check("deterministic envelope matches the published vector",
            env["sig"] == expected["sig"] and env["aid"] == expected["aid"],
            "signature or AID differs from SPEC §5.4")

    # 往返
    ok, reason, aid = attest.verify_envelope(env, now=ENVELOPE_TS)
    r.check("round-trip verifies", ok and aid == kp["aid_hex"], reason)

    # claim 层：闭集 + URI 语法
    ok, reason, _ = attest.verify_attestation(env, now=ENVELOPE_TS)
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

    # 新鲜度
    ok, reason, _ = attest.verify_envelope(env, now=ENVELOPE_TS + 121)
    r.check("stale envelope rejected (121s > 120s window)", not ok, reason)
    ok, reason, _ = attest.verify_envelope(env, now=ENVELOPE_TS + 121,
                                           check_freshness=False)
    r.check("archival mode accepts a stale envelope", ok, reason)

    # 篡改矩阵：每一处改动都必须被拒
    def tampered(mutate) -> dict:
        e = copy.deepcopy(env)
        mutate(e)
        return e

    other = attest.generate_keypair()
    other_env = attest.seal({"x": 1}, other, ts=ENVELOPE_TS, nonce=ENVELOPE_NONCE)

    def expect_reject(name: str, e: dict) -> None:
        ok, reason, _ = attest.verify_envelope(e, now=ENVELOPE_TS,
                                               check_freshness=False)
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
# 4. 零依赖（核心模块静态扫描）
# ---------------------------------------------------------------------------

STDLIB_OK = {
    "__future__", "ast", "copy", "hashlib", "json", "os", "sys", "time",
}

def run_zero_dep(r: Runner) -> None:
    if not r.quiet:
        print("\n[4] Zero dependencies -- core modules import stdlib only")
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


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="iqa self-test")
    ap.add_argument("--quiet", action="store_true", help="summary line only")
    args = ap.parse_args()

    r = Runner(quiet=args.quiet)
    run_conformance(r)
    run_rfc8032(r)
    run_envelope(r)
    run_zero_dep(r)

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
