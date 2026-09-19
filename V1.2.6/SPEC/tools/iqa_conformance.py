#!/usr/bin/env python3
"""
IQA v1.2.6 一致性工具 —— 生成 / 校验 conformance vectors

用法（在本目录下）：
    python iqa_conformance.py --generate      # 重新生成 ../iqa-conformance-vectors.json
    python iqa_conformance.py --check         # 用向量回放当前实现
    python iqa_conformance.py --show          # 打印关键向量（供写入 spec 正文）

为什么需要它：
    规范要能被**互不信任的独立实现**验证。本工具把「iqa:// URI → 解析字段 →
    IQA_ROUTE」这条链路 + action 安全档 + 证明信封固化成确定性向量：
    任何语言的实现只要通过同一份向量，即可互操作。

权威边界：语法唯一权威 = RFC-009 §10.2 ABNF；安全档唯一权威 = §11.3；
信封布局唯一权威 = SPEC/IQA-URI-ATTEST-v1.2.6.md §5（承 RTTP-SEAL-ENVELOPE-v1.2.6 §3）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_SRC = os.path.normpath(os.path.join(HERE, "..", "..", "PKG", "iqa", "src"))
VECTORS = os.path.normpath(os.path.join(HERE, "..", "iqa-conformance-vectors.json"))

sys.path.insert(0, PKG_SRC)

import iqa.iqa_uri as iqa_uri  # noqa: E402

# ---------------------------------------------------------------------------
# 用例
# ---------------------------------------------------------------------------

# Forward: URIs. §10.3 examples first, then boundary shapes.
POSITIVE_URIS = [
    ("iqa://3f9a1b2c.gateway.iqa", None),                          # §10.3 short form - standing read
    ("iqa://0000004149434e531c5b21d80403358b.forge.iqa", None),    # §10.3 full 128-bit AID form
    ("iqa://3f9a1b2c.tss.iqa/audit", None),                        # §10.3 explicit fidelity audit
    ("iqa://master-authority.gateway.iqa/verify", None),           # §10.3 readable label form
    ("iqa://0000004149434e531c5b21d80403358ba794ef228ca5253994959ef6f3ff5678.tss.iqa/attest",
     None),                                                        # 256-bit AID form (doc AID + SHARD A)
    ("iqa://0000000000000000.gateway.iqa", None),                  # all-zero 8-hex boundary
    ("iqa://a-b-c.forge.iqa/revoke", None),                        # hyphens in a name subject
    # A lowercase-hex string of a NON-hash length (9 here) matches neither
    # 8/32/64, so the ABNF's ordered choice falls through to name-subject.
    # The grammar is the grammar - this documents it rather than "fixing" it.
    ("iqa://3f9a1b2cd.gateway.iqa/verify",
     "note - 9 hex digits is not a hash length (8/32/64), so the subject "
     "parses as a name-subject per the ABNF ordered choice (RFC-009 §10.2)"),
]

# Negative: MUST be rejected (fail closed, §10.3 / §12 #8).
NEGATIVE_URIS = [
    ("iqa://3f9a1b2c.gateway.iqa/AUDIT", "uppercase action - lowercase only (RFC-009 §10.3)"),
    ("iqa://3F9A1B2C.gateway.iqa/audit", "uppercase hex subject - lowercase only (RFC-009 §10.3)"),
    ("IQA://3f9a1b2c.gateway.iqa/audit", "uppercase scheme prefix - canonical form is lowercase (RFC-009 §10.3)"),
    ("iqas://3f9a1b2c.gateway.iqa/audit", "no iqas variant exists and no fallback is defined - fail closed (RFC-009 §12 #8)"),
    ("iqa://subject@iqa.org", "userinfo is not defined (RFC-009 §10.3)"),
    ("iqa://iqa.org/RFC-009/", "no organ, second path segment - this is an https matter (RFC-009 §10.3)"),
    ("iqa://3f9a1b2c.forgery.iqa", "organ is a closed set (RFC-009 §10.1/§10.3)"),
    ("iqa://3f9a1b2c.gateway.iqa/pulse", "action is a closed set - 'pulse' is not one of the four verbs (RFC-009 §10.1)"),
    ("iqa://3f9a1b2c.Gateway.iqa/verify", "organ is case-sensitive within the closed set (RFC-009 §10.3)"),
    ("iqa://3f9a1b2c.gateway.iqa/audit?x=1", "query is not defined (RFC-009 §10.3)"),
    ("iqa://3f9a1b2c.gateway.iqa/audit#f", "fragment is not defined (RFC-009 §10.3)"),
    ("iqa://3f9a1b2c.gateway.iqa:443/audit", "port is not defined (RFC-009 §10.3)"),
    ("iqa://3f9a1b2c.gateway.iqa/a/b", "second path segment - path is a single '/<action>' (RFC-009 §10.2)"),
    ("iqa://3f9a1b2c.gateway.iqa/", "trailing '/' with empty action - the closed set has no empty verb (RFC-009 §10.2)"),
    ("iqa://a.b", "authority has two segments, must be <subject>.<organ>.<root> (RFC-009 §10.2)"),
    ("iqa://a.b.c.d/audit", "authority has four segments, must be <subject>.<organ>.<root> (RFC-009 §10.2)"),
    ("https://3f9a1b2c.gateway.iqa/audit", "not an iqa scheme - there is no fallback (RFC-009 §10.3, §12 #8)"),
    ("iqa://3f9a1b2c.gateway.iqa/audit ", "trailing whitespace"),
]

# §11.3 safety classes, restated as data so both implementations replay them.
ACTION_SAFETY = [
    {"action": None,     "safe": True,  "why": "omitted - standing read (RFC-009 §11.1/§11.3)"},
    {"action": "verify", "safe": True,  "why": "read-only comparison, no state written (RFC-009 §11.3)"},
    {"action": "audit",  "safe": False, "why": "a failing measurement triggers Authority Ischemia (RFC-009 §11.3/§11.4)"},
    {"action": "attest", "safe": False, "why": "state transition - Seal issuance (RFC-009 §11.3)"},
    {"action": "revoke", "safe": False, "why": "state transition - standing withdrawal (RFC-009 §11.3)"},
]

# ---------------------------------------------------------------------------
# Deterministic attestation envelope (spec §5; layout from RTTP-SEAL-ENVELOPE
# v1.2.6 §3 with the iqa domain separation). Ed25519 is deterministic
# (RFC 8032), so fixed seed + ts + nonce give a byte-identical envelope.
# ---------------------------------------------------------------------------

ENVELOPE_SEED = bytes.fromhex(
    "e722fed924c7f76b157faab674ea97bb7c3075f55ad7d3c6319418e22b86d611")
ENVELOPE_TS = 1760000000
ENVELOPE_NONCE = bytes.fromhex("0011223344556677")
ENVELOPE_PAYLOAD = {
    "subject_uri": "iqa://3f9a1b2c.gateway.iqa",
    "organ": "gateway",
    "standing": "radiant",
}
DOMAIN = b"iqa-attest-v1\n"


def canonical_json(obj) -> str:
    """UTF-8, sorted keys, separators ',' ':' with no insignificant whitespace."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def signing_input(payload: dict, pub_hex: str, aid_hex: str,
                  ts: int, nonce_hex: str) -> bytes:
    body = canonical_json({
        "alg": "ed25519",
        "aid": aid_hex,
        "nonce": nonce_hex,
        "payload": payload,
        "pub": pub_hex,
        "ts": ts,
    })
    return DOMAIN + body.encode("utf-8")


def build_envelope_vector() -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    private = Ed25519PrivateKey.from_private_bytes(ENVELOPE_SEED)
    public = private.public_key().public_bytes_raw()
    pub_hex = public.hex()
    aid_hex = hashlib.sha256(public).hexdigest()
    raw = signing_input(ENVELOPE_PAYLOAD, pub_hex, aid_hex,
                        ENVELOPE_TS, ENVELOPE_NONCE.hex())
    signature = private.sign(raw)

    return {
        "v": 1,
        "alg": "ed25519",
        "aid": aid_hex,
        "pub": pub_hex,
        "ts": ENVELOPE_TS,
        "nonce": ENVELOPE_NONCE.hex(),
        "sig": signature.hex(),
        "payload": ENVELOPE_PAYLOAD,
        "seed_hex": ENVELOPE_SEED.hex(),               # test-only disclosure
        "signing_input_hex": raw.hex(),
        "domain_prefix_hex": DOMAIN.hex(),
        "expected": "verify MUST accept; aid MUST equal SHA-256(pub); "
                    "signing input MUST reproduce byte for byte",
    }


# ---------------------------------------------------------------------------
# 生成
# ---------------------------------------------------------------------------

def _build_payload() -> dict:
    positive = []
    for uri, note in POSITIVE_URIS:
        p = iqa_uri.parse(uri)
        positive.append({
            "uri": uri,
            "canonical_uri": p["canonical_uri"],
            "subject": p["subject"],
            "subject_is_hash": p["subject_is_hash"],
            "organ": p["organ"],
            "root": p["root"],
            "authority": p["authority"],
            "action": p["action"],
            "action_omitted": p["action_omitted"],
            "action_safe": p["action_safe"],
            "route_hex": p["route_hex"],
            "note": note,
        })

    negative = [{"uri": u, "reason": r} for u, r in NEGATIVE_URIS]

    return {
        "spec": "IQA-URI-ATTEST-v1.2.6",
        "applies_to": ["RFC-009 §10", "RFC-009 §11"],
        "generated_by": "SPEC/tools/iqa_conformance.py",
        "note": "Generated file - do not edit by hand. Change the cases in iqa_conformance.py instead.",
        "route_rule": "IQA_ROUTE = SHA-256(ASCII(canonical_authority))[0:4]",
        "organ_closed_set": list(iqa_uri.ORGANS),
        "action_closed_set": list(iqa_uri.ACTIONS),
        "standings_closed_set": list(iqa_uri.STANDINGS),
        "positive_uris": positive,
        "negative_uris": negative,
        "action_safety": ACTION_SAFETY,
        "attest_envelope_vector": build_envelope_vector(),
    }


def cmd_generate() -> int:
    payload = _build_payload()
    with open(VECTORS, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")
    print(f"[GEN] {VECTORS}")
    print(f"      positive={len(payload['positive_uris'])} "
          f"negative={len(payload['negative_uris'])} "
          f"safety={len(payload['action_safety'])} "
          f"envelope=1")
    return 0


# ---------------------------------------------------------------------------
# 校验
# ---------------------------------------------------------------------------

def cmd_check() -> int:
    if not os.path.exists(VECTORS):
        print(f"[ERR] vectors missing: {VECTORS} (run --generate first)")
        return 2
    with open(VECTORS, "r", encoding="utf-8") as fh:
        expected = json.load(fh)

    failures = []
    checked = 0

    for case in expected["positive_uris"]:
        checked += 1
        p = iqa_uri.parse(case["uri"])
        for key in ("canonical_uri", "subject_is_hash", "organ", "root",
                    "authority", "action", "action_omitted", "action_safe",
                    "route_hex"):
            if case[key] != p[key]:
                failures.append(f"{case['uri']} :: {key} {case[key]!r} != {p[key]!r}")

    for case in expected["negative_uris"]:
        checked += 1
        try:
            iqa_uri.parse(case["uri"])
            failures.append(f"{case['uri']} :: expected REJECT but parsed")
        except iqa_uri.IqaUriError:
            pass

    for row in expected["action_safety"]:
        checked += 1
        action = row["action"]
        if action is None:
            got = iqa_uri.parse("iqa://3f9a1b2c.gateway.iqa")["action_safe"]
        else:
            got = iqa_uri.parse(f"iqa://3f9a1b2c.gateway.iqa/{action}")["action_safe"]
        if got != row["safe"]:
            failures.append(f"action_safety {action} :: expected {row['safe']} got {got}")

    env = expected["attest_envelope_vector"]
    checked += 1
    raw = signing_input(env["payload"], env["pub"], env["aid"],
                        env["ts"], env["nonce"])
    if raw.hex() != env["signing_input_hex"]:
        failures.append("envelope :: signing input mismatch")
    checked += 1
    if hashlib.sha256(bytes.fromhex(env["pub"])).hexdigest() != env["aid"]:
        failures.append("envelope :: aid != SHA-256(pub)")
    checked += 1
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(env["pub"])).verify(
            bytes.fromhex(env["sig"]), raw)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"envelope :: signature verification failed: {exc}")

    if failures:
        print(f"[FAIL] {len(failures)} of {checked} checks failed")
        for item in failures:
            print("   -", item)
        return 1
    print(f"[PASS] all {checked} checks passed")
    return 0


def cmd_show() -> int:
    payload = _build_payload()
    print("=== iqa:// URI -> fields / IQA_ROUTE ===")
    for c in payload["positive_uris"]:
        act = c["action"] or "(omitted)"
        print(f"{c['authority']:<62} action={act:<9} safe={c['action_safe']!s:<5} "
              f"route={c['route_hex']}")
    print()
    print("=== Attestation envelope (deterministic) ===")
    env = payload["attest_envelope_vector"]
    print(f"public    {env['pub']}")
    print(f"aid       {env['aid']}")
    print(f"signature {env['sig']}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="IQA v1.2.6 conformance")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--generate", action="store_true")
    g.add_argument("--check", action="store_true")
    g.add_argument("--show", action="store_true")
    args = ap.parse_args()
    if args.generate:
        return cmd_generate()
    if args.check:
        return cmd_check()
    return cmd_show()


if __name__ == "__main__":
    raise SystemExit(main())
